"""GitHub Events API monitor for force push detection.

Polls the public GitHub Events API for PushEvent entries that indicate
force pushes (especially zero-commit force pushes, which strongly correlate
with developers trying to remove accidentally-committed secrets).

Detected events are stored in a SQLite database compatible with
``force_push_scanner.py --db-file``.

Usage:
    export GITHUB_TOKEN=ghp_...
    python github_event_monitor.py [--db-file pushes.sqlite3] [--scan] [--interval 1.0]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests

log = logging.getLogger("github_event_monitor")

# GitHub Events API returns at most 300 events (10 pages x 30) or 100 per page.
# We request the maximum per-page to minimise round-trips.
_PER_PAGE = 100
_MAX_PAGES = 3  # 300 events per poll cycle is plenty

_DEFAULT_INTERVAL = 1.0  # seconds between poll cycles (stay under rate limit)
_USER_AGENT = "force-push-scanner/1.0"

# ── Database ────────────────────────────────────────────────────────────────


def _init_db(db_path: Path) -> sqlite3.Connection:
    """Create (or open) the SQLite database and ensure the schema exists."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pushes (
            id          TEXT PRIMARY KEY,
            repo_org    TEXT NOT NULL,
            repo_name   TEXT NOT NULL,
            before      TEXT NOT NULL,
            timestamp   INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _insert_event(conn: sqlite3.Connection, event: dict) -> bool:
    """Insert a force-push event into the database.

    Returns True if the row was newly inserted, False if it already existed.
    """
    try:
        conn.execute(
            "INSERT INTO pushes (id, repo_org, repo_name, before, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                event["id"],
                event["repo_org"],
                event["repo_name"],
                event["before"],
                event["timestamp"],
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Duplicate – already recorded
        return False


# ── GitHub API ──────────────────────────────────────────────────────────────


def _build_session(token: str) -> requests.Session:
    """Return a ``requests.Session`` pre-configured with auth and headers."""
    sess = requests.Session()
    sess.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": _USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    return sess


def _fetch_events_page(
    sess: requests.Session,
    page: int = 1,
    per_page: int = _PER_PAGE,
) -> tuple[list[dict], dict]:
    """Fetch a single page from the public events endpoint.

    Returns (events_list, response_headers).
    """
    url = f"https://api.github.com/events?per_page={per_page}&page={page}"
    resp = sess.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json(), dict(resp.headers)


def _extract_force_pushes(events: list[dict]) -> list[dict]:
    """Filter *events* to zero-commit force-push PushEvents.

    A "zero-commit" force push has ``size == 0`` in the payload, meaning
    the developer pushed a new HEAD that overwrites history without adding
    new commits – the strongest signal for secret-removal attempts.

    Returns a list of dicts ready for DB insertion.
    """
    results: list[dict] = []
    for ev in events:
        if ev.get("type") != "PushEvent":
            continue

        payload = ev.get("payload", {})

        # ``forced`` is only present in the Events API payload when True.
        if not payload.get("forced"):
            continue

        # Focus on zero-commit force pushes (the high-signal pattern).
        if payload.get("size", 1) != 0:
            continue

        before_sha = payload.get("before", "")
        if not before_sha or before_sha == "0" * 40:
            # New branch creation, not a force push rewrite
            continue

        repo = ev.get("repo", {})
        repo_full = repo.get("name", "")  # "org/repo"
        if "/" not in repo_full:
            continue

        org, name = repo_full.split("/", 1)
        created_at = ev.get("created_at", "")

        # Parse ISO-8601 timestamp → Unix epoch
        try:
            ts = int(
                datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc)
                .timestamp()
            )
        except (ValueError, TypeError):
            ts = int(time.time())

        results.append(
            {
                "id": ev.get("id", ""),
                "repo_org": org,
                "repo_name": name,
                "before": before_sha,
                "timestamp": ts,
            }
        )
    return results


# ── Monitor loop ────────────────────────────────────────────────────────────

_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("Received signal %s – shutting down after current cycle", signum)
    _running = False


def monitor(
    db_path: Path,
    token: str,
    interval: float = _DEFAULT_INTERVAL,
    scan: bool = False,
    verbose: bool = False,
) -> None:
    """Main monitor loop: poll → filter → store → (optionally) scan."""
    global _running

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    conn = _init_db(db_path)
    sess = _build_session(token)

    # Track event IDs we've already seen this session to skip duplicates
    # quickly without hitting the DB every time.
    seen_ids: Set[str] = set()

    log.info(
        "Monitoring GitHub Events API (interval=%.1fs, db=%s, scan=%s)",
        interval,
        db_path,
        scan,
    )

    while _running:
        try:
            all_events: list[dict] = []
            for page in range(1, _MAX_PAGES + 1):
                events, headers = _fetch_events_page(sess, page=page)
                all_events.extend(events)
                # Stop paging if fewer results than requested (last page)
                if len(events) < _PER_PAGE:
                    break

            force_pushes = _extract_force_pushes(all_events)

            # Deduplicate against session cache
            new_pushes = [fp for fp in force_pushes if fp["id"] not in seen_ids]

            inserted = 0
            for fp in new_pushes:
                seen_ids.add(fp["id"])
                if _insert_event(conn, fp):
                    inserted += 1
                    log.info(
                        "New force push: %s/%s  commit=%s",
                        fp["repo_org"],
                        fp["repo_name"],
                        fp["before"],
                    )

            # Rate-limit info
            remaining = headers.get("X-RateLimit-Remaining", "?")
            reset_ts = headers.get("X-RateLimit-Reset", "")
            reset_str = ""
            if reset_ts:
                try:
                    reset_str = datetime.fromtimestamp(
                        int(reset_ts), tz=timezone.utc
                    ).strftime("%H:%M:%S UTC")
                except (ValueError, OSError):
                    reset_str = reset_ts

            log.info(
                "Polled %d events, %d force pushes (%d new) | API remaining: %s (reset %s)",
                len(all_events),
                len(force_pushes),
                inserted,
                remaining,
                reset_str,
            )

            # Optionally trigger scanning for each newly-inserted event
            if scan and inserted > 0:
                _trigger_scan(db_path, new_pushes)

        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            if status == 403:
                # Rate limited – back off until reset
                reset_ts = ""
                if exc.response is not None:
                    reset_ts = exc.response.headers.get("X-RateLimit-Reset", "")
                wait = 60
                if reset_ts:
                    try:
                        wait = max(
                            1,
                            int(reset_ts) - int(time.time()) + 1,
                        )
                    except ValueError:
                        pass
                log.warning("Rate limited (403). Sleeping %ds until reset.", wait)
                time.sleep(wait)
                continue
            else:
                log.error("HTTP error %s: %s", status, exc)
        except requests.exceptions.RequestException as exc:
            log.error("Request failed: %s", exc)
        except Exception:
            log.exception("Unexpected error during poll cycle")

        # Wait before next cycle
        time.sleep(interval)

    conn.close()
    log.info("Monitor stopped.")


def _trigger_scan(db_path: Path, events: list[dict]) -> None:
    """Invoke force_push_scanner for each unique org in the new events."""
    import subprocess

    orgs = {e["repo_org"] for e in events}
    for org in orgs:
        log.info("Triggering scan for org: %s", org)
        try:
            subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).parent / "force_push_scanner.py"),
                    org,
                    "--db-file",
                    str(db_path),
                    "--scan",
                ],
                check=False,
            )
        except Exception:
            log.exception("Failed to launch scanner for org %s", org)


# ── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor GitHub Events API for zero-commit force pushes and "
        "feed them to the force-push scanner.",
    )
    parser.add_argument(
        "--db-file",
        default="force_push_commits.sqlite3",
        help="Path to the SQLite database for storing events (default: force_push_commits.sqlite3)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=_DEFAULT_INTERVAL,
        help="Seconds between poll cycles (default: %(default)s)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Automatically run the force-push scanner when new events are detected",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        log.error("GITHUB_TOKEN environment variable is required.")
        sys.exit(1)

    db_path = Path(args.db_file)
    monitor(
        db_path=db_path,
        token=token,
        interval=args.interval,
        scan=args.scan,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
