"""GitHub Events API monitor for force push detection.

Polls the public GitHub Events API for PushEvent entries that indicate
force pushes (especially zero-commit force pushes, which strongly correlate
with developers trying to remove accidentally-committed secrets).

Detected events are stored in a SQLite database compatible with
``force_push_scanner.py --db-file``.

Usage:
    export GITHUB_TOKEN=ghp_...
    python github_event_monitor.py [--db-file pushes.sqlite3] [--scan] [--poll-delay 0.75]
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

log = logging.getLogger("github_event_monitor")

# Match the Ruby crawler: single request with a large per_page value.
# The GitHub Events API caps at 100 per page for the public timeline,
# but we request as many as it will give us.
_PAGE_LIMIT = 100

# Fixed delay (seconds) between the *end* of one poll and the *start* of the
# next – mirrors the Ruby crawler's ``EM.add_timer(0.75, &process)`` pattern.
_POLL_DELAY = 0.75
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


def _fetch_events(
    sess: requests.Session,
) -> tuple[list[dict], dict]:
    """Fetch a single page of events from the public timeline.

    Mirrors the Ruby crawler's single-request approach with a large per_page.
    Returns (events_list, response_headers).
    """
    url = f"https://api.github.com/events?per_page={_PAGE_LIMIT}"
    resp = sess.get(url, timeout=(5, 5))  # (connect_timeout, read_timeout)
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
    poll_delay: float = _POLL_DELAY,
    scan: bool = False,
    verbose: bool = False,
) -> None:
    """Main monitor loop – mirrors the Ruby crawler's callback/timer pattern.

    Each cycle:
      1. Fetch one page of events from the public timeline.
      2. Deduplicate against the *previous* response's IDs (sliding window).
      3. Filter & store new force-push events.
      4. Log rate-limit headers (Remaining / Reset).
      5. Sleep ``poll_delay`` seconds, then repeat.

    On any error (HTTP or network) the same delay is applied before retrying,
    exactly like the Ruby crawler's ``EM.add_timer(0.75, &process)`` in the
    errback.
    """
    global _running

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    conn = _init_db(db_path)
    sess = _build_session(token)

    # Sliding-window dedup: keep only the event IDs from the *last* successful
    # response, just like the Ruby crawler's ``@latest = urls``.
    latest_ids: list[str] = []
    latest_key = lambda ev: ev.get("id", "")

    log.info(
        "Monitoring GitHub Events API (poll_delay=%.2fs, db=%s, scan=%s)",
        poll_delay,
        db_path,
        scan,
    )

    while _running:
        try:
            events, headers = _fetch_events(sess)

            # Build the full ID list for this response
            current_ids = [latest_key(e) for e in events]

            # New events = those whose ID was NOT in the previous response
            new_events = [e for e in events if latest_key(e) not in latest_ids]

            # Slide the window forward (replace, don't accumulate)
            latest_ids = current_ids

            # Filter to zero-commit force pushes
            force_pushes = _extract_force_pushes(new_events)

            inserted = 0
            for fp in force_pushes:
                if _insert_event(conn, fp):
                    inserted += 1
                    log.info(
                        "New force push: %s/%s  commit=%s",
                        fp["repo_org"],
                        fp["repo_name"],
                        fp["before"],
                    )

            # Log rate-limit info (read & log, same as the Ruby crawler)
            remaining = headers.get("X-RateLimit-Remaining", "?")
            reset_epoch = headers.get("X-RateLimit-Reset", "")
            reset_str = ""
            if reset_epoch:
                try:
                    reset_str = str(
                        datetime.fromtimestamp(int(reset_epoch), tz=timezone.utc)
                    )
                except (ValueError, OSError):
                    reset_str = reset_epoch

            log.info(
                "Found %d new events, %d force pushes (%d stored), API: %s, reset: %s",
                len(new_events),
                len(force_pushes),
                inserted,
                remaining,
                reset_str,
            )

            if len(new_events) >= _PAGE_LIMIT:
                log.warning("Missed records — new events filled entire page")

            # Optionally trigger scanning for newly-inserted events
            if scan and inserted > 0:
                _trigger_scan(force_pushes)

        except requests.exceptions.RequestException as exc:
            log.error(
                "Error: status=%s, response=%s",
                getattr(getattr(exc, "response", None), "status_code", "?"),
                getattr(getattr(exc, "response", None), "text", str(exc)),
            )
        except Exception:
            log.exception("Unexpected error during poll cycle")

        # Fixed delay after completion (success or failure), matching the
        # Ruby crawler's EM.add_timer(0.75, &process) in both callback paths.
        time.sleep(poll_delay)

    conn.close()
    log.info("Monitor stopped.")


def _trigger_scan(events: list[dict]) -> None:
    """Scan all newly-detected force push events directly.

    Builds the repos mapping from the new events and calls
    ``force_push_scanner.scan_commits`` without filtering by org —
    every new event gets scanned.
    """
    from collections import defaultdict
    from force_push_scanner import scan_commits

    # Build the same {repo_url → [{before, date}]} structure the scanner expects
    repos: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        url = f"https://github.com/{ev['repo_org']}/{ev['repo_name']}"
        repos[url].append({"before": ev["before"], "date": ev["timestamp"]})

    log.info("Scanning %d events across %d repos", len(events), len(repos))
    try:
        scan_commits("", repos)
    except Exception:
        log.exception("Scan failed")


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
        "--poll-delay",
        type=float,
        default=_POLL_DELAY,
        help="Seconds to wait after each poll before the next one (default: %(default)s)",
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
        poll_delay=args.poll_delay,
        scan=args.scan,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
