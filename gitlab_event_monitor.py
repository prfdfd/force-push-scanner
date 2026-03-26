"""GitLab Events API monitor for force push detection.

Polls the global GitLab Events API (``GET /api/v4/events?action=pushed``)
for push events that indicate force pushes — especially zero-commit force
pushes, which strongly correlate with developers trying to remove
accidentally-committed secrets.

Mirrors the GitHub monitor's architecture: single-stream polling with
sliding-window deduplication on event IDs.

Rate limits handled:
  - **General (429)**: backs off using the ``Retry-After`` header.
  - **Large-file blobs** (``/repository/blobs/:sha``,
    ``/repository/files/:path``): 5 req/min per object per project for
    files > 10 MB.  Not hit during event polling, but relevant if the
    scanner ever fetches blobs via the REST API instead of ``git clone``.

Detected events are stored in a SQLite database compatible with
``force_push_scanner.py --db-file``.

Usage:
    export GITLAB_TOKEN=glpat-...
    python gitlab_event_monitor.py [--gitlab-url https://gitlab.com] [--db-file pushes.sqlite3] [--scan]
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

log = logging.getLogger("gitlab_event_monitor")

_PER_PAGE = 100
_POLL_DELAY = 60.0  # seconds between polls
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
        return False


# ── GitLab API ──────────────────────────────────────────────────────────────


def _build_session(token: str) -> requests.Session:
    """Return a ``requests.Session`` pre-configured with GitLab PAT auth."""
    sess = requests.Session()
    sess.headers.update(
        {
            "PRIVATE-TOKEN": token,
            "User-Agent": _USER_AGENT,
        }
    )
    return sess


_MAX_429_RETRIES = 5


def _gitlab_get(
    sess: requests.Session, url: str, params: dict | None = None,
) -> requests.Response:
    """GET with automatic 429 Retry-After back-off.

    Also aware of GitLab's per-object blob rate limit (5 req/min for
    files > 10 MB on ``/repository/blobs`` and ``/repository/files``
    endpoints).  Those endpoints return 429 with ``Retry-After`` as well,
    so the same handler covers both.

    Retries up to ``_MAX_429_RETRIES`` times before raising.
    """
    retries = 0
    while True:
        resp = sess.get(url, params=params, timeout=(10, 30))
        if resp.status_code == 429:
            retries += 1
            if retries > _MAX_429_RETRIES:
                log.error("Rate limit exceeded after %d retries, giving up", _MAX_429_RETRIES)
                resp.raise_for_status()
            sleep_time = int(resp.headers.get("Retry-After", 60))
            log.warning("Rate limit hit (%d/%d). Sleeping for %d seconds...", retries, _MAX_429_RETRIES, sleep_time)
            time.sleep(sleep_time)
            continue
        return resp


def _fetch_events(
    sess: requests.Session,
    gitlab_url: str,
) -> tuple[list[dict], dict]:
    """Fetch one page of push events from the global events stream.

    Uses ``GET /api/v4/events?action=pushed`` which returns all push events
    across every project visible to the authenticated token.

    Returns ``(events_list, response_headers)``.
    """
    resp = _gitlab_get(
        sess,
        f"{gitlab_url}/api/v4/events",
        params={"action": "pushed", "per_page": _PER_PAGE},
    )
    resp.raise_for_status()
    return resp.json(), dict(resp.headers)


def _extract_force_pushes(events: list[dict]) -> list[dict]:
    """Filter *events* to zero-commit force pushes.

    GitLab push events carry a ``push_data`` object with:
      - ``action``: ``"force_pushed"`` for force pushes
      - ``commit_count``: 0 for zero-commit rewrites
      - ``commit_from``: the before SHA (the overwritten HEAD)

    The ``project`` key (present on global-stream events) provides the
    namespace and project name so we don't need per-project lookups.
    """
    results: list[dict] = []
    for ev in events:
        push_data = ev.get("push_data")
        if not push_data:
            continue

        if push_data.get("action") != "force_pushed":
            continue

        # Focus on zero-commit force pushes (high-signal pattern)
        if push_data.get("commit_count", 1) != 0:
            continue

        before_sha = push_data.get("commit_from", "")
        if not before_sha or before_sha == "0" * 40:
            continue

        # Extract project metadata from the event itself
        project = ev.get("project", {})
        path_with_ns = project.get("path_with_namespace", "")
        if "/" not in path_with_ns:
            continue
        namespace, name = path_with_ns.rsplit("/", 1)

        created_at = ev.get("created_at", "")
        ts = _parse_gitlab_timestamp(created_at)

        results.append(
            {
                "id": f"gl-{ev.get('id', '')}",
                "repo_org": namespace,
                "repo_name": name,
                "before": before_sha,
                "timestamp": ts,
            }
        )
    return results


def _parse_gitlab_timestamp(created_at: str) -> int:
    """Parse a GitLab ISO-8601 timestamp to Unix epoch.

    Handles both ``2024-01-01T00:00:00.000Z`` (with fractional seconds)
    and ``2024-01-01T00:00:00Z`` (without).
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return int(
                datetime.strptime(created_at, fmt)
                .replace(tzinfo=timezone.utc)
                .timestamp()
            )
        except (ValueError, TypeError):
            continue
    return int(time.time())


# ── Monitor loop ────────────────────────────────────────────────────────────

_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("Received signal %s – shutting down after current cycle", signum)
    _running = False


def monitor(
    db_path: Path,
    gitlab_url: str,
    token: str,
    poll_delay: float = _POLL_DELAY,
    scan: bool = False,
) -> None:
    """Main monitor loop — polls the global GitLab event stream.

    Each cycle:
      1. Fetch one page of push events from ``/api/v4/events?action=pushed``.
      2. Deduplicate against the *previous* response's IDs (sliding window).
      3. Filter to zero-commit force pushes & store new events.
      4. Optionally trigger the scanner for newly-inserted events.
      5. Sleep *poll_delay* seconds, then repeat.
    """
    global _running

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    conn = _init_db(db_path)
    sess = _build_session(token)

    # Prune old events at startup to keep DB size bounded
    from force_push_scanner import prune_old_events
    prune_old_events(conn)

    # Sliding-window dedup: keep event IDs from the *last* successful
    # response, matching the GitHub monitor's pattern.
    latest_ids: list[str] = []
    latest_key = lambda ev: str(ev.get("id", ""))

    log.info(
        "Monitoring GitLab Events API (%s), poll=%.0fs, scan=%s",
        gitlab_url,
        poll_delay,
        scan,
    )

    while _running:
        sleep_seconds = poll_delay

        try:
            events, headers = _fetch_events(sess, gitlab_url)

            if not events:
                log.debug("No events returned, sleeping %.1fs", sleep_seconds)
                time.sleep(sleep_seconds)
                continue

            # Build full ID list for this response
            current_ids = [latest_key(e) for e in events]

            # New events = those whose ID was NOT in the previous response
            new_events = [e for e in events if latest_key(e) not in latest_ids]

            # Slide the window forward
            latest_ids = current_ids

            # Filter to zero-commit force pushes
            force_pushes = _extract_force_pushes(new_events)

            inserted = 0
            cycle_force_pushes: list[dict] = []
            for fp in force_pushes:
                if _insert_event(conn, fp):
                    inserted += 1
                    cycle_force_pushes.append(fp)
                    log.info(
                        "New force push: %s/%s  commit=%s",
                        fp["repo_org"],
                        fp["repo_name"],
                        fp["before"],
                    )

            # Log rate-limit info (GitLab uses RateLimit-* headers)
            remaining = headers.get("RateLimit-Remaining", "?")
            reset_epoch = headers.get("RateLimit-Reset", "")
            reset_str = ""
            if reset_epoch:
                try:
                    reset_str = str(
                        datetime.fromtimestamp(int(reset_epoch), tz=timezone.utc)
                    )
                except (ValueError, OSError):
                    reset_str = reset_epoch

            log.info(
                "Found %d new events, %d force pushes (%d stored), "
                "API remaining: %s, reset: %s, poll: %.0fs",
                len(new_events),
                len(force_pushes),
                inserted,
                remaining,
                reset_str,
                sleep_seconds,
            )

            if len(new_events) >= _PER_PAGE:
                log.warning("Missed records — new events filled entire page")

            # Optionally trigger scanning for newly-inserted events
            if scan and cycle_force_pushes:
                _trigger_scan(cycle_force_pushes, gitlab_url, db_path)

        except requests.exceptions.RequestException as exc:
            log.error(
                "Request error: status=%s, response=%s",
                getattr(getattr(exc, "response", None), "status_code", "?"),
                getattr(getattr(exc, "response", None), "text", str(exc)),
            )
        except Exception:
            log.exception("Unexpected error during poll cycle")

        time.sleep(sleep_seconds)

    conn.close()
    log.info("Monitor stopped.")


def _trigger_scan(events: list[dict], gitlab_url: str, db_path: Path) -> None:
    """Scan newly-detected force push events via force_push_scanner."""
    from collections import defaultdict
    from force_push_scanner import scan_commits

    repos: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        url = f"{gitlab_url}/{ev['repo_org']}/{ev['repo_name']}"
        repos[url].append({"before": ev["before"], "date": ev["timestamp"]})

    log.info("Scanning %d events across %d repos", len(events), len(repos))
    try:
        scan_commits(repos, db_path=db_path)
    except Exception:
        log.exception("Scan failed")


# ── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor the GitLab global event stream for zero-commit "
        "force pushes and feed them to the force-push scanner.",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com"),
        help="GitLab instance URL (default: $GITLAB_URL or https://gitlab.com)",
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
        help="Seconds between polls (default: %(default)s)",
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Disable automatic scanning — only collect events, do not run trufflehog",
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

    token = os.environ.get("GITLAB_TOKEN", "")
    if not token:
        log.error("GITLAB_TOKEN environment variable is required.")
        sys.exit(1)

    scan = not args.no_scan

    if scan:
        for tool in ("git", "trufflehog"):
            if shutil.which(tool) is None:
                log.error("Required tool '%s' not found in PATH", tool)
                sys.exit(1)

    db_path = Path(args.db_file)
    monitor(
        db_path=db_path,
        gitlab_url=args.gitlab_url.rstrip("/"),
        token=token,
        poll_delay=args.poll_delay,
        scan=scan,
    )


if __name__ == "__main__":
    main()
