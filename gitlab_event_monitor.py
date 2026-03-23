"""GitLab Events API monitor for force push detection.

Polls the GitLab Projects Events API for push events that indicate
force pushes (especially zero-commit force pushes, which strongly correlate
with developers trying to remove accidentally-committed secrets).

Handles rate limiting via the ``Retry-After`` header returned by GitLab
when the 429 status is hit.

Detected events are stored in a SQLite database compatible with
``force_push_scanner.py --db-file``.

Usage:
    export GITLAB_TOKEN=glpat-...
    python gitlab_event_monitor.py --project-ids 123 456 [--gitlab-url https://gitlab.com] [--db-file pushes.sqlite3] [--scan]
    python gitlab_event_monitor.py --group-id 789 [--scan]
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
_POLL_DELAY = 60.0  # seconds between full polling cycles
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
    """Return a ``requests.Session`` pre-configured with GitLab auth."""
    sess = requests.Session()
    sess.headers.update(
        {
            "PRIVATE-TOKEN": token,
            "User-Agent": _USER_AGENT,
        }
    )
    return sess


def _gitlab_get(sess: requests.Session, url: str, params: dict | None = None) -> requests.Response:
    """GET with automatic 429 Retry-After handling."""
    while True:
        resp = sess.get(url, params=params, timeout=(10, 30))
        if resp.status_code == 429:
            sleep_time = int(resp.headers.get("Retry-After", 60))
            log.warning("Rate limit hit. Sleeping for %d seconds...", sleep_time)
            time.sleep(sleep_time)
            continue
        return resp


def _discover_projects(sess: requests.Session, gitlab_url: str, group_id: int) -> list[dict]:
    """List all projects in *group_id* (including subgroups) via pagination."""
    projects: list[dict] = []
    page = 1
    while True:
        resp = _gitlab_get(
            sess,
            f"{gitlab_url}/api/v4/groups/{group_id}/projects",
            params={
                "per_page": _PER_PAGE,
                "page": page,
                "include_subgroups": "true",
                "simple": "true",
            },
        )
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        projects.extend(batch)
        page += 1
    return projects


def _fetch_push_events(
    sess: requests.Session,
    gitlab_url: str,
    project_id: int,
) -> list[dict]:
    """Fetch recent push events for a single project."""
    resp = _gitlab_get(
        sess,
        f"{gitlab_url}/api/v4/projects/{project_id}/events",
        params={"action": "pushed", "per_page": _PER_PAGE},
    )
    if resp.status_code == 404:
        log.warning("Project %d not found or not accessible — skipping", project_id)
        return []
    resp.raise_for_status()
    return resp.json()


def _extract_force_pushes(events: list[dict], namespace: str, project_name: str) -> list[dict]:
    """Filter *events* to zero-commit force pushes.

    GitLab push events have a ``push_data`` object with:
      - ``action``: ``"force_pushed"`` for force pushes
      - ``commit_count``: 0 for zero-commit rewrites
      - ``commit_from``: the before SHA (the overwritten HEAD)
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

        created_at = ev.get("created_at", "")
        try:
            ts = int(
                datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=timezone.utc)
                .timestamp()
            )
        except (ValueError, TypeError):
            try:
                # Fallback: some GitLab versions omit fractional seconds
                ts = int(
                    datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except (ValueError, TypeError):
                ts = int(time.time())

        results.append(
            {
                "id": f"gl-{ev.get('id', '')}",
                "repo_org": namespace,
                "repo_name": project_name,
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
    gitlab_url: str,
    token: str,
    project_ids: list[int],
    group_id: int | None = None,
    poll_delay: float = _POLL_DELAY,
    scan: bool = False,
) -> None:
    """Main monitor loop.

    Each cycle:
      1. Resolve project list (from --project-ids or --group-id).
      2. For each project, fetch push events and filter to force pushes.
      3. Deduplicate via the DB (INSERT OR IGNORE).
      4. Optionally trigger the scanner for new events.
      5. Sleep *poll_delay* seconds, then repeat.
    """
    global _running

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    conn = _init_db(db_path)
    sess = _build_session(token)

    # Resolve projects once at startup; re-resolve each cycle if using a group
    # so newly-created repos are picked up.
    static_projects: list[dict] | None = None
    if project_ids:
        static_projects = [{"id": pid} for pid in project_ids]

    log.info(
        "Monitoring GitLab (%s) — projects=%s, group=%s, poll=%.0fs, scan=%s",
        gitlab_url,
        project_ids or "from group",
        group_id,
        poll_delay,
        scan,
    )

    while _running:
        try:
            # Determine which projects to poll this cycle
            if static_projects is not None:
                projects = static_projects
            elif group_id is not None:
                projects = _discover_projects(sess, gitlab_url, group_id)
                log.info("Discovered %d projects in group %d", len(projects), group_id)
            else:
                log.error("No projects or group specified")
                break

            cycle_inserted = 0
            cycle_force_pushes: list[dict] = []

            for proj in projects:
                if not _running:
                    break

                pid = proj["id"]
                # For static IDs we don't have namespace/name; fetch them lazily
                namespace = proj.get("namespace", {}).get("full_path", "")
                name = proj.get("path", "")
                if not namespace or not name:
                    # Fetch project metadata for static IDs
                    meta_resp = _gitlab_get(sess, f"{gitlab_url}/api/v4/projects/{pid}")
                    if meta_resp.status_code == 200:
                        meta = meta_resp.json()
                        namespace = meta.get("namespace", {}).get("full_path", str(pid))
                        name = meta.get("path", str(pid))
                    else:
                        namespace = str(pid)
                        name = str(pid)

                events = _fetch_push_events(sess, gitlab_url, pid)
                force_pushes = _extract_force_pushes(events, namespace, name)

                for fp in force_pushes:
                    if _insert_event(conn, fp):
                        cycle_inserted += 1
                        cycle_force_pushes.append(fp)
                        log.info(
                            "New force push: %s/%s  commit=%s",
                            fp["repo_org"],
                            fp["repo_name"],
                            fp["before"],
                        )

            log.info(
                "Cycle complete: %d projects polled, %d new force pushes stored",
                len(projects),
                cycle_inserted,
            )

            if scan and cycle_force_pushes:
                _trigger_scan(cycle_force_pushes, gitlab_url)

        except requests.exceptions.RequestException as exc:
            log.error(
                "Request error: status=%s, response=%s",
                getattr(getattr(exc, "response", None), "status_code", "?"),
                getattr(getattr(exc, "response", None), "text", str(exc)),
            )
        except Exception:
            log.exception("Unexpected error during poll cycle")

        time.sleep(poll_delay)

    conn.close()
    log.info("Monitor stopped.")


def _trigger_scan(events: list[dict], gitlab_url: str) -> None:
    """Scan newly-detected force push events via force_push_scanner."""
    from collections import defaultdict
    from force_push_scanner import scan_commits

    repos: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        url = f"{gitlab_url}/{ev['repo_org']}/{ev['repo_name']}"
        repos[url].append({"before": ev["before"], "date": ev["timestamp"]})

    log.info("Scanning %d events across %d repos", len(events), len(repos))
    try:
        scan_commits(repos)
    except Exception:
        log.exception("Scan failed")


# ── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor GitLab Events API for zero-commit force pushes and "
        "feed them to the force-push scanner.",
    )
    parser.add_argument(
        "--gitlab-url",
        default=os.environ.get("GITLAB_URL", "https://gitlab.com"),
        help="GitLab instance URL (default: $GITLAB_URL or https://gitlab.com)",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--project-ids",
        nargs="+",
        type=int,
        help="One or more GitLab project IDs to monitor",
    )
    source.add_argument(
        "--group-id",
        type=int,
        help="GitLab group ID — all projects (including subgroups) will be monitored",
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
        help="Seconds between full polling cycles (default: %(default)s)",
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

    token = os.environ.get("GITLAB_TOKEN", "")
    if not token:
        log.error("GITLAB_TOKEN environment variable is required.")
        sys.exit(1)

    if args.scan:
        for tool in ("git", "trufflehog"):
            if shutil.which(tool) is None:
                log.error("Required tool '%s' not found in PATH (needed for --scan)", tool)
                sys.exit(1)

    db_path = Path(args.db_file)
    monitor(
        db_path=db_path,
        gitlab_url=args.gitlab_url.rstrip("/"),
        token=token,
        project_ids=args.project_ids or [],
        group_id=args.group_id,
        poll_delay=args.poll_delay,
        scan=args.scan,
    )


if __name__ == "__main__":
    main()
