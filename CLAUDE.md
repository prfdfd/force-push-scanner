# CLAUDE.md

## Project Overview

Force Push Secret Scanner — monitors GitHub and GitLab Events APIs for force pushes and scans overwritten commits for leaked secrets using [TruffleHog](https://github.com/trufflesecurity/trufflehog).

## Architecture

- **`force_push_scanner.py`** — CLI tool that reads force-push events from a SQLite DB or CSV, reports summary statistics, and optionally scans the overwritten commits with TruffleHog. Findings are stored back into the SQLite DB.
- **`github_event_monitor.py`** — Long-running daemon that polls the GitHub public Events API for zero-commit force pushes using ETag conditional requests. Stores events in SQLite and optionally triggers scanning.
- **`gitlab_event_monitor.py`** — Same as above but for GitLab's Events API.
- **Docker** — `Dockerfile` + `docker-compose.yml` run both monitors as containers with a shared SQLite volume at `/data`.

## Tech Stack

- Python 3.12 (runs on 3.10+ via `from __future__ import annotations`)
- Dependencies: `requests`, `colorama` (see `requirements.txt`)
- External tools: `git`, `trufflehog` (must be in PATH)
- SQLite for event and findings storage
- Docker for deployment

## Common Commands

```bash
# Run the scanner against an org (requires --db-file or --events-file)
python force_push_scanner.py <org> --db-file force_push_commits.sqlite3

# Report only (no TruffleHog scan)
python force_push_scanner.py <org> --db-file force_push_commits.sqlite3 --no-scan

# Start the GitHub event monitor
export GITHUB_TOKEN=ghp_...
python github_event_monitor.py --db-file force_push_commits.sqlite3

# Start via Docker
docker compose up -d

# View logs
docker compose logs -f
```

## Code Conventions

- Pure Python, no frameworks — stdlib + `requests` + `colorama`
- Functions use type hints (`from __future__ import annotations` for forward refs)
- Errors printed with colored output via `colorama` (graceful fallback if missing)
- `terminate()` helper for fatal errors (prints red message, calls `sys.exit(1)`)
- `RunCmdError` for subprocess failures; callers decide whether to abort or skip
- Logging via stdlib `logging`; `--verbose` / `-v` enables DEBUG level
- Fork-based contribution model; CLA required (see `CONTRIBUTING.md`)
