# Force Push Secret Scanner

Scan for secrets in dangling commits created by force pushes on GitHub. Uses [TruffleHog](https://github.com/trufflesecurity/trufflehog) to find verified credentials in overwritten history.

Built with [Sharon Brizinov](https://github.com/SharonBrizinov) — read the [blog post](https://trufflesecurity.com/blog/guest-post-how-i-scanned-all-of-github-s-oops-commits-for-leaked-secrets).

![demo](./demo.gif)

## Quick Start

### Docker (VPS)

```bash
cp .env.example .env   # add your GITHUB_TOKEN
docker compose up -d
```

This runs the live monitor with `--scan` enabled. Events are persisted in a Docker volume.

### Local

```bash
pip install -r requirements.txt
```

**Scan from the pre-built DB** (get it via [this form](https://forms.gle/344GbP6WrJ1fhW2A6)):

```bash
python force_push_scanner.py <org> --db-file force_push_commits.sqlite3 --scan
```

**Scan from a BigQuery CSV export:**

```sql
SELECT * FROM `external-truffle-security-gha.force_push_commits.pushes`
WHERE repo_org = '<ORG>';
```

```bash
python force_push_scanner.py <org> --events-file export.csv --scan
```

**Live monitor** (polls the GitHub Events API, scans in real time):

```bash
export GITHUB_TOKEN=ghp_...
python github_event_monitor.py --scan
```

## How It Works

1. Collects zero-commit force push events (the strongest signal for secret removal attempts).
2. For each overwritten commit, runs TruffleHog with `--only-verified`.
3. Reports verified findings with commit links.

The live monitor uses ETag conditional requests (304s are free against the rate limit) and respects `X-Poll-Interval`.

## CLI Reference

```
force_push_scanner.py <org> [--db-file PATH] [--events-file PATH] [--scan] [-v]
github_event_monitor.py      [--db-file PATH] [--scan] [--poll-delay N] [-v]
```

## Disclaimer

For authorized defensive security operations only. Obtain permission before scanning. Unauthorized use is prohibited.
