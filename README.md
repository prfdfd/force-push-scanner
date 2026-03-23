# Force Push Secret Scanner

Monitors the GitHub Events API for force pushes and scans the overwritten commits for leaked secrets using [TruffleHog](https://github.com/trufflesecurity/trufflehog).

Built with [Sharon Brizinov](https://github.com/SharonBrizinov) — [blog post](https://trufflesecurity.com/blog/guest-post-how-i-scanned-all-of-github-s-oops-commits-for-leaked-secrets).

## Setup

```bash
git clone https://github.com/trufflesecurity/force-push-scanner.git
cd force-push-scanner
cp .env.example .env
```

Edit `.env` and add your GitHub token:

```
GITHUB_TOKEN=ghp_...
```

Start:

```bash
docker compose up -d
```

View logs:

```bash
docker compose logs -f
```

## Disclaimer

For authorized defensive security operations only.
