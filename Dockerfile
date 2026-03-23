FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Install trufflehog binary
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY force_push_scanner.py github_event_monitor.py ./

# SQLite DB lives here — mount a volume to persist across restarts
VOLUME ["/data"]

ENTRYPOINT ["python", "github_event_monitor.py", "--db-file", "/data/force_push_commits.sqlite3", "--scan"]
