# SCMS — Secure Continuous Monitoring System

A lightweight, Python-based log monitoring daemon that tails text files and systemd journal units, ships events to a central server over HTTP, and buffers them locally when the server is unreachable.

---

## Overview

SCMS runs as two background processes managed by a single CLI:

- **Agent** — tails configured log files and journal units, then forwards each line to the server as a structured JSON event.
- **Server** — receives inbound events, authenticates them via API key, and persists them to a SQLite database.

When the server is down, the agent buffers events to disk and flushes them automatically once the connection is restored.

---

## Project Structure

```
SCMS/
├── scms.py            # CLI control (start / stop / restart / status / logs)
├── agent.py           # Log collection daemon
├── app.py             # Flask/HTTP server
├── run_server.py      # Server entrypoint
├── buffer.py          # Disk-based event buffer
├── db.py              # PostgreSQL helpers
├── config.py          # Configuration (paths, API key, server URL)
├── install.py         # First-run setup
├── setup_db.py        # Database initialisation
├── reset_all.py       # Full reset (DB + buffer)
├── reset_password.py  # Reset server credentials
├── run/               # PID files
└── logs/              # Rotating log files
```

---

## Requirements

- Python 3.8+
- `requests` library
- `journalctl` available (for journal monitoring)

Install dependencies:

```bash
pip install requests flask psycopg2-binary
```

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/sonnyWilson/SCMS.git
cd SCMS

# 2. Run the installer (creates the DB, run/, and logs/ directories)
python install.py

# 3. Edit config.py to set your log file paths, journal units, API key, and server URL
```

---

## Usage

All process management goes through `scms.py`:

```bash
# Start both server and agent
python scms.py start

# Start a single service
python scms.py start server
python scms.py start agent

# Stop everything
python scms.py stop

# Restart
python scms.py restart

# Check running status
python scms.py status

# Tail the server log (last 60 lines by default)
python scms.py logs server

# Tail the agent log, custom line count
python scms.py logs agent -n 100
```

### Status output example

```
 SCMS Service Status
 ────────────────────────────────────────
 SCMS Server                ● RUNNING (PID 12345)
 SCMS Agent                 ● RUNNING (PID 12346)
```

---

## Configuration (`config.py`)

| Variable | Description |
|---|---|
| `TEXT_LOG_FILES` | List of absolute paths to text log files to tail |
| `JOURNAL_UNITS` | List of systemd unit names (or `"all"` for the full journal) |
| `SERVER_URL` | HTTP endpoint the agent posts events to |
| `API_KEY` | Shared secret used to authenticate events |

---

## How It Works

1. The **agent** spawns one thread per monitored source (text file or journal unit).
2. Each thread tails its source and calls `_send_log()` for every non-empty line.
3. `_send_log()` first flushes any buffered events, then POSTs the new event to the server.
4. If the POST fails (connection error or non-200 response), the event is saved to the local buffer via `buffer.py`.
5. The **server** validates the API key and writes the event to PostgreSQL via `db.py`.

---

## Utilities

```bash
# Re-initialise the database
python setup_db.py

# Wipe the database and clear the event buffer
python reset_all.py

# Reset the server password / credentials
python reset_password.py
```

---

## License

MIT
