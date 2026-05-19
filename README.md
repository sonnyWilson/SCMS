# SCMS — Secure Continuous Monitoring System

A lightweight, self-hosted security monitoring platform built with Python and Flask. SCMS runs a background agent that collects system events and forwards them to a local server, which exposes a web interface for viewing and managing alerts.

---

## Features

- Agent/server architecture with PID-based process management (no systemd required)
- Flask web backend with session-based authentication
- SQLite database for event and user storage
- ANSI-colored CLI control script (`scms.py`) for start / stop / restart / status / logs

---

## Requirements

- Python 3.10+
- pip

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Initialize the database

```bash
python install.py
```

### 2. Start the server and agent

```bash
python scms.py start
```

### 3. Open the dashboard

Navigate to `http://localhost:<port>` (see `config.py` for the configured port).

---

## CLI Reference

```
python scms.py <command> [target]

Commands:
  start    [server|agent|both]   Start one or both services
  stop     [server|agent|both]   Stop one or both services
  restart  [server|agent|both]   Restart one or both services
  status                         Show running status of all services
  logs     [server|agent] [-n N] Tail the last N lines of a service log (default: 60)
```

---

## Project Structure

```
SCMS/
├── scms.py           # CLI entry point — manage services
├── app.py            # Flask application factory
├── agent.py          # Background monitoring agent
├── run_server.py     # Production server runner (Waitress/Gunicorn)
├── config.py         # Centralised configuration
├── db.py             # Database helpers
├── buffer.py         # Event buffer between agent and server
├── install.py        # First-run database setup
├── reset_all.py      # Wipe and reinitialise all data
├── reset_password.py # Admin password reset utility
├── setup_db.py       # Low-level schema creation
└── server/           # Flask blueprints (routes, auth, security)
```

Runtime directories (`run/` for PID files, `logs/` for output) are created automatically and are excluded from version control.

---

## Configuration

Edit `config.py` to change the host, port, secret key, and database path before first run.

---

## License

MIT
