"""
Log collection daemon.  Designed to run as a background systemd service.
Handles SIGTERM/SIGINT cleanly with zero error output on normal shutdown.
"""

import time
import socket
import threading
import subprocess
import signal
import sys
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests

from config import TEXT_LOG_FILES, JOURNAL_UNITS, API_KEY, SERVER_URL
import buffer

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
_handler = RotatingFileHandler(LOG_DIR / "agent.log", maxBytes=10*1024*1024, backupCount=3)
_handler.setFormatter(logging.Formatter("%(asctime)s [agent] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler(sys.stdout)])
log = logging.getLogger("scms.agent")

HOSTNAME       = socket.gethostname()
RETRY_INTERVAL = 5
_stop          = threading.Event()


def _handle_shutdown(sig, frame):
    log.info("Shutdown signal received — stopping agent …")
    _stop.set()

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT,  _handle_shutdown)


def _follow_file(f):
    f.seek(0, 2)
    while not _stop.is_set():
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def _follow_journal(unit=None):
    cmd = ["journalctl", "-f", "--no-pager", "-o", "short"]
    if unit and unit != "all":
        cmd.extend(["-u", unit])
    process = None
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        while not _stop.is_set():
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                yield line
    except Exception as exc:
        if not _stop.is_set():
            log.warning("journalctl error (%s): %s", unit, exc)
    finally:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                pass


def _send_log(line: str, source_type: str = "SYS"):
    data = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "host":        HOSTNAME,
        "message":     line.strip(),
        "source_type": source_type,
        "api_key":     API_KEY,
    }
    try:
        _flush_buffer()
        resp = requests.post(SERVER_URL, json=data, timeout=5)
        if resp.status_code != 200:
            buffer.save(data)
    except requests.exceptions.ConnectionError:
        buffer.save(data)
    except Exception as exc:
        log.debug("send_log: %s — buffering", exc)
        buffer.save(data)


def _flush_buffer():
    pending = buffer.load()
    if not pending:
        return
    sent = []
    for event in pending:
        try:
            resp = requests.post(SERVER_URL, json=event, timeout=5)
            if resp.status_code == 200:
                sent.append(event)
        except Exception:
            break
    if sent:
        remaining = [e for e in pending if e not in sent]
        buffer.clear()
        for e in remaining:
            buffer.save(e)
        log.info("Flushed %d buffered event(s)", len(sent))


def _monitor_text_file(path: str):
    while not _stop.is_set():
        try:
            with open(path) as f:
                log.info("Monitoring text file: %s", path)
                for line in _follow_file(f):
                    if line.strip():
                        _send_log(line, source_type="TEXT")
        except FileNotFoundError:
            if not _stop.is_set():
                log.warning("File not found: %s — retrying in %ds", path, RETRY_INTERVAL)
                _stop.wait(RETRY_INTERVAL)
        except Exception as exc:
            if not _stop.is_set():
                log.warning("Error on %s: %s — retrying", path, exc)
                _stop.wait(RETRY_INTERVAL)


def _monitor_journal(unit: str):
    while not _stop.is_set():
        try:
            for line in _follow_journal(unit):
                if line.strip():
                    _send_log(line, source_type="JOURNAL")
        except Exception as exc:
            if not _stop.is_set():
                log.warning("Journal monitor error (%s): %s — retrying", unit, exc)
                _stop.wait(RETRY_INTERVAL)


def main():
    threads = []
    for path in TEXT_LOG_FILES:
        if path.strip():
            t = threading.Thread(target=_monitor_text_file, args=(path,), daemon=True)
            t.start(); threads.append(t)
    for unit in JOURNAL_UNITS:
        if unit.strip():
            t = threading.Thread(target=_monitor_journal, args=(unit,), daemon=True)
            t.start(); threads.append(t)

    log.info("SCMS Agent running on %s — %d text files, %d journal units → %s",
             HOSTNAME, len(TEXT_LOG_FILES), len(JOURNAL_UNITS), SERVER_URL)
    _stop.wait()
    log.info("Agent stopped.")
    sys.exit(0)


if __name__ == "__main__":
    main()
