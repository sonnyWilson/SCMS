"""
buffer.py — Secure Continuous Monitoring System
Thread-safe offline buffer for log events that fail to reach the server.
Uses an atomic write (write-then-rename) to prevent data corruption.
"""

import json
import threading
from pathlib import Path

_BUFFER_FILE = Path(__file__).resolve().parent / "buffer.json"
_lock        = threading.Lock()


def save(event: dict) -> None:
    with _lock:
        data = _read()
        data.append(event)
        _write(data)


def load() -> list:
    with _lock:
        return _read()


def clear() -> None:
    with _lock:
        _BUFFER_FILE.unlink(missing_ok=True)


def _read() -> list:
    if not _BUFFER_FILE.exists():
        return []
    try:
        return json.loads(_BUFFER_FILE.read_text())
    except Exception:
        return []


def _write(data: list) -> None:
    tmp = _BUFFER_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data))
        tmp.replace(_BUFFER_FILE)   # atomic on POSIX
    except OSError:
        pass
