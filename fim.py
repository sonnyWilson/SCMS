"""
server/fim.py — Secure Continuous Monitoring System
File Integrity Monitoring (FIM) — hashes critical files with SHA-256
and detects changes against a stored baseline.
"""

import os
import hashlib
import logging
from pathlib import Path

log = logging.getLogger("scms.fim")

DEFAULT_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/hosts", "/etc/crontab", "/root/.bashrc",
    "/etc/ssh/sshd_config", "/etc/pam.d/common-auth",
]


def _sha256(path: str) -> str | None:
    """Return hex SHA-256 of file contents, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        log.debug("FIM hash error on %s: %s", path, exc)
        return None


def fim_scan(paths: list | None = None) -> list[dict]:
    """
    Scan each path and return a list of dicts with:
      path, hash (SHA-256), size (bytes), mtime (float), status ('ok' or error msg)
    """
    targets = paths or DEFAULT_PATHS
    results = []

    for p in targets:
        try:
            stat   = os.stat(p)
            digest = _sha256(p)
            results.append({
                "path":   p,
                "hash":   digest,
                "size":   stat.st_size,
                "mtime":  stat.st_mtime,
                "status": "ok",
            })
        except FileNotFoundError:
            results.append({"path": p, "hash": None, "size": 0, "mtime": 0,
                             "status": "not found"})
        except PermissionError:
            results.append({"path": p, "hash": None, "size": 0, "mtime": 0,
                             "status": "permission denied"})
        except Exception as exc:
            results.append({"path": p, "hash": None, "size": 0, "mtime": 0,
                             "status": str(exc)})

    return results
