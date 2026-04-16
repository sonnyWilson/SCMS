"""
server/security.py — Secure Continuous Monitoring System
Security headers, CSP nonce, rate limiter, and input validators.

Changes:
  - Rate limiter now cleans up stale entries every 5 minutes to prevent
    unbounded memory growth under sustained traffic.
  - Cleanup runs in a daemon thread so it never blocks a request.
"""

import time
import secrets
import logging
import re
import threading
from collections import defaultdict

from flask import request, g
from config import ENABLE_RATE_LIMIT, ENABLE_CSP, RATE_LIMIT

log = logging.getLogger("scms.security")

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_store: dict = defaultdict(list)   # ip → [timestamps]
_rate_lock  = threading.Lock()
_last_cleanup = [0.0]


def _cleanup_rate_store():
    """Remove entries whose entire window is older than 60 seconds."""
    now = time.time()
    with _rate_lock:
        stale = [k for k, ts in _rate_store.items()
                 if not any(now - t < 60 for t in ts)]
        for k in stale:
            del _rate_store[k]


def check_rate_limit() -> bool:
    """
    Return True if the request is allowed, False if the client is over the limit.
    Limit is RATE_LIMIT_PER_MINUTE requests/IP/minute.
    Runs a background cleanup pass at most once every 5 minutes.
    """
    if not ENABLE_RATE_LIMIT:
        return True

    ip  = request.remote_addr or "unknown"
    now = time.time()

    # Periodic cleanup — fire-and-forget daemon thread, at most once per 5 min
    if now - _last_cleanup[0] > 300:
        _last_cleanup[0] = now
        threading.Thread(target=_cleanup_rate_store, daemon=True,
                         name="rate-limit-gc").start()

    with _rate_lock:
        window = [t for t in _rate_store[ip] if now - t < 60]
        if len(window) >= RATE_LIMIT:
            log.warning("Rate limit exceeded: %s (%d req/min)", ip, len(window))
            return False
        window.append(now)
        _rate_store[ip] = window
    return True


# ── CSP nonce ────────────────────────────────────────────────────────────────
def get_csp_nonce() -> str:
    """
    Return (or create) the CSP nonce for this request.
    Stored in Flask's g so it is the same value used in both the
    Content-Security-Policy header and the HTML <script> tags.
    """
    if not hasattr(g, "csp_nonce"):
        g.csp_nonce = secrets.token_urlsafe(16)
    return g.csp_nonce


# ── Security headers ─────────────────────────────────────────────────────────
def add_security_headers(response):
    """
    after_request hook — adds security headers to every response.
    """
    nonce = get_csp_nonce()

    if ENABLE_CSP:
        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            f"style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data: https:; "
            f"connect-src 'self'; "
            f"frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"]          = "no-store"

    return response


# ── Input validators ──────────────────────────────────────────────────────────
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
_IP_RE       = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def validate_username(value: str) -> bool:
    return bool(value and _USERNAME_RE.match(value))


def validate_ip(value: str) -> bool:
    if not value or not _IP_RE.match(value):
        return False
    return all(0 <= int(p) <= 255 for p in value.split("."))


def sanitize_str(value: str, max_len: int = 512) -> str:
    """Strip leading/trailing whitespace and truncate."""
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]
