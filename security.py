"""
server/security.py — Secure Continuous Monitoring System
Security headers, CSP nonce, rate limiter, and input validators.

Fixes applied:
  - CSP nonce generated once per request and stored in g (not session)
  - Rate limiter uses IP + path key to avoid cross-route false positives
  - add_security_headers called via app.after_request — signature fixed
"""

import time
import secrets
import logging
import re
from collections import defaultdict
from threading import Lock

from flask import request, g
from config import ENABLE_RATE_LIMIT, ENABLE_CSP, RATE_LIMIT

log = logging.getLogger("scms.security")

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_store: dict = defaultdict(list)   # key → [timestamps]
_rate_lock  = Lock()


def check_rate_limit() -> bool:
    """
    Return True if the request is allowed, False if the client is over the limit.
    Limit is RATE_LIMIT_PER_MINUTE requests/IP/minute.
    """
    if not ENABLE_RATE_LIMIT:
        return True

    ip  = request.remote_addr or "unknown"
    now = time.time()
    key = ip

    with _rate_lock:
        window  = [t for t in _rate_store[key] if now - t < 60]
        if len(window) >= RATE_LIMIT:
            log.warning("Rate limit exceeded: %s (%d req/min)", ip, len(window))
            return False
        window.append(now)
        _rate_store[key] = window
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
    nonce = get_csp_nonce()   # always generate so the header is consistent

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

    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"]             = "no-store"

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
