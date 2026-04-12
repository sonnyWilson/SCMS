"""
server/auth.py — Secure Continuous Monitoring System
Login, session management, CSRF tokens, account lockout.

Fixes applied:
  - verify_password handles bcrypt AND scrypt: fallback formats correctly
  - CSRF token stored in session (not regenerated on every request)
  - generate_csrf_token() is idempotent — returns existing token if present
  - Account lockout counter resets on successful login
  - create_user / verify_password signatures match what install.py + reset_password.py expect
"""

import os
import hashlib
import base64
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import request, session, redirect, url_for, jsonify

log = logging.getLogger("scms.auth")

# ── Lockout config ────────────────────────────────────────────────────────────
MAX_ATTEMPTS   = 10
LOCKOUT_SECS   = 300   # 5 minutes

# In-memory lockout table  {username: {"attempts": int, "locked_until": float}}
_lockout: dict = {}

# ── DB helper ─────────────────────────────────────────────────────────────────
def _get_conn():
    from config import DB_CONFIG
    import psycopg2
    return psycopg2.connect(**DB_CONFIG)


def ensure_users_table():
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scms_users (
                    id            SERIAL PRIMARY KEY,
                    username      VARCHAR(64) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role          VARCHAR(20) DEFAULT 'analyst',
                    created_at    TIMESTAMPTZ DEFAULT NOW(),
                    last_login    TIMESTAMPTZ,
                    active        BOOLEAN DEFAULT TRUE
                )
            """)
        conn.commit()
    finally:
        conn.close()


# ── Password hashing ──────────────────────────────────────────────────────────
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(plaintext: str) -> str:
    """Hash a password. Uses bcrypt if available, otherwise stdlib scrypt."""
    try:
        import bcrypt
        return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()
    except ImportError:
        pass
    salt = os.urandom(32)
    dk   = hashlib.scrypt(plaintext.encode(), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return "scrypt:" + base64.b64encode(salt).decode() + ":" + base64.b64encode(dk).decode()


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored hash.
    Supports:
      - bcrypt hashes  ($2b$... / $2a$...)
      - scrypt hashes  (scrypt:<b64salt>:<b64dk>)
    """
    if not plaintext or not stored_hash:
        return False

    try:
        # ── bcrypt ────────────────────────────────────────────────────────────
        if stored_hash.startswith(("$2b$", "$2a$", "$2y$")):
            import bcrypt
            return bcrypt.checkpw(plaintext.encode(), stored_hash.encode())

        # ── scrypt fallback ───────────────────────────────────────────────────
        if stored_hash.startswith("scrypt:"):
            parts = stored_hash.split(":")
            if len(parts) != 3:
                log.warning("Malformed scrypt hash")
                return False
            _, b64_salt, b64_dk = parts
            salt       = base64.b64decode(b64_salt)
            stored_dk  = base64.b64decode(b64_dk)
            derived_dk = hashlib.scrypt(plaintext.encode(), salt=salt,
                                        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            # Constant-time comparison
            return secrets.compare_digest(derived_dk, stored_dk)

        log.warning("Unknown password hash format: %s…", stored_hash[:10])
        return False

    except Exception as e:
        log.error("verify_password error: %s", e)
        return False


# ── User CRUD ─────────────────────────────────────────────────────────────────
def get_user(username: str) -> dict | None:
    """Return user row as dict, or None if not found."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, password_hash, role, active "
                "FROM scms_users WHERE username = %s",
                (username.lower().strip(),)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id":            row[0],
                "username":      row[1],
                "password_hash": row[2],
                "role":          row[3],
                "active":        row[4],
            }
    finally:
        conn.close()


def create_user(username: str, password: str, role: str = "admin") -> tuple[bool, str]:
    """
    Create a new user account.
    Returns (True, "ok") on success, (False, reason) on failure.
    """
    import psycopg2
    if len(password) < 12:
        return False, "Password must be at least 12 characters"
    pw_hash = hash_password(password)
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scms_users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username.lower().strip(), pw_hash, role)
            )
        conn.commit()
        return True, "ok"
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return False, f"Username '{username}' already exists"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        conn.close()


def _update_last_login(username: str):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scms_users SET last_login = NOW() WHERE username = %s",
                (username.lower().strip(),)
            )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


# ── Account lockout ───────────────────────────────────────────────────────────
def _is_locked(username: str) -> bool:
    entry = _lockout.get(username)
    if not entry:
        return False
    if entry["locked_until"] and datetime.now(timezone.utc).timestamp() < entry["locked_until"]:
        return True
    # Lockout expired — clear it
    _lockout.pop(username, None)
    return False


def _record_failure(username: str):
    entry = _lockout.setdefault(username, {"attempts": 0, "locked_until": 0.0})
    entry["attempts"] += 1
    if entry["attempts"] >= MAX_ATTEMPTS:
        entry["locked_until"] = datetime.now(timezone.utc).timestamp() + LOCKOUT_SECS
        log.warning("Account '%s' locked after %d failed attempts", username, entry["attempts"])


def _record_success(username: str):
    _lockout.pop(username, None)


# ── CSRF ──────────────────────────────────────────────────────────────────────
def generate_csrf_token() -> str:
    """
    Return the CSRF token for this session.
    Creates one if it doesn't exist yet (idempotent).
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf(token: str | None) -> bool:
    """
    Return True if the submitted token matches the session token.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected = session.get("csrf_token")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)


# ── Login / logout ────────────────────────────────────────────────────────────
def attempt_login(username: str, password: str) -> tuple[bool, str]:
    """
    Validate credentials.
    Returns (True, role) on success, (False, reason) on failure.
    """
    username = (username or "").lower().strip()

    if _is_locked(username):
        return False, "Account temporarily locked — too many failed attempts"

    user = get_user(username)
    if not user:
        _record_failure(username)
        log.warning("Login attempt for unknown user '%s' from %s", username, request.remote_addr)
        return False, "Invalid username or password"

    if not user["active"]:
        return False, "Account is disabled"

    if not verify_password(password, user["password_hash"]):
        _record_failure(username)
        log.warning("Failed login for '%s' from %s", username, request.remote_addr)
        return False, "Invalid username or password"

    _record_success(username)
    _update_last_login(username)
    log.info("Successful login: '%s' from %s", username, request.remote_addr)
    return True, user["role"]


# ── Decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    """Redirect to login page if no valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def api_login_required(f):
    """Return 401 JSON if no valid session (for API/AJAX routes)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated
