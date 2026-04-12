#!/usr/bin/env python3
"""
reset_password.py — Secure Continuous Monitoring System
Reset or create any dashboard user account.

Run from the SCMS project directory:
    python3 reset_password.py
    python3 reset_password.py --username admin --password NewPassword123!
    python3 reset_password.py --list
"""

import sys
import os
import argparse
import getpass
import hashlib
import hmac
import base64
import secrets

# Must run from the project root so config.py is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Colours ───────────────────────────────────────────────────────────────────
G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; X="\033[0m"
def ok(m):   print(f"{G}  ✔  {m}{X}")
def err(m):  print(f"{R}  ✘  {m}{X}")
def info(m): print(f"{C}  →  {m}{X}")
def warn(m): print(f"{Y}  ⚠  {m}{X}")


# ── Load config (reads .env automatically) ────────────────────────────────────
def load_config():
    try:
        import config as _cfg
        return _cfg.DB_CONFIG
    except Exception as e:
        err(f"Cannot load config.py: {e}")
        err("Run this script from the SCMS project directory.")
        sys.exit(1)


# ── DB connection ─────────────────────────────────────────────────────────────
def get_conn(db_config):
    try:
        import psycopg2
        return psycopg2.connect(**db_config)
    except ImportError:
        err("psycopg2 not installed.")
        err("Fix:  sudo apt install python3-psycopg2")
        err("  or: pip install psycopg2-binary --break-system-packages")
        sys.exit(1)
    except Exception as e:
        err(f"Cannot connect to PostgreSQL: {e}")
        err("Check that PostgreSQL is running:  sudo systemctl status postgresql")
        err("Check your DB credentials in .env")
        sys.exit(1)


def ensure_table(conn):
    """Create scms_users table if it doesn't exist."""
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scms_users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(64) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          VARCHAR(20) DEFAULT 'analyst',
            created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            last_login    TIMESTAMP WITH TIME ZONE,
            active        BOOLEAN DEFAULT TRUE
        )
    """)
    conn.commit()
    cur.close()


# ── Password hashing (mirrors server/auth.py exactly) ────────────────────────
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

def hash_password(plaintext: str) -> str:
    """Hash a password. Uses bcrypt if available, otherwise scrypt."""
    try:
        import bcrypt
        return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()
    except ImportError:
        pass
    # stdlib scrypt fallback
    salt = os.urandom(32)
    dk   = hashlib.scrypt(plaintext.encode(), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return "scrypt:" + base64.b64encode(salt).decode() + ":" + base64.b64encode(dk).decode()


# ── User operations ───────────────────────────────────────────────────────────
def list_users(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT username, role, active,
               created_at::text,
               COALESCE(last_login::text, 'never') as last_login
        FROM scms_users
        ORDER BY id
    """)
    rows = cur.fetchall()
    cur.close()
    if not rows:
        warn("No users found in scms_users table.")
        return
    print(f"\n  {'Username':<20} {'Role':<12} {'Active':<8} {'Last Login':<22} Created")
    print("  " + "─"*80)
    for username, role, active, created, last_login in rows:
        status = f"{G}yes{X}" if active else f"{R}no{X}"
        print(f"  {username:<20} {role:<12} {status:<16} {last_login[:19]:<22} {created[:19]}")
    print()


def set_password(conn, username: str, new_password: str) -> bool:
    """Update password for an existing user. Returns True on success."""
    cur = conn.cursor()
    cur.execute("SELECT id FROM scms_users WHERE username = %s", (username.lower().strip(),))
    row = cur.fetchone()
    if not row:
        cur.close()
        return False
    pw_hash = hash_password(new_password)
    cur.execute(
        "UPDATE scms_users SET password_hash=%s, active=TRUE WHERE username=%s",
        (pw_hash, username.lower().strip())
    )
    conn.commit()
    cur.close()
    return True


def create_user(conn, username: str, password: str, role: str = "admin") -> bool:
    """Create a new user. Returns True on success."""
    import psycopg2
    pw_hash = hash_password(password)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scms_users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username.lower().strip(), pw_hash, role)
        )
        conn.commit()
        cur.close()
        return True
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return None   # signals "already exists"
    except Exception as e:
        conn.rollback()
        err(f"Create user error: {e}")
        return False


def unlock_user(conn, username: str) -> bool:
    """Set active=TRUE so a deactivated account can log in again."""
    cur = conn.cursor()
    cur.execute("UPDATE scms_users SET active=TRUE WHERE username=%s",
                (username.lower().strip(),))
    affected = cur.rowcount
    conn.commit(); cur.close()
    return affected > 0


# ── Password prompt ───────────────────────────────────────────────────────────
def prompt_password(label: str = "New password") -> str:
    while True:
        pw = getpass.getpass(f"  {label} (min 12 chars): ").strip()
        if len(pw) < 12:
            err("Password must be at least 12 characters. Try again.")
            continue
        pw2 = getpass.getpass(f"  Confirm password: ").strip()
        if pw != pw2:
            err("Passwords do not match. Try again.")
            continue
        return pw


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="reset_password.py",
        description="Manage SCMS dashboard user accounts",
    )
    parser.add_argument("--username", "-u", help="Username to create or reset")
    parser.add_argument("--password", "-p", help="New password (prompted if omitted)")
    parser.add_argument("--role",     "-r", default="admin",
                        choices=["admin","analyst"], help="Role for new users (default: admin)")
    parser.add_argument("--list",     "-l", action="store_true",
                        help="List all users and exit")
    parser.add_argument("--unlock",         action="store_true",
                        help="Unlock a locked/inactive account without changing password")
    args = parser.parse_args()

    print(f"\n{B}Secure Continuous Monitoring System — Account Manager{X}\n")

    db_config = load_config()
    conn      = get_conn(db_config)
    ensure_table(conn)

    # ── List users ────────────────────────────────────────────────────────────
    if args.list:
        list_users(conn)
        conn.close()
        return

    # ── Need a username for everything else ───────────────────────────────────
    if not args.username:
        # Interactive mode
        print("  What would you like to do?\n")
        print(f"  {B}[1]{X} Reset password for existing user")
        print(f"  {B}[2]{X} Create new admin account")
        print(f"  {B}[3]{X} List all users")
        print(f"  {B}[4]{X} Unlock an account\n")
        choice = input("  Choice (1-4): ").strip()

        if choice == "3":
            list_users(conn)
            conn.close()
            return

        if choice == "4":
            username = input("  Username to unlock: ").strip()
            if unlock_user(conn, username):
                ok(f"Account '{username}' unlocked — try logging in now")
            else:
                err(f"User '{username}' not found")
            conn.close()
            return

        username = input("  Username: ").strip()
        if not username:
            err("Username cannot be empty.")
            conn.close()
            sys.exit(1)

        password = prompt_password()
        role     = "admin" if choice == "2" else "admin"

        if choice == "1":
            # Reset existing
            if set_password(conn, username, password):
                ok(f"Password updated for '{username}'")
                ok("You can now log in at http://localhost:5000")
            else:
                # User doesn't exist — offer to create
                warn(f"User '{username}' not found.")
                yn = input(f"  Create new admin account '{username}'? [y/N]: ").strip().lower()
                if yn == "y":
                    result = create_user(conn, username, password, "admin")
                    if result is True:
                        ok(f"Admin account '{username}' created")
                        ok("Log in at http://localhost:5000")
                    elif result is None:
                        warn("Username already exists (race condition). Try again.")
                    else:
                        err("Failed to create account.")
                else:
                    info("No changes made.")

        elif choice == "2":
            result = create_user(conn, username, password, "admin")
            if result is True:
                ok(f"Admin account '{username}' created")
                ok("Log in at http://localhost:5000")
            elif result is None:
                warn(f"Username '{username}' already exists.")
                yn = input("  Reset its password instead? [y/N]: ").strip().lower()
                if yn == "y":
                    set_password(conn, username, password)
                    ok(f"Password reset for '{username}'")

    else:
        # ── Non-interactive (--username / --password flags) ───────────────────
        username = args.username.strip()

        if args.unlock:
            if unlock_user(conn, username):
                ok(f"Account '{username}' unlocked")
            else:
                err(f"User '{username}' not found")
            conn.close()
            return

        password = args.password if args.password else prompt_password()

        if len(password) < 12:
            err("Password must be at least 12 characters.")
            conn.close()
            sys.exit(1)

        # Try reset first, then create
        if set_password(conn, username, password):
            ok(f"Password reset for '{username}'")
            ok("Log in at http://localhost:5000")
        else:
            info(f"User '{username}' not found — creating as {args.role} …")
            result = create_user(conn, username, password, args.role)
            if result is True:
                ok(f"Account '{username}' created (role: {args.role})")
                ok("Log in at http://localhost:5000")
            elif result is None:
                err(f"Username '{username}' already exists but update failed.")
            else:
                err("Failed. Check database connection and try again.")

    conn.close()


if __name__ == "__main__":
    main()
