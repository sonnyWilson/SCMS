#!/usr/bin/env python3
"""
Reset a user's password from the command line (no DB session required).
Usage:  python3 reset_password.py [username]
"""

import sys
import getpass
from pathlib import Path

# Load .env before importing anything that reads config
_env = Path(__file__).resolve().parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        import os; os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

import psycopg2
from config import DB_CONFIG
from server.auth import hash_password

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[1m"; X = "\033[0m"


def reset_password(username: str, new_password: str) -> bool:
    if len(new_password) < 12:
        print(f"  {R}Password must be at least 12 characters{X}")
        return False
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM scms_users WHERE username = %s", (username.lower(),))
            row = cur.fetchone()
            if not row:
                print(f"  {R}User '{username}' not found{X}")
                return False
            pw_hash = hash_password(new_password)
            cur.execute(
                "UPDATE scms_users SET password_hash = %s WHERE username = %s",
                (pw_hash, username.lower()),
            )
        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        print(f"  {R}DB error: {exc}{X}")
        return False


def main():
    print(f"\n{B}SCMS — Password Reset{X}\n{'─'*36}")
    username = (sys.argv[1] if len(sys.argv) > 1 else input("  Username: ").strip()).lower()
    if not username:
        print(f"  {R}No username provided{X}"); sys.exit(1)

    while True:
        password = getpass.getpass(f"  New password for '{username}' (min 12 chars): ")
        if len(password) >= 12:
            break
        print(f"  {Y}Too short — minimum 12 characters{X}")

    confirm = getpass.getpass("  Confirm password: ")
    if password != confirm:
        print(f"  {R}Passwords do not match{X}"); sys.exit(1)

    if reset_password(username, password):
        print(f"  {G}✔  Password updated for '{username}'{X}\n")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
