#!/usr/bin/env python3
"""
reset_all.py — Secure Continuous Monitoring System
Wipes all data from every table and resets sequences.
Does NOT drop the database or remove the schema — the tables are
truncated and auto-increment counters are reset to 1.

Run from the SCMS project directory:
    python3 reset_all.py
    python3 reset_all.py --yes           # skip confirmation prompt
    python3 reset_all.py --yes --newpw   # also reset/create admin account after wipe
"""

import sys
import os
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; X="\033[0m"
def ok(m):   print(f"{G}  ✔  {m}{X}")
def err(m):  print(f"{R}  ✘  {m}{X}"); sys.exit(1)
def info(m): print(f"{C}  →  {m}{X}")
def warn(m): print(f"{Y}  ⚠  {m}{X}")


# ── Tables to wipe (order matters for FK constraints) ─────────────────────────
TABLES = [
    "GeoEvents",
    "SIS_Events",
    "Incidents",
    "Packets",
    "Logs",
    "Inventory",
    # scms_users intentionally last — wiped only with --wipe-users
]

SEQUENCES = {
    "Logs":       "logs_logid_seq",
    "Packets":    "packets_pktid_seq",
    "Incidents":  "incidents_incid_seq",
    "Inventory":  "inventory_devid_seq",
    "SIS_Events": "sis_events_sisid_seq",
    "GeoEvents":  "geoevents_geoid_seq",
    "scms_users": "scms_users_id_seq",
}


def get_conn():
    try:
        import psycopg2
        from config import DB_CONFIG
        return psycopg2.connect(**DB_CONFIG)
    except ImportError:
        err("psycopg2 not installed — pip install psycopg2-binary --break-system-packages")
    except Exception as e:
        err(f"Cannot connect to PostgreSQL: {e}\n"
            "  Check that PostgreSQL is running:  sudo systemctl status postgresql\n"
            "  Check credentials in .env")


def truncate_tables(conn, wipe_users: bool = False):
    tables = TABLES + (["scms_users"] if wipe_users else [])
    with conn.cursor() as cur:
        for table in tables:
            try:
                cur.execute(f'TRUNCATE TABLE "{table}" RESTART IDENTITY CASCADE')
                ok(f"Truncated {table}")
            except Exception as e:
                warn(f"Could not truncate {table}: {e}")
                conn.rollback()
    conn.commit()
    info("All sequences reset to 1.")


def clear_buffer():
    buf = Path(__file__).resolve().parent / "buffer.json"
    if buf.exists():
        buf.unlink()
        ok("Cleared buffer.json")
    else:
        info("buffer.json not present — nothing to clear.")


def clear_logs():
    log_dir = Path(__file__).resolve().parent / "logs"
    if log_dir.exists():
        for f in log_dir.glob("*.log"):
            try:
                f.write_text("")
                ok(f"Cleared {f.name}")
            except Exception as e:
                warn(f"Could not clear {f}: {e}")
    else:
        info("logs/ directory not found — nothing to clear.")


def create_admin(conn):
    import getpass
    print(f"\n{B}Create / Reset Admin Account{X}")
    username = input("  Username [admin]: ").strip() or "admin"
    while True:
        pw1 = getpass.getpass("  Password (min 12 chars): ")
        if len(pw1) < 12:
            print(f"{R}  Password too short — try again.{X}")
            continue
        pw2 = getpass.getpass("  Confirm password: ")
        if pw1 != pw2:
            print(f"{R}  Passwords do not match — try again.{X}")
            continue
        break

    # Use the same hashing logic as auth.py
    try:
        import bcrypt
        pw_hash = bcrypt.hashpw(pw1.encode(), bcrypt.gensalt(rounds=12)).decode()
    except ImportError:
        import hashlib, base64, os as _os
        salt = _os.urandom(32)
        dk   = hashlib.scrypt(pw1.encode(), salt=salt, n=2**15, r=8, p=1)
        pw_hash = "scrypt:" + base64.b64encode(salt).decode() + ":" + base64.b64encode(dk).decode()

    import psycopg2
    with conn.cursor() as cur:
        try:
            cur.execute(
                "INSERT INTO scms_users (username, password_hash, role, active) "
                "VALUES (%s, %s, 'admin', TRUE) "
                "ON CONFLICT (username) DO UPDATE "
                "SET password_hash=EXCLUDED.password_hash, active=TRUE",
                (username.lower(), pw_hash)
            )
            conn.commit()
            ok(f"Admin account '{username}' ready — log in at http://localhost:5000")
        except Exception as e:
            conn.rollback()
            err(f"Could not upsert admin account: {e}")


def main():
    parser = argparse.ArgumentParser(
        prog="reset_all.py",
        description="Wipe all SCMS data and start fresh",
    )
    parser.add_argument("--yes",        action="store_true",
                        help="Skip the confirmation prompt")
    parser.add_argument("--wipe-users", action="store_true",
                        help="Also truncate the scms_users table (you will need to re-create admin)")
    parser.add_argument("--newpw",      action="store_true",
                        help="Prompt to create/reset admin account after wiping")
    args = parser.parse_args()

    print(f"\n{B}{'═'*60}{X}")
    print(f"  {R}SCMS — Full Data Reset{X}")
    print(f"{B}{'═'*60}{X}")

    if args.wipe_users:
        print(f"\n  {R}WARNING: --wipe-users will DELETE ALL dashboard accounts.{X}")
        print(f"  You MUST use --newpw or run reset_password.py afterwards to regain access.\n")

    if not args.yes:
        print(f"  {Y}This will permanently delete all logs, packets, incidents,")
        print(f"  inventory records, SIS events, and geo events.{X}")
        if args.wipe_users:
            print(f"  {R}All user accounts will also be deleted.{X}")
        confirm = input("\n  Type 'yes' to confirm: ").strip().lower()
        if confirm != "yes":
            print(f"\n  {Y}Aborted — no changes made.{X}\n")
            sys.exit(0)

    conn = get_conn()

    print()
    info("Truncating tables …")
    truncate_tables(conn, wipe_users=args.wipe_users)

    info("Clearing offline buffer …")
    clear_buffer()

    info("Clearing log files …")
    clear_logs()

    if args.newpw or args.wipe_users:
        create_admin(conn)

    conn.close()

    print(f"\n{G}{B}✔  Reset complete — the system is ready for a fresh start.{X}")
    if not args.wipe_users:
        print(f"  Existing user accounts are untouched.")
        print(f"  To reset a password:  python3 reset_password.py")
    print(f"  To start the server:   python3 scms.py start server\n")


if __name__ == "__main__":
    main()
