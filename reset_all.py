#!/usr/bin/env python3
"""
reset_all.py — Secure Continuous Monitoring System
Truncates all event data (Logs, Packets, Incidents, SIS_Events, GeoEvents,
Inventory) while preserving the schema, users, and configuration.

Usage:  python3 reset_all.py [--yes]
"""

import sys
from pathlib import Path

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

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[1m"; X = "\033[0m"

TABLES = [
    "GeoEvents",
    "SIS_Events",
    "Packets",
    "Logs",
    "Incidents",
    "Inventory",
]


def confirm() -> bool:
    if "--yes" in sys.argv or "-y" in sys.argv:
        return True
    print(f"\n  {Y}{B}WARNING:{X}{Y} This will DELETE ALL event data from:{X}")
    for t in TABLES:
        print(f"    • {t}")
    print(f"\n  Users and schema are preserved.")
    ans = input(f"\n  Type {B}YES{X} to confirm: ").strip()
    return ans == "YES"


def reset_all():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        with conn.cursor() as cur:
            for table in TABLES:
                cur.execute(f'TRUNCATE TABLE "{table}" RESTART IDENTITY CASCADE')
                print(f"  {G}✔{X}  Truncated {table}")
        conn.commit()
        conn.close()
        print(f"\n  {G}{B}All event data cleared.{X}\n")
    except Exception as exc:
        print(f"  {R}Reset failed: {exc}{X}")
        sys.exit(1)


def main():
    print(f"\n{B}SCMS — Full Data Reset{X}\n{'─'*36}")
    print(f"  Target database: {B}{DB_CONFIG.get('database', 'scms')}{X} @ {DB_CONFIG.get('host','localhost')}")
    if not confirm():
        print("  Aborted.")
        sys.exit(0)
    reset_all()


if __name__ == "__main__":
    main()
