import psycopg2
from config import DB_CONFIG

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def insert(event):
    """
    Insert a parsed log event.
    Previously only stored 8 fields — Severity, MitreIds, DestIp, Protocol,
    and Port were silently dropped, breaking all severity filtering on the
    dashboard.  All 13 fields now persisted.
    """
    conn = get_connection()
    try:
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO Logs
                (EventTime, EventType, Success, UserName, HostName,
                 SourceIp, DestIp, Protocol, Port,
                 Message, RawLine, Severity, MitreIds)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event.get("EventTime"),
                event.get("EventType"),
                event.get("Success"),
                event.get("UserName"),
                event.get("HostName"),
                event.get("SourceIp"),
                event.get("DestIp"),
                event.get("Protocol"),
                event.get("Port"),
                event.get("Message"),
                event.get("RawLine"),
                event.get("Severity", "LOW"),
                event.get("MitreIds"),
            ))
            conn.commit()
    finally:
        conn.close()

def query(sql, params=None):
    conn = get_connection()
    try:
        with conn.cursor() as c:
            c.execute(sql, params or ())
            return c.fetchall()
    finally:
        conn.close()
