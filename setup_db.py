"""
setup_db.py — Secure Continuous Monitoring System
Expanded schema: Logs, Packets, Incidents, Inventory, SIS_Events, GeoEvents, scms_users
"""
import psycopg2, sys
from config import DB_CONFIG

def create_database():
    cfg = DB_CONFIG.copy(); cfg['database'] = 'postgres'
    try:
        conn = psycopg2.connect(**cfg); conn.autocommit = True; cur = conn.cursor()
        db_name = DB_CONFIG.get('database', 'scms')
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s",(db_name,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{db_name}"')
            print(f"  Created database '{db_name}'.")
        else:
            print(f"  Database '{db_name}' exists.")
        cur.close(); conn.close(); return True
    except Exception as e: print(f"DB create error: {e}"); return False

def create_tables():
    try:
        conn = psycopg2.connect(**DB_CONFIG); cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS Logs (
            logid        SERIAL PRIMARY KEY,
            EventTime    TIMESTAMPTZ DEFAULT NOW(),
            EventType    VARCHAR(80), Success INTEGER DEFAULT 1,
            UserName     TEXT, HostName VARCHAR(100),
            SourceIp     TEXT, DestIp TEXT,
            Protocol     VARCHAR(20), Port INTEGER,
            Message      TEXT, RawLine TEXT,
            Severity     VARCHAR(20) DEFAULT 'LOW',
            MitreIds     TEXT, PacketRef INTEGER, IncidentRef INTEGER,
            SiteZone     VARCHAR(80), DeviceId INTEGER
        );
        CREATE TABLE IF NOT EXISTS Packets (
            pktid           SERIAL PRIMARY KEY,
            CaptureTime     TIMESTAMPTZ DEFAULT NOW(),
            Interface       VARCHAR(30),
            SrcIp           TEXT, DstIp TEXT,
            SrcPort         INTEGER, DstPort INTEGER,
            Protocol        VARCHAR(30), Length INTEGER,
            TTL             INTEGER, Flags VARCHAR(20),
            Payload         TEXT, PayloadHex TEXT,
            ICSProtocol     VARCHAR(30),
            ICSFunctionCode INTEGER, ICSFunctionName VARCHAR(80),
            ICSAddress      INTEGER, ICSValue TEXT,
            RawHex          TEXT,
            Anomaly         BOOLEAN DEFAULT FALSE, AnomalyReason TEXT,
            GeoCountry      VARCHAR(60), GeoCity VARCHAR(80),
            GeoLat          DOUBLE PRECISION, GeoLon DOUBLE PRECISION,
            ThreatScore     INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS Incidents (
            incid           SERIAL PRIMARY KEY,
            CreatedAt       TIMESTAMPTZ DEFAULT NOW(),
            UpdatedAt       TIMESTAMPTZ DEFAULT NOW(),
            Title           TEXT NOT NULL,
            Severity        VARCHAR(20) DEFAULT 'MEDIUM',
            Status          VARCHAR(30) DEFAULT 'OPEN',
            Category        VARCHAR(60), Description TEXT,
            AffectedHost    VARCHAR(100), AffectedIp TEXT,
            AffectedZone    VARCHAR(80), AffectedDevice INTEGER,
            AttackVector    TEXT, MitreIds TEXT,
            Iocs            TEXT, PacketIds TEXT, LogIds TEXT,
            SisTripped      BOOLEAN DEFAULT FALSE, SisActions TEXT,
            ViolationsJson  TEXT, TimelineJson TEXT,
            RemediationSteps TEXT, AssignedTo VARCHAR(64),
            ResolvedAt      TIMESTAMPTZ, Notes TEXT, SystemInfo TEXT,
            GeoLat DOUBLE PRECISION, GeoLon DOUBLE PRECISION,
            GeoCountry VARCHAR(60), GeoCity VARCHAR(80)
        );
        CREATE TABLE IF NOT EXISTS Inventory (
            devid       SERIAL PRIMARY KEY,
            FirstSeen   TIMESTAMPTZ DEFAULT NOW(),
            LastSeen    TIMESTAMPTZ DEFAULT NOW(),
            IpAddress   TEXT UNIQUE NOT NULL,
            MacAddress  VARCHAR(30), Hostname VARCHAR(100),
            Vendor      VARCHAR(100), DeviceType VARCHAR(60),
            OSInfo      VARCHAR(100), Firmware VARCHAR(100),
            OpenPorts   TEXT, Protocols TEXT,
            Zone        VARCHAR(80), Role VARCHAR(60),
            Criticality VARCHAR(20) DEFAULT 'MEDIUM',
            IsICS       BOOLEAN DEFAULT FALSE,
            ICSProtocol VARCHAR(30), PLCModel VARCHAR(100),
            Location    VARCHAR(100), Notes TEXT,
            IsHoneypot  BOOLEAN DEFAULT FALSE,
            ThreatScore INTEGER DEFAULT 0,
            GeoLat DOUBLE PRECISION, GeoLon DOUBLE PRECISION, GeoCountry VARCHAR(60)
        );
        CREATE TABLE IF NOT EXISTS SIS_Events (
            sisid           SERIAL PRIMARY KEY,
            EventTime       TIMESTAMPTZ DEFAULT NOW(),
            RuleId          VARCHAR(60), RuleName TEXT,
            Severity        VARCHAR(20) DEFAULT 'CRITICAL',
            TriggerProtocol VARCHAR(30), TriggerFunction VARCHAR(80),
            TriggerAddress  INTEGER, TriggerValue TEXT,
            SrcIp TEXT, DstIp TEXT,
            AffectedDevice  VARCHAR(100), AffectedZone VARCHAR(80),
            Action TEXT, ActionTaken BOOLEAN DEFAULT FALSE,
            PacketRef INTEGER, IncidentRef INTEGER,
            Acknowledged BOOLEAN DEFAULT FALSE,
            AckBy VARCHAR(64), AckTime TIMESTAMPTZ, Notes TEXT
        );
        CREATE TABLE IF NOT EXISTS GeoEvents (
            geoid       SERIAL PRIMARY KEY,
            EventTime   TIMESTAMPTZ DEFAULT NOW(),
            SrcIp TEXT, GeoLat DOUBLE PRECISION, GeoLon DOUBLE PRECISION,
            GeoCountry VARCHAR(60), GeoCity VARCHAR(80), GeoISP VARCHAR(100),
            ThreatScore INTEGER DEFAULT 0, EventType VARCHAR(60),
            PacketRef INTEGER, LogRef INTEGER
        );
        CREATE TABLE IF NOT EXISTS scms_users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(64) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          VARCHAR(20) DEFAULT 'analyst',
            created_at    TIMESTAMPTZ DEFAULT NOW(),
            last_login    TIMESTAMPTZ, active BOOLEAN DEFAULT TRUE
        );
        """)

        for idx in [
            "CREATE INDEX IF NOT EXISTS idx_logs_time   ON Logs(EventTime DESC)",
            "CREATE INDEX IF NOT EXISTS idx_logs_type   ON Logs(EventType)",
            "CREATE INDEX IF NOT EXISTS idx_logs_srcip  ON Logs(SourceIp)",
            "CREATE INDEX IF NOT EXISTS idx_logs_sev    ON Logs(Severity)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_time   ON Packets(CaptureTime DESC)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_srcip  ON Packets(SrcIp)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_dstip  ON Packets(DstIp)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_proto  ON Packets(Protocol)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_ics    ON Packets(ICSProtocol)",
            "CREATE INDEX IF NOT EXISTS idx_pkts_anom   ON Packets(Anomaly)",
            "CREATE INDEX IF NOT EXISTS idx_inc_time    ON Incidents(CreatedAt DESC)",
            "CREATE INDEX IF NOT EXISTS idx_inc_sev     ON Incidents(Severity)",
            "CREATE INDEX IF NOT EXISTS idx_inc_status  ON Incidents(Status)",
            "CREATE INDEX IF NOT EXISTS idx_inv_ip      ON Inventory(IpAddress)",
            "CREATE INDEX IF NOT EXISTS idx_inv_zone    ON Inventory(Zone)",
            "CREATE INDEX IF NOT EXISTS idx_sis_time    ON SIS_Events(EventTime DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sis_ack     ON SIS_Events(Acknowledged)",
            "CREATE INDEX IF NOT EXISTS idx_geo_time    ON GeoEvents(EventTime DESC)",
            "CREATE INDEX IF NOT EXISTS idx_geo_country ON GeoEvents(GeoCountry)",
        ]: cur.execute(idx)

        conn.commit(); cur.close(); conn.close()
        print("  All tables and indexes ready."); return True
    except Exception as e: print(f"Table error: {e}"); return False

if __name__ == "__main__":
    print("Secure Continuous Monitoring System — Database Setup")
    ok = create_database() and create_tables()
    if ok: print("\nSetup complete.")
    else: print("\nFailed — check PostgreSQL and credentials.\nTry: sudo -u postgres python3 setup_db.py")
