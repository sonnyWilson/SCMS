"""
server/routes.py — Secure Continuous Monitoring System
All Flask route handlers.
"""

import secrets
import logging
import os
import subprocess
import signal
import csv
import io
import re
import ipaddress
import concurrent.futures
from datetime import datetime, timezone

from flask import (
    Flask, request, session, redirect, url_for,
    jsonify, render_template_string, make_response,
)

from config import API_KEY, DB_CONFIG
from server.auth import (
    attempt_login, generate_csrf_token, validate_csrf,
    login_required, api_login_required,
)
from server.security import check_rate_limit, get_csp_nonce, sanitize_str
import db
from server import parser as log_parser

log = logging.getLogger("scms.routes")

# ── Event-type colour palette (for sidebar chart) ─────────────────────────────
ETYPE_COLORS = {
    "AUTH":               "#f85149",
    "AUTH_FAIL":          "#e3a03a",
    "SUDO":               "#bc8cff",
    "SUSPICIOUS_COMMAND": "#f85149",
    "BASH_HISTORY":       "#79c0ff",
    "ICS_MODBUS":         "#0ea5e9",
    "ICS_DNP3":           "#00d4aa",
    "ICS_ENIP":           "#3fb950",
    "ICS_IEC104":         "#d29922",
    "ICS_BACnet":         "#e3a03a",
    "ICS_S7":             "#bc8cff",
    "SYS":                "#5a7080",
    "CRON":               "#5a7080",
    "PKG_MGMT":           "#79c0ff",
    "NET_CHANGE":         "#3fb950",
    "SYS_ERROR":          "#f85149",
    "NETWORK_ANOMALY":    "#e3a03a",
}


def _fmt_log(r):
    """
    Convert a Logs query row into the dict the dashboard JS expects.
    Column order: logid, EventTime, EventType, Success, UserName,
                  HostName, SourceIp, DestIp, Protocol, Port,
                  Message, Severity, MitreIds, SiteZone
    """
    sev = r[11] or "LOW"
    tl  = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(sev, 0)
    return {
        # ── fields the dashboard JS references directly ───────────────────────
        "logid":        r[0],
        "timestamp":    r[1].isoformat() if r[1] else None,
        "eventtype":    r[2]  or "SYS",
        "threat_level": tl,
        "threat_label": sev,
        "username":     r[4]  or "—",
        "hostname":     r[5]  or "—",
        "sourceip":     r[6]  or "—",
        "destip":       r[7]  or "—",
        "protocol":     r[8]  or "—",
        "port":         r[9],
        "message":      r[10] or "",
        "severity":     sev,
        "mitre_ids":    r[12] or "",
        "zone":         r[13] or "—",
        "rawline":      r[10] or "",
        # ── legacy aliases so nothing downstream breaks ───────────────────────
        "id":           r[0],
        "type":         r[2]  or "SYS",
        "host":         r[5]  or "—",
        "user":         r[4]  or "—",
        "source_ip":    r[6]  or "—",
        "dest_ip":      r[7]  or "—",
    }


# ── Route registration ────────────────────────────────────────────────────────
def register_routes(app: Flask):

    # ── Login (GET + POST) ────────────────────────────────────────────────────
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("logged_in"):
            return redirect(url_for("dashboard"))

        from server.login_html import LOGIN_HTML

        if request.method == "GET":
            token = generate_csrf_token()
            return render_template_string(
                LOGIN_HTML,
                csrf_token=token,
                error=None,
                username_prefill="",
            )

        # POST
        if not check_rate_limit():
            return render_template_string(
                LOGIN_HTML,
                csrf_token=generate_csrf_token(),
                error="Too many requests — please wait a minute and try again.",
                username_prefill="",
            ), 429

        submitted_token = request.form.get("_csrf_token", "")
        if not validate_csrf(submitted_token):
            log.warning("CSRF validation failed from %s", request.remote_addr)
            session.pop("csrf_token", None)
            return render_template_string(
                LOGIN_HTML,
                csrf_token=generate_csrf_token(),
                error="Security token mismatch — please try again.",
                username_prefill="",
            ), 403

        username = sanitize_str(request.form.get("username", ""), 64)
        password = request.form.get("password", "")

        ok_flag, result = attempt_login(username, password)
        if not ok_flag:
            return render_template_string(
                LOGIN_HTML,
                csrf_token=generate_csrf_token(),
                error=result,
                username_prefill=username,
            ), 401

        session.clear()
        session["logged_in"]  = True
        session["username"]   = username.lower().strip()
        session["role"]       = result
        session.permanent     = True
        session["csrf_token"] = secrets.token_hex(32)

        return redirect(url_for("dashboard"))

    # ── Logout ────────────────────────────────────────────────────────────────
    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ── Dashboard (protected) ─────────────────────────────────────────────────
    @app.route("/")
    @login_required
    def dashboard():
        from server.dashboard_html import DASHBOARD_HTML
        import config

        nonce = get_csp_nonce()

        mitre_map = {
            "AUTH":               [{"id": "T1110",    "name": "Brute Force",                "tactic": "Credential Access"}],
            "AUTH_FAIL":          [{"id": "T1110",    "name": "Brute Force",                "tactic": "Credential Access"},
                                   {"id": "T1110.001","name": "Password Guessing",          "tactic": "Credential Access"}],
            "SUDO":               [{"id": "T1548.003","name": "Sudo and Sudo Caching",      "tactic": "Privilege Escalation"}],
            "SUSPICIOUS_COMMAND": [{"id": "T1059.004","name": "Unix Shell",                 "tactic": "Execution"},
                                   {"id": "T0807",    "name": "Command-Line Interface",     "tactic": "Execution"}],
            "ICS_MODBUS":         [{"id": "T0836",    "name": "Modify Parameter",           "tactic": "Impair Process Control"},
                                   {"id": "T0855",    "name": "Unauthorized Command Message","tactic": "Impair Process Control"}],
            "ICS_DNP3":           [{"id": "T0855",    "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0831",    "name": "Manipulation of Control",    "tactic": "Impair Process Control"}],
            "ICS_ENIP":           [{"id": "T0855",    "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0836",    "name": "Modify Parameter",           "tactic": "Impair Process Control"}],
            "ICS_IEC104":         [{"id": "T0855",    "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0836",    "name": "Modify Parameter",           "tactic": "Impair Process Control"}],
            "NETWORK_ANOMALY":    [{"id": "T0846",    "name": "Remote System Discovery",    "tactic": "Discovery"},
                                   {"id": "T0888",    "name": "Remote System Information",  "tactic": "Discovery"}],
            "BASH_HISTORY":       [{"id": "T1552.003","name": "Bash History",               "tactic": "Credential Access"}],
        }

        return render_template_string(
            DASHBOARD_HTML,
            nonce=nonce,
            username=session.get("username", ""),
            role=session.get("role", ""),
            log_paths=config.TEXT_LOG_FILES,
            mitre_map=mitre_map,
            current_db=config.DB_CONFIG.get("database", "scms"),
        )

    # ── Log ingest (agent → server) ───────────────────────────────────────────
    @app.route("/ingest", methods=["POST"])
    def ingest():
        if not check_rate_limit():
            return jsonify({"error": "Rate limit exceeded"}), 429

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        if data.get("api_key") != API_KEY:
            log.warning("Invalid API key from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401

        message = sanitize_str(data.get("message", ""), 2000)
        if not message:
            return jsonify({"ok": True}), 200

        source_type = data.get("source_type", "SYS")
        event = log_parser.parse(message, source_type=source_type)
        if event:
            event["HostName"] = sanitize_str(data.get("host", ""), 100)
            try:
                db.insert(event)
            except Exception as e:
                log.error("DB insert failed: %s", e)
                return jsonify({"error": "DB error"}), 500

        return jsonify({"ok": True}), 200

    # ── /api/stats ────────────────────────────────────────────────────────────
    @app.route("/api/stats")
    @api_login_required
    def api_stats():
        try:
            total_logs = db.query("SELECT COUNT(*) FROM Logs")[0][0]
            failed     = db.query("SELECT COUNT(*) FROM Logs WHERE Success=0")[0][0]
            incidents  = db.query("SELECT COUNT(*) FROM Incidents")[0][0]
            open_inc   = db.query("SELECT COUNT(*) FROM Incidents WHERE Status='OPEN'")[0][0]
            packets    = db.query("SELECT COUNT(*) FROM Packets")[0][0]
            anomalies  = db.query("SELECT COUNT(*) FROM Packets WHERE Anomaly=TRUE")[0][0]

            # Extra sidebar counters
            brute_total      = db.query("SELECT COUNT(DISTINCT SourceIp) FROM Logs WHERE Success=0 AND SourceIp IS NOT NULL")[0][0]
            sudo_total       = db.query("SELECT COUNT(*) FROM Logs WHERE EventType='SUDO'")[0][0]
            suspicious_count = db.query("SELECT COUNT(*) FROM Logs WHERE EventType='SUSPICIOUS_COMMAND'")[0][0]
            auth_count       = db.query("SELECT COUNT(*) FROM Logs WHERE EventType IN ('AUTH','AUTH_FAIL')")[0][0]
            host_count       = db.query("SELECT COUNT(DISTINCT HostName) FROM Logs WHERE HostName IS NOT NULL")[0][0]
            unique_ips       = db.query("SELECT COUNT(DISTINCT SourceIp) FROM Logs WHERE SourceIp IS NOT NULL")[0][0]

            logs_rows = db.query("""
                SELECT logid, EventTime, EventType, Success, UserName,
                       HostName, SourceIp, DestIp, Protocol, Port,
                       Message, Severity, MitreIds, SiteZone
                FROM Logs ORDER BY EventTime DESC LIMIT 500
            """)
            logs = [_fmt_log(r) for r in logs_rows]

            top_ips_rows = db.query("""
                SELECT SourceIp, COUNT(*) as c FROM Logs
                WHERE Success=0 AND SourceIp IS NOT NULL
                GROUP BY SourceIp ORDER BY c DESC LIMIT 10
            """)
            top_ips = [[r[0], r[1]] for r in top_ips_rows]

            sudo_rows = db.query("""
                SELECT UserName, COUNT(*) as c FROM Logs
                WHERE EventType='SUDO' AND UserName IS NOT NULL
                GROUP BY UserName ORDER BY c DESC LIMIT 10
            """)
            sudo_users = [[r[0], r[1]] for r in sudo_rows]

            sev_rows = db.query("""
                SELECT Severity, COUNT(*) FROM Logs
                GROUP BY Severity ORDER BY COUNT(*) DESC
            """)
            severity_counts = {r[0]: r[1] for r in sev_rows}

            etype_rows = db.query("""
                SELECT EventType, COUNT(*) FROM Logs
                GROUP BY EventType ORDER BY COUNT(*) DESC LIMIT 15
            """)
            # Dashboard sidebar expects a list of {name, count, color}
            event_types = [
                {
                    "name":  r[0],
                    "count": r[1],
                    "color": ETYPE_COLORS.get(r[0], "#5a7080"),
                }
                for r in etype_rows
            ]

            return jsonify({
                "total_logs":       total_logs,
                "failed_logins":    failed,
                "brute_total":      brute_total,
                "sudo_total":       sudo_total,
                "suspicious_count": suspicious_count,
                "auth_count":       auth_count,
                "host_count":       host_count,
                "unique_ips":       unique_ips,
                "total_incidents":  incidents,
                "open_incidents":   open_inc,
                "total_packets":    packets,
                "anomaly_packets":  anomalies,
                "logs":             logs,
                "top_ips":          top_ips,
                "sudo_users":       sudo_users,
                "severity_counts":  severity_counts,
                "event_types":      event_types,
            }), 200
        except Exception as e:
            log.error("api_stats: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /api/top-ips ──────────────────────────────────────────────────────────
    @app.route("/api/top-ips")
    @api_login_required
    def api_top_ips():
        try:
            rows = db.query("""
                SELECT SourceIp, COUNT(*) as c FROM Logs
                WHERE Success=0 AND SourceIp IS NOT NULL
                GROUP BY SourceIp ORDER BY c DESC LIMIT 10
            """)
            return jsonify([[r[0], r[1]] for r in rows]), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/sudo-users ───────────────────────────────────────────────────────
    @app.route("/api/sudo-users")
    @api_login_required
    def api_sudo_users():
        try:
            rows = db.query("""
                SELECT UserName, COUNT(*) as c FROM Logs
                WHERE EventType='SUDO' AND UserName IS NOT NULL
                GROUP BY UserName ORDER BY c DESC LIMIT 10
            """)
            return jsonify([[r[0], r[1]] for r in rows]), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/fim ──────────────────────────────────────────────────────────────
    @app.route("/api/fim", methods=["POST"])
    @api_login_required
    def api_fim():
        try:
            from server.fim import fim_scan
            data  = request.get_json(silent=True) or {}
            paths = data.get("paths") or None
            return jsonify(fim_scan(paths)), 200
        except Exception as e:
            log.error("api_fim: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /api/sca ──────────────────────────────────────────────────────────────
    @app.route("/api/sca")
    @api_login_required
    def api_sca():
        try:
            from server.sca import run_sca
            return jsonify(run_sca()), 200
        except Exception as e:
            log.error("api_sca: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /api/vuln ─────────────────────────────────────────────────────────────
    @app.route("/api/vuln")
    @api_login_required
    def api_vuln():
        try:
            from server.vuln import vuln_scan
            return jsonify(vuln_scan()), 200
        except Exception as e:
            log.error("api_vuln: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /api/compliance ───────────────────────────────────────────────────────
    @app.route("/api/compliance", methods=["POST"])
    @api_login_required
    def api_compliance():
        try:
            from server.sca import run_sca, compute_compliance
            checks = run_sca()
            scores = compute_compliance(checks)
            return jsonify({"checks": checks, "scores": scores}), 200
        except Exception as e:
            log.error("api_compliance: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /api/block-ip ─────────────────────────────────────────────────────────
    @app.route("/api/block-ip", methods=["POST"])
    @api_login_required
    def api_block_ip():
        try:
            from server.response import block_ip
            data   = request.get_json(silent=True) or {}
            ip     = sanitize_str(data.get("ip", ""), 45)
            reason = sanitize_str(data.get("reason", "Manual"), 200)
            if not ip:
                return jsonify({"error": "ip required"}), 400
            ok_flag, msg = block_ip(ip, reason)
            return jsonify({"ok": ok_flag, "message": msg}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/unblock-ip ───────────────────────────────────────────────────────
    @app.route("/api/unblock-ip", methods=["POST"])
    @api_login_required
    def api_unblock_ip():
        try:
            from server.response import unblock_ip
            data = request.get_json(silent=True) or {}
            ip   = sanitize_str(data.get("ip", ""), 45)
            if not ip:
                return jsonify({"error": "ip required"}), 400
            ok_flag, msg = unblock_ip(ip)
            return jsonify({"ok": ok_flag, "message": msg}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/processes ────────────────────────────────────────────────────────
    @app.route("/api/processes")
    @api_login_required
    def api_processes():
        try:
            r = subprocess.run(
                ["ps", "aux", "--no-headers"],
                capture_output=True, text=True, timeout=5
            )
            procs = []
            for line in r.stdout.splitlines():
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        "user":    parts[0],
                        "pid":     int(parts[1]),
                        "cpu":     parts[2],
                        "mem":     parts[3],
                        "cmd":     parts[10][:80],
                        "command": parts[10][:80],
                    })
            return jsonify(procs), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/kill-process ─────────────────────────────────────────────────────
    @app.route("/api/kill-process", methods=["POST"])
    @api_login_required
    def api_kill_process():
        try:
            data = request.get_json(silent=True) or {}
            pid  = int(data.get("pid", 0))
            if pid <= 1:
                return jsonify({"error": "Invalid PID"}), 400
            os.kill(pid, signal.SIGTERM)
            log.warning("Process %d killed by %s", pid, session.get("username"))
            return jsonify({"ok": True}), 200
        except ProcessLookupError:
            return jsonify({"error": "Process not found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/inventory ────────────────────────────────────────────────────────
    @app.route("/api/inventory")
    @api_login_required
    def api_inventory():
        try:
            import platform
            rows = db.query("""
                SELECT devid, IpAddress, MacAddress, Hostname, Vendor,
                       DeviceType, OSInfo, Zone, Criticality, IsICS,
                       ICSProtocol, ThreatScore, LastSeen
                FROM Inventory ORDER BY ThreatScore DESC, LastSeen DESC
                LIMIT 200
            """)
            devices = [{
                "id":           r[0], "ip":          r[1], "mac":        r[2],
                "hostname":     r[3], "vendor":      r[4], "type":       r[5],
                "os":           r[6], "zone":        r[7], "criticality": r[8],
                "is_ics":       r[9], "ics_protocol": r[10],
                "threat_score": r[11],
                "last_seen":    r[12].isoformat() if r[12] else None,
            } for r in rows]
            import config as _cfg
            return jsonify({
                "hostname":  os.uname().nodename,
                "os":        platform.system() + " " + platform.release(),
                "platform":  platform.platform(),
                "python":    platform.python_version(),
                "log_paths": len(_cfg.TEXT_LOG_FILES),
                "db_host":   _cfg.DB_CONFIG.get("host","localhost"),
                "db_name":   _cfg.DB_CONFIG.get("database","scms"),
                "devices":   devices,
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/databases ────────────────────────────────────────────────────────
    @app.route("/api/databases")
    @api_login_required
    def api_databases():
        try:
            import psycopg2
            cfg = DB_CONFIG.copy(); cfg["database"] = "postgres"
            conn = psycopg2.connect(**cfg)
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT datname FROM pg_database
                    WHERE datistemplate = FALSE ORDER BY datname
                """)
                dbs = [r[0] for r in cur.fetchall()]
            conn.close()
            return jsonify(dbs), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/switch-db ────────────────────────────────────────────────────────
    @app.route("/api/switch-db", methods=["POST"])
    @api_login_required
    def api_switch_db():
        return jsonify({
            "success": False,
            "message": "Switch DB_NAME in .env and restart the server",
        }), 200

    # ── /api/create-db ────────────────────────────────────────────────────────
    @app.route("/api/create-db", methods=["POST"])
    @api_login_required
    def api_create_db():
        try:
            import psycopg2
            data = request.get_json(silent=True) or {}
            name = sanitize_str(data.get("name", ""), 64)
            if not name or not name.replace("_", "").replace("-", "").isalnum():
                return jsonify({"error": "Invalid database name"}), 400
            cfg = DB_CONFIG.copy(); cfg["database"] = "postgres"
            conn = psycopg2.connect(**cfg); conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(f'CREATE DATABASE "{name}"')
            conn.close()
            return jsonify({"ok": True, "message": f"Database '{name}' created"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/add-log-path / /api/remove-log-path ─────────────────────────────
    @app.route("/api/add-log-path", methods=["POST"])
    @api_login_required
    def api_add_log_path():
        data = request.get_json(silent=True) or {}
        path = sanitize_str(data.get("path", ""), 512)
        if not path:
            return jsonify({"error": "path required"}), 400
        import config
        if path not in config.TEXT_LOG_FILES:
            config.TEXT_LOG_FILES.append(path)
        return jsonify({"ok": True, "paths": config.TEXT_LOG_FILES}), 200

    @app.route("/api/remove-log-path", methods=["POST"])
    @api_login_required
    def api_remove_log_path():
        data = request.get_json(silent=True) or {}
        path = sanitize_str(data.get("path", ""), 512)
        import config
        config.TEXT_LOG_FILES = [p for p in config.TEXT_LOG_FILES if p != path]
        return jsonify({"ok": True, "paths": config.TEXT_LOG_FILES}), 200

    # ── /clear-logs ───────────────────────────────────────────────────────────
    @app.route("/clear-logs", methods=["POST"])
    @api_login_required
    def clear_logs():
        try:
            import psycopg2
            conn = psycopg2.connect(**DB_CONFIG)
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE Logs RESTART IDENTITY CASCADE")
            conn.commit(); conn.close()
            log.warning("All logs cleared by %s", session.get("username"))
            return jsonify({"status": "success"}), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # ── /import/csv ───────────────────────────────────────────────────────────
    @app.route("/import/csv", methods=["POST"])
    @api_login_required
    def import_csv():
        try:
            f = request.files.get("file")
            if not f:
                return jsonify({"error": "No file uploaded"}), 400
            text   = f.read().decode("utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            imported = 0
            for row in reader:
                event = {
                    "EventTime": row.get("EventTime") or datetime.now(timezone.utc).isoformat(),
                    "EventType": row.get("EventType", "SYS"),
                    "Success":   int(row.get("Success", 1)),
                    "UserName":  row.get("UserName"),
                    "HostName":  row.get("HostName"),
                    "SourceIp":  row.get("SourceIp"),
                    "Message":   row.get("Message", "")[:700],
                    "RawLine":   row.get("RawLine", "")[:700],
                    "Severity":  row.get("Severity", "LOW"),
                    "MitreIds":  row.get("MitreIds"),
                }
                db.insert(event)
                imported += 1
            return jsonify({"ok": True, "imported": imported}), 200
        except Exception as e:
            log.error("import_csv: %s", e)
            return jsonify({"error": str(e)}), 500

    # ── /export/csv ───────────────────────────────────────────────────────────
    @app.route("/export/csv")
    @api_login_required
    def export_csv():
        try:
            rows = db.query("""
                SELECT logid, EventTime, EventType, Success, UserName,
                       HostName, SourceIp, DestIp, Protocol, Port,
                       Message, Severity, MitreIds
                FROM Logs ORDER BY EventTime DESC LIMIT 10000
            """)
            out = io.StringIO()
            w   = csv.writer(out)
            w.writerow(["logid","EventTime","EventType","Success","UserName",
                        "HostName","SourceIp","DestIp","Protocol","Port",
                        "Message","Severity","MitreIds"])
            for r in rows:
                w.writerow([str(x) if x is not None else "" for x in r])
            resp = make_response(out.getvalue())
            resp.headers["Content-Type"]        = "text/csv"
            resp.headers["Content-Disposition"] = "attachment; filename=scms_logs.csv"
            return resp
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /health ───────────────────────────────────────────────────────────────
    @app.route("/health")
    def health():
        db_status = "unreachable"
        try:
            db.query("SELECT 1")
            db_status = "reachable"
        except Exception:
            pass
        return jsonify({"status": "ok", "service": "scms", "db": db_status}), 200

    # ── /api/capture/interfaces ───────────────────────────────────────────────
    @app.route("/api/capture/interfaces")
    @api_login_required
    def api_capture_interfaces():
        try:
            from server.capture import list_interfaces
            return jsonify({"interfaces": list_interfaces()}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/capture/start ────────────────────────────────────────────────────
    @app.route("/api/capture/start", methods=["POST"])
    @api_login_required
    def api_capture_start():
        try:
            from server.capture import start_capture
            data  = request.get_json(silent=True) or {}
            iface = sanitize_str(data.get("interface", "eth0"), 32)
            ok, msg = start_capture(iface)
            return jsonify({"ok": ok, "message": msg}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/capture/stop ─────────────────────────────────────────────────────
    @app.route("/api/capture/stop", methods=["POST"])
    @api_login_required
    def api_capture_stop():
        try:
            from server.capture import stop_capture
            ok, msg = stop_capture()
            return jsonify({"ok": ok, "message": msg}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/capture/stats ────────────────────────────────────────────────────
    @app.route("/api/capture/stats")
    @api_login_required
    def api_capture_stats():
        try:
            from server.capture import get_stats
            return jsonify(get_stats()), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/packets ─────────────────────────────────────────────────────────
    @app.route("/api/packets")
    @api_login_required
    def api_packets():
        try:
            rows = db.query("""
                SELECT pktid, CaptureTime, SrcIp, DstIp, SrcPort, DstPort,
                       Protocol, Length, TTL, Flags, Interface,
                       ICSProtocol, ICSFunctionCode, ICSFunctionName,
                       ICSAddress, ICSValue, Anomaly, AnomalyReason,
                       GeoCountry, GeoCity, ThreatScore
                FROM Packets ORDER BY CaptureTime DESC LIMIT 500
            """)
            pkts = [{
                "id": r[0], "time": r[1].isoformat() if r[1] else None,
                "src_ip": r[2], "dst_ip": r[3], "src_port": r[4], "dst_port": r[5],
                "proto": r[6], "len": r[7], "ttl": r[8], "flags": r[9], "iface": r[10],
                "ics_proto": r[11], "ics_fc": r[12], "ics_fn": r[13],
                "ics_addr": r[14], "ics_val": r[15],
                "anomaly": r[16], "anomaly_reason": r[17],
                "geo_country": r[18], "geo_city": r[19], "threat": r[20],
            } for r in rows]
            return jsonify(pkts), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/network/scan ─────────────────────────────────────────────────────
    @app.route("/api/network/scan", methods=["POST"])
    @api_login_required
    def api_network_scan():
        try:
            data   = request.get_json(silent=True) or {}
            target = sanitize_str(data.get("target", ""), 64)
            if not target:
                return jsonify({"error": "target required"}), 400
            if not re.match(r'^[\d./]+$', target):
                return jsonify({"error": "Invalid target"}), 400
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--open", "-oG", "-", target],
                capture_output=True, text=True, timeout=60
            )
            hosts = []
            for line in result.stdout.splitlines():
                if "Host:" in line and "Status: Up" in line:
                    parts = line.split()
                    ip       = parts[1] if len(parts) > 1 else ""
                    hostname = parts[2].strip("()") if len(parts) > 2 else ""
                    hosts.append({"ip": ip, "hostname": hostname, "status": "up"})
            return jsonify({"hosts": hosts, "target": target, "count": len(hosts)}), 200
        except FileNotFoundError:
            # nmap not installed — threaded ping sweep fallback
            try:
                net = ipaddress.ip_network(target, strict=False)
                ips = [str(h) for h in net.hosts()][:254]
            except Exception:
                ips = [target]
            def _ping(ip):
                r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                   capture_output=True, timeout=3)
                return {"ip": ip, "hostname": "", "status": "up"} if r.returncode == 0 else None
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
                results = list(ex.map(_ping, ips))
            hosts = [h for h in results if h]
            return jsonify({"hosts": hosts, "target": target, "count": len(hosts)}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/network/portscan ─────────────────────────────────────────────────
    @app.route("/api/network/portscan", methods=["POST"])
    @api_login_required
    def api_network_portscan():
        try:
            data   = request.get_json(silent=True) or {}
            target = sanitize_str(data.get("target", ""), 64)
            ports  = sanitize_str(data.get("ports", "1-1024"), 32)
            if not target or not re.match(r'^[\d./]+$', target):
                return jsonify({"error": "Invalid target"}), 400
            result = subprocess.run(
                ["nmap", "-sV", "-T4", "-p", ports, "-oG", "-", target],
                capture_output=True, text=True, timeout=120
            )
            open_ports = []
            for line in result.stdout.splitlines():
                if "Ports:" in line:
                    for entry in line.split("Ports:")[-1].split(","):
                        entry = entry.strip()
                        if "open" in entry:
                            parts = entry.split("/")
                            if len(parts) >= 5:
                                open_ports.append({
                                    "port":    parts[0],
                                    "state":   parts[1],
                                    "proto":   parts[2],
                                    "service": parts[4],
                                    "version": parts[6] if len(parts) > 6 else "",
                                })
            return jsonify({"target": target, "ports": open_ports}), 200
        except FileNotFoundError:
            return jsonify({"error": "nmap not installed. Run: sudo apt install nmap"}), 503
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/ics/events ───────────────────────────────────────────────────────
    @app.route("/api/ics/events")
    @api_login_required
    def api_ics_events():
        try:
            rows = db.query("""
                SELECT logid, EventTime, EventType, SourceIp, DestIp,
                       Protocol, Port, Message, Severity, MitreIds
                FROM Logs
                WHERE EventType IN
                  ('ICS_MODBUS','ICS_DNP3','ICS_ENIP','ICS_IEC104',
                   'ICS_BACnet','ICS_S7','ICS_PROFINET')
                ORDER BY EventTime DESC LIMIT 500
            """)
            events = [{
                "id": r[0], "time": r[1].isoformat() if r[1] else None,
                "type": r[2], "src_ip": r[3], "dst_ip": r[4],
                "proto": r[5], "port": r[6], "message": r[7],
                "severity": r[8], "mitre": r[9],
            } for r in rows]
            return jsonify(events), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/ics/packets ──────────────────────────────────────────────────────
    @app.route("/api/ics/packets")
    @api_login_required
    def api_ics_packets():
        try:
            rows = db.query("""
                SELECT pktid, CaptureTime, SrcIp, DstIp, SrcPort, DstPort,
                       ICSProtocol, ICSFunctionCode, ICSFunctionName,
                       ICSAddress, ICSValue, ThreatScore, Anomaly, AnomalyReason
                FROM Packets
                WHERE ICSProtocol IS NOT NULL
                ORDER BY CaptureTime DESC LIMIT 500
            """)
            pkts = [{
                "id": r[0], "time": r[1].isoformat() if r[1] else None,
                "src_ip": r[2], "dst_ip": r[3], "src_port": r[4], "dst_port": r[5],
                "proto": r[6], "fc": r[7], "fn": r[8],
                "addr": r[9], "val": r[10], "threat": r[11],
                "anomaly": r[12], "reason": r[13],
            } for r in rows]
            return jsonify(pkts), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/ics/sis-rules ────────────────────────────────────────────────────
    @app.route("/api/ics/sis-rules")
    @api_login_required
    def api_ics_sis_rules():
        try:
            from server.sis import get_all_rules
            return jsonify(get_all_rules()), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/ics/sis-events ───────────────────────────────────────────────────
    @app.route("/api/ics/sis-events")
    @api_login_required
    def api_ics_sis_events():
        try:
            rows = db.query("""
                SELECT sisid, EventTime, RuleId, RuleName, Severity,
                       TriggerProtocol, TriggerFunction, TriggerAddress,
                       TriggerValue, SrcIp, DstIp, AffectedZone, Action
                FROM SIS_Events ORDER BY EventTime DESC LIMIT 200
            """)
            events = [{
                "id": r[0], "time": r[1].isoformat() if r[1] else None,
                "rule_id": r[2], "rule_name": r[3], "severity": r[4],
                "proto": r[5], "fn": r[6], "addr": r[7], "val": r[8],
                "src_ip": r[9], "dst_ip": r[10], "zone": r[11], "action": r[12],
            } for r in rows]
            return jsonify(events), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/ics/risk-assessment ──────────────────────────────────────────────
    @app.route("/api/ics/risk-assessment")
    @api_login_required
    def api_ics_risk_assessment():
        try:
            sis_events   = db.query("SELECT COUNT(*) FROM SIS_Events")[0][0]
            ics_logs     = db.query("""
                SELECT COUNT(*) FROM Logs
                WHERE EventType IN ('ICS_MODBUS','ICS_DNP3','ICS_ENIP','ICS_IEC104')
            """)[0][0]
            crit_sis     = db.query("SELECT COUNT(*) FROM SIS_Events WHERE Severity='CRITICAL'")[0][0]
            anomaly_pkts = db.query("SELECT COUNT(*) FROM Packets WHERE Anomaly=TRUE AND ICSProtocol IS NOT NULL")[0][0]
            ext_ics      = db.query("""
                SELECT COUNT(*) FROM Packets
                WHERE ICSProtocol IS NOT NULL
                  AND SrcIp NOT LIKE '192.168.%'
                  AND SrcIp NOT LIKE '10.%'
                  AND SrcIp NOT LIKE '172.%'
            """)[0][0]

            def _score(val, thresholds):
                for t, s in thresholds:
                    if val >= t: return s
                return 100

            availability = _score(sis_events,   [(10,20),(5,50),(1,75),(0,100)])
            integrity    = _score(crit_sis,      [(5,10),(2,40),(1,70),(0,100)])
            confidential = _score(ext_ics,       [(20,20),(10,50),(1,75),(0,100)])
            auth_score   = _score(anomaly_pkts,  [(50,20),(20,50),(5,75),(0,100)])
            overall      = round((availability + integrity + confidential + auth_score) / 4)
            risk_level   = ("CRITICAL" if overall < 40 else
                            "HIGH"     if overall < 60 else
                            "MEDIUM"   if overall < 80 else "LOW")

            return jsonify({
                "overall":    overall,
                "risk_level": risk_level,
                "domains": {
                    "Availability":    availability,
                    "Integrity":       integrity,
                    "Confidentiality": confidential,
                    "Authentication":  auth_score,
                },
                "counts": {
                    "sis_events":     sis_events,
                    "ics_logs":       ics_logs,
                    "critical_sis":   crit_sis,
                    "anomaly_packets":anomaly_pkts,
                    "external_ics":   ext_ics,
                },
                "standards": [
                    "IEC 62443-3-3", "NIST SP 800-82 Rev 3",
                    "NERC CIP-005",  "NERC CIP-007", "IEC 60870-5",
                ],
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/assets ───────────────────────────────────────────────────────────
    @app.route("/api/assets")
    @api_login_required
    def api_assets():
        try:
            rows = db.query("""
                SELECT devid, IpAddress, MacAddress, Hostname, Vendor,
                       DeviceType, OSInfo, Zone, Criticality, IsICS,
                       ICSProtocol, ThreatScore, LastSeen, Notes
                FROM Inventory ORDER BY ThreatScore DESC, LastSeen DESC LIMIT 500
            """)
            assets = [{
                "id": r[0], "ip": r[1], "mac": r[2], "hostname": r[3],
                "vendor": r[4], "type": r[5], "os": r[6], "zone": r[7],
                "criticality": r[8], "is_ics": r[9], "ics_proto": r[10],
                "threat_score": r[11],
                "last_seen": r[12].isoformat() if r[12] else None,
                "notes": r[13],
            } for r in rows]
            return jsonify(assets), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/assets/update ────────────────────────────────────────────────────
    @app.route("/api/assets/update", methods=["POST"])
    @api_login_required
    def api_assets_update():
        try:
            import psycopg2
            data  = request.get_json(silent=True) or {}
            devid = int(data.get("id", 0))
            notes = sanitize_str(data.get("notes", ""), 500)
            crit  = sanitize_str(data.get("criticality", "MEDIUM"), 20)
            zone  = sanitize_str(data.get("zone", ""), 100)
            conn  = psycopg2.connect(**DB_CONFIG)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE Inventory SET Notes=%s, Criticality=%s, Zone=%s WHERE devid=%s",
                    (notes, crit, zone, devid)
                )
            conn.commit(); conn.close()
            return jsonify({"ok": True}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/honeypot/events ──────────────────────────────────────────────────
    @app.route("/api/honeypot/events")
    @api_login_required
    def api_honeypot_events():
        try:
            rows = db.query("""
                SELECT logid, EventTime, EventType, SourceIp, DestIp,
                       Protocol, Port, Message, Severity, HostName
                FROM Logs
                WHERE HostName LIKE '%honeypot%'
                   OR Message ILIKE '%honeypot%'
                   OR Message ILIKE '%conpot%'
                   OR Port IN (102, 502, 20000, 44818, 47808)
                ORDER BY EventTime DESC LIMIT 500
            """)
            events = [{
                "id": r[0], "time": r[1].isoformat() if r[1] else None,
                "type": r[2], "src_ip": r[3], "dst_ip": r[4],
                "proto": r[5], "port": r[6], "message": r[7],
                "severity": r[8], "host": r[9],
            } for r in rows]
            return jsonify(events), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/honeypot/stats ───────────────────────────────────────────────────
    @app.route("/api/honeypot/stats")
    @api_login_required
    def api_honeypot_stats():
        try:
            total = db.query("""
                SELECT COUNT(*) FROM Logs
                WHERE HostName LIKE '%honeypot%' OR Message ILIKE '%honeypot%'
                   OR Message ILIKE '%conpot%' OR Port IN (102,502,20000,44818,47808)
            """)[0][0]
            top_ips    = db.query("""
                SELECT SourceIp, COUNT(*) FROM Logs
                WHERE Port IN (102,502,20000,44818,47808) AND SourceIp IS NOT NULL
                GROUP BY SourceIp ORDER BY COUNT(*) DESC LIMIT 10
            """)
            proto_hits = db.query("""
                SELECT Port, COUNT(*) FROM Logs
                WHERE Port IN (102,502,20000,44818,47808)
                GROUP BY Port ORDER BY COUNT(*) DESC
            """)
            PORT_NAMES = {
                102: "S7/IEC104", 502: "Modbus",
                20000: "DNP3",    44818: "EtherNet/IP", 47808: "BACnet",
            }
            return jsonify({
                "total":       total,
                "top_ips":     [[r[0], r[1]] for r in top_ips],
                "proto_hits":  [[PORT_NAMES.get(r[0], str(r[0])), r[1]] for r in proto_hits],
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
