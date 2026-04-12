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
import parser as log_parser

log = logging.getLogger("scms.routes")


# ── Route registration ────────────────────────────────────────────────────────
def register_routes(app: Flask):

    # ── Health check (no auth) ────────────────────────────────────────────────
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "scms"}), 200

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

        # CSRF — login_html.py uses field name "_csrf_token"
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
        session["logged_in"] = True
        session["username"]  = username.lower().strip()
        session["role"]      = result
        session.permanent    = True
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

        # MITRE ATT&CK technique map keyed by EventType
        mitre_map = {
            "AUTH":               [{"id": "T1110",   "name": "Brute Force",               "tactic": "Credential Access"}],
            "AUTH_FAIL":          [{"id": "T1110",   "name": "Brute Force",               "tactic": "Credential Access"},
                                   {"id": "T1110.001","name": "Password Guessing",         "tactic": "Credential Access"}],
            "SUDO":               [{"id": "T1548.003","name": "Sudo and Sudo Caching",     "tactic": "Privilege Escalation"}],
            "SUSPICIOUS_COMMAND": [{"id": "T1059.004","name": "Unix Shell",                "tactic": "Execution"},
                                   {"id": "T0807",    "name": "Command-Line Interface",    "tactic": "Execution"}],
            "ICS_MODBUS":         [{"id": "T0836",   "name": "Modify Parameter",          "tactic": "Impair Process Control"},
                                   {"id": "T0855",   "name": "Unauthorized Command Message","tactic": "Impair Process Control"}],
            "ICS_DNP3":           [{"id": "T0855",   "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0831",   "name": "Manipulation of Control",   "tactic": "Impair Process Control"}],
            "ICS_ENIP":           [{"id": "T0855",   "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0836",   "name": "Modify Parameter",          "tactic": "Impair Process Control"}],
            "ICS_IEC104":         [{"id": "T0855",   "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
                                   {"id": "T0836",   "name": "Modify Parameter",          "tactic": "Impair Process Control"}],
            "NETWORK_ANOMALY":    [{"id": "T0846",   "name": "Remote System Discovery",   "tactic": "Discovery"},
                                   {"id": "T0888",   "name": "Remote System Information", "tactic": "Discovery"}],
            "BASH_HISTORY":       [{"id": "T1552.003","name": "Bash History",              "tactic": "Credential Access"}],
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

    # ── /api/stats — main polling endpoint used by dashboard ─────────────────
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
            event_types = {r[0]: r[1] for r in etype_rows}

            return jsonify({
                "total_logs":       total_logs,
                "failed_logins":    failed,
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

    def _fmt_log(r):
        return {
            "id":          r[0],
            "timestamp":   r[1].isoformat() if r[1] else None,
            "type":        r[2],
            "threat_level": 0 if r[3] == 1 else 1,
            "user":        r[4],
            "host":        r[5],
            "source_ip":   r[6],
            "dest_ip":     r[7],
            "protocol":    r[8],
            "port":        r[9],
            "message":     r[10],
            "severity":    r[11],
            "mitre_ids":   r[12],
            "zone":        r[13],
        }

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
            rows = db.query("""
                SELECT devid, IpAddress, MacAddress, Hostname, Vendor,
                       DeviceType, OSInfo, Zone, Criticality, IsICS,
                       ICSProtocol, ThreatScore, LastSeen
                FROM Inventory ORDER BY ThreatScore DESC, LastSeen DESC
                LIMIT 200
            """)
            devices = [{
                "id":          r[0], "ip":         r[1], "mac":       r[2],
                "hostname":    r[3], "vendor":     r[4], "type":      r[5],
                "os":          r[6], "zone":       r[7], "criticality": r[8],
                "is_ics":      r[9], "ics_protocol": r[10],
                "threat_score": r[11],
                "last_seen":   r[12].isoformat() if r[12] else None,
            } for r in rows]
            return jsonify(devices), 200
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
            return jsonify({"databases": dbs, "current": DB_CONFIG["database"]}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── /api/switch-db ────────────────────────────────────────────────────────
    @app.route("/api/switch-db", methods=["POST"])
    @api_login_required
    def api_switch_db():
        # Runtime DB switching is not supported — inform the dashboard gracefully
        return jsonify({"success": False,
                        "message": "Switch DB_NAME in .env and restart the server"}), 200

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
            return jsonify({"ok": True}), 200
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
        # Append to running config in-memory (agent reads TEXT_LOG_FILES at startup)
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
            text    = f.read().decode("utf-8", errors="replace")
            reader  = csv.DictReader(io.StringIO(text))
            imported = 0
            for row in reader:
                event = {
                    "EventTime":  row.get("EventTime") or datetime.now(timezone.utc).isoformat(),
                    "EventType":  row.get("EventType", "SYS"),
                    "Success":    int(row.get("Success", 1)),
                    "UserName":   row.get("UserName"),
                    "HostName":   row.get("HostName"),
                    "SourceIp":   row.get("SourceIp"),
                    "Message":    row.get("Message", "")[:700],
                    "RawLine":    row.get("RawLine", "")[:700],
                    "Severity":   row.get("Severity", "LOW"),
                    "MitreIds":   row.get("MitreIds"),
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
