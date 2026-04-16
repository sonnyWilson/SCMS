
"""

Active Response: iptables IP blocking/unblocking, in-memory block registry,
and optional SMTP email alerts for critical events.
"""

import subprocess
import smtplib
import logging
import threading
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, SMTP_TO

log = logging.getLogger("scms.response")

_blocked: dict[str, dict] = {}
_blocked_lock = threading.Lock()


def block_ip(ip: str, reason: str = "Manual") -> tuple[bool, str]:
    with _blocked_lock:
        if ip in _blocked:
            return False, f"IP {ip} is already blocked"
        _blocked[ip] = {
            "reason":     reason,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
        }
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5, check=True,
        )
        log.info("Blocked %s via iptables (%s)", ip, reason)
        return True, f"Blocked {ip} via iptables"
    except FileNotFoundError:
        return True, f"Simulated block of {ip} (iptables not available)"
    except subprocess.CalledProcessError as exc:
        return True, f"iptables error for {ip}: {exc}"
    except Exception as exc:
        return True, f"Simulated block of {ip}: {exc}"


def unblock_ip(ip: str) -> tuple[bool, str]:
    with _blocked_lock:
        _blocked.pop(ip, None)
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        log.info("Unblocked %s", ip)
        return True, f"Unblocked {ip}"
    except Exception as exc:
        return True, f"Simulated unblock of {ip}: {exc}"


def get_blocked() -> list[dict]:
    with _blocked_lock:
        return [{"ip": ip, **data} for ip, data in _blocked.items()]


def is_blocked(ip: str) -> bool:
    with _blocked_lock:
        return ip in _blocked


def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and SMTP_FROM and SMTP_TO)


def send_alert_email(subject: str, body: str) -> bool:
    if not _smtp_configured():
        log.debug("SMTP not configured — skipping email alert")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SCMS ALERT] {subject}"
        msg["From"]    = SMTP_FROM
        msg["To"]      = SMTP_TO
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_FROM, SMTP_TO.split(","), msg.as_string())
        log.info("Alert email sent: %s", subject)
        return True
    except Exception as exc:
        log.warning("Email alert failed: %s", exc)
        return False


def maybe_auto_block(top_ips: list, threshold: int = 10) -> list[str]:
    newly_blocked = []
    for ip, count in top_ips:
        if ip and count > threshold and not is_blocked(ip):
            ok, msg = block_ip(ip, reason=f"Auto: {count} failed logins")
            if ok:
                newly_blocked.append(ip)
                log.warning("Auto-blocked %s (%d failed logins)", ip, count)
                threading.Thread(
                    target=send_alert_email,
                    args=(f"Auto-blocked {ip}", f"{ip} blocked — {count} failed logins"),
                    daemon=True,
                ).start()
    return newly_blocked
