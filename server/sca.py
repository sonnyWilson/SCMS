"""
Security Configuration Assessment — 32 CIS Benchmark checks
covering authentication, filesystem, network, auditing, and ICS hardening.
"""

import os
import re
import subprocess
import logging
from pathlib import Path

log = logging.getLogger("scms.sca")


def _run(cmd: str) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception:
        return 1, ""


def _file_contains(path: str, pattern: str) -> bool:
    try:
        return bool(re.search(pattern, Path(path).read_text(), re.IGNORECASE | re.MULTILINE))
    except Exception:
        return False


def _file_exists(path: str) -> bool:
    return Path(path).exists()


def _file_mode(path: str, expected_max: int) -> bool:
    """Return True if file permissions are <= expected_max (octal)."""
    try:
        mode = oct(os.stat(path).st_mode & 0o777)
        return int(mode, 8) <= expected_max
    except Exception:
        return False


def run_sca() -> list[dict]:
    checks = []

    def chk(cid, title, passed, severity, tags, detail=""):
        checks.append({
            "id":       cid,
            "title":    title,
            "status":   "PASS" if passed else "FAIL",
            "severity": severity,
            "tags":     tags,
            "detail":   detail,
        })

    # ── 1. Authentication ──────────────────────────────────────────
    chk("CIS-1.1", "Password minimum length ≥ 12",
        _file_contains("/etc/security/pwquality.conf", r"minlen\s*=\s*(1[2-9]|[2-9]\d)") or
        _file_contains("/etc/pam.d/common-password", r"minlen=1[2-9]"),
        "HIGH", "PCI-DSS,NIST,HIPAA")

    chk("CIS-1.2", "Password complexity enforced (pam_pwquality)",
        _file_contains("/etc/pam.d/common-password", r"pam_pwquality"),
        "MEDIUM", "PCI-DSS,NIST")

    chk("CIS-1.3", "Root login over SSH disabled",
        _file_contains("/etc/ssh/sshd_config", r"PermitRootLogin\s+(no|prohibit-password)"),
        "CRITICAL", "PCI-DSS,NIST,HIPAA,IEC62443")

    chk("CIS-1.4", "SSH password authentication disabled",
        _file_contains("/etc/ssh/sshd_config", r"PasswordAuthentication\s+no"),
        "HIGH", "PCI-DSS,NIST,IEC62443")

    chk("CIS-1.5", "SSH max auth tries ≤ 4",
        _file_contains("/etc/ssh/sshd_config", r"MaxAuthTries\s+[1-4]\b"),
        "MEDIUM", "PCI-DSS,NIST")

    chk("CIS-1.6", "SSH idle timeout configured (ClientAliveInterval)",
        _file_contains("/etc/ssh/sshd_config", r"ClientAliveInterval\s+[1-9]\d*"),
        "MEDIUM", "NIST,HIPAA")

    chk("CIS-1.7", "Root account locked (no direct login)",
        _run("passwd -S root")[1].startswith("root L") or
        _file_contains("/etc/passwd", r"^root:[*!x]"),
        "HIGH", "PCI-DSS,NIST,IEC62443")

    chk("CIS-1.8", "Account lockout configured (pam_faillock/tally2)",
        _file_contains("/etc/pam.d/common-auth", r"pam_faillock|pam_tally2"),
        "HIGH", "PCI-DSS,NIST,HIPAA")

    # ── 2. Filesystem ──────────────────────────────────────────────
    chk("CIS-2.1", "/etc/passwd permissions 644 or stricter",
        _file_mode("/etc/passwd", 0o644),
        "HIGH", "CIS,NIST")

    chk("CIS-2.2", "/etc/shadow permissions 640 or stricter",
        _file_mode("/etc/shadow", 0o640),
        "CRITICAL", "CIS,NIST,PCI-DSS")

    chk("CIS-2.3", "/etc/sudoers permissions 440 or stricter",
        _file_mode("/etc/sudoers", 0o440),
        "CRITICAL", "CIS,NIST,IEC62443")

    chk("CIS-2.4", "No world-writable files in /etc",
        _run("find /etc -maxdepth 2 -perm -002 -type f 2>/dev/null | head -1")[1] == "",
        "HIGH", "CIS,NIST")

    chk("CIS-2.5", "No SUID binaries outside expected set",
        _run("find /usr/bin /usr/sbin -perm -4000 -not -name 'sudo' -not -name 'su' "
             "-not -name 'passwd' -not -name 'ping' 2>/dev/null | wc -l")[1].strip() in ("0", ""),
        "MEDIUM", "CIS,NIST")

    chk("CIS-2.6", "Sticky bit set on /tmp",
        _run("stat -c '%a' /tmp")[1].startswith(("1", "17")),
        "MEDIUM", "CIS")

    # ── 3. Network ─────────────────────────────────────────────────
    chk("CIS-3.1", "Firewall (ufw/iptables) active",
        _run("ufw status")[1].startswith("Status: active") or
        _run("iptables -L INPUT -n")[1].count("ACCEPT") < 5,
        "CRITICAL", "PCI-DSS,NIST,IEC62443")

    chk("CIS-3.2", "IP forwarding disabled",
        _run("sysctl net.ipv4.ip_forward")[1] in ("net.ipv4.ip_forward = 0", ""),
        "HIGH", "NIST,IEC62443")

    chk("CIS-3.3", "SYN cookies enabled",
        _run("sysctl net.ipv4.tcp_syncookies")[1] == "net.ipv4.tcp_syncookies = 1",
        "MEDIUM", "NIST")

    chk("CIS-3.4", "ICMP redirects ignored",
        _run("sysctl net.ipv4.conf.all.accept_redirects")[1] == "net.ipv4.conf.all.accept_redirects = 0",
        "MEDIUM", "NIST,IEC62443")

    chk("CIS-3.5", "Source routing disabled",
        _run("sysctl net.ipv4.conf.all.accept_source_route")[1] == "net.ipv4.conf.all.accept_source_route = 0",
        "MEDIUM", "NIST")

    chk("CIS-3.6", "No unencrypted telnet service running",
        _run("ss -tlnp | grep ':23 '")[1] == "",
        "CRITICAL", "PCI-DSS,NIST,IEC62443")

    chk("CIS-3.7", "No FTP service running",
        _run("ss -tlnp | grep -E ':(21|20) '")[1] == "",
        "HIGH", "PCI-DSS,NIST")

    # ── 4. Auditing ────────────────────────────────────────────────
    chk("CIS-4.1", "auditd service enabled and running",
        _run("systemctl is-active auditd")[1] == "active",
        "HIGH", "PCI-DSS,NIST,HIPAA")

    chk("CIS-4.2", "Audit rules for /etc/passwd changes",
        _file_contains("/etc/audit/rules.d/audit.rules", r"/etc/passwd") or
        _run("auditctl -l 2>/dev/null | grep passwd")[0] == 0,
        "HIGH", "PCI-DSS,NIST,HIPAA")

    chk("CIS-4.3", "Audit rules for sudo usage",
        _file_contains("/etc/audit/rules.d/audit.rules", r"sudo") or
        _run("auditctl -l 2>/dev/null | grep sudo")[0] == 0,
        "MEDIUM", "NIST")

    chk("CIS-4.4", "Auditd log rotation configured",
        _file_contains("/etc/audit/auditd.conf", r"max_log_file_action\s*=\s*ROTATE"),
        "MEDIUM", "PCI-DSS,NIST")

    chk("CIS-4.5", "syslog / rsyslog service running",
        _run("systemctl is-active rsyslog syslog")[1] in ("active", "active\nactive"),
        "MEDIUM", "PCI-DSS,NIST")

    # ── 5. Updates & services ──────────────────────────────────────
    chk("CIS-5.1", "Automatic security updates configured",
        _file_exists("/etc/apt/apt.conf.d/20auto-upgrades") and
        _file_contains("/etc/apt/apt.conf.d/20auto-upgrades", r'APT::Periodic::Unattended-Upgrade\s+"1"'),
        "HIGH", "PCI-DSS,NIST")

    chk("CIS-5.2", "NTP / timesyncd configured (accurate timestamps)",
        _run("systemctl is-active systemd-timesyncd ntp chrony")[1].startswith("active") or
        _file_exists("/etc/ntp.conf"),
        "MEDIUM", "PCI-DSS,IEC62443")

    chk("CIS-5.3", "X11 server not running",
        _run("ss -tlnp | grep -E ':(6000|6001) '")[1] == "",
        "LOW", "CIS,IEC62443")

    chk("CIS-5.4", "Avahi / mDNS daemon disabled",
        _run("systemctl is-active avahi-daemon")[1] != "active",
        "LOW", "CIS,IEC62443")

    # ── 6. ICS-specific ───────────────────────────────────────────
    chk("ICS-1.1", "Modbus port 502 not exposed externally",
        _run("ss -tlnp | grep ':502 '")[1] == "" or
        _run("iptables -L INPUT -n | grep '0.0.0.0.*502'")[1] == "",
        "CRITICAL", "IEC62443,NIST-SP800-82")

    chk("ICS-1.2", "DNP3 port 20000 restricted to OT network",
        _run("ss -tlnp | grep ':20000 '")[1] == "",
        "CRITICAL", "IEC62443,NERC-CIP")

    chk("ICS-1.3", "EtherNet/IP port 44818 access controlled",
        _run("ss -tlnp | grep ':44818 '")[1] == "",
        "HIGH", "IEC62443,NIST-SP800-82")

    chk("ICS-1.4", "USB storage disabled (ICS air-gap policy)",
        _file_contains("/etc/modprobe.d/blacklist.conf", r"usb-storage") or
        _run("lsmod | grep usb_storage")[1] == "",
        "HIGH", "IEC62443,NERC-CIP,ICS-CERT")

    return checks


def compute_compliance(checks: list[dict]) -> dict:
    """Compute PCI-DSS, HIPAA, and NIST CSF scores from SCA results."""
    total = len(checks) or 1

    def _score(tags_filter):
        relevant = [c for c in checks if any(t in (c.get("tags", "")) for t in tags_filter.split(","))]
        if not relevant:
            return {"score": 0, "pass": 0, "fail": 0, "crit_fail": 0, "status": "NON-COMPLIANT"}
        passed    = sum(1 for c in relevant if c["status"] == "PASS")
        failed    = sum(1 for c in relevant if c["status"] == "FAIL")
        crit_fail = sum(1 for c in relevant if c["status"] == "FAIL" and c["severity"] == "CRITICAL")
        score     = max(0, round(passed / len(relevant) * 100) - crit_fail * 15)
        status    = "COMPLIANT" if score >= 80 else "PARTIAL" if score >= 50 else "NON-COMPLIANT"
        return {"score": score, "pass": passed, "fail": failed, "crit_fail": crit_fail, "status": status}

    return {
        "PCI-DSS": _score("PCI-DSS"),
        "HIPAA":   _score("HIPAA"),
        "NIST":    _score("NIST"),
    }
