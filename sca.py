"""
server/sca.py — Secure Continuous Monitoring System
Security Configuration Assessment — 32 CIS Benchmark checks across SSH,
account policy, filesystem permissions, networking, kernel hardening,
and service auditing.
"""

import os
import subprocess
import logging

log = logging.getLogger("scms.sca")


# ── helpers ───────────────────────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def _cmd(cmd, timeout: int = 4) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return r.stdout + r.stderr
    except Exception:
        return ""


def _chk(checks: list, cid, title, sev, passed: bool, detail="", tags=""):
    checks.append({
        "id":       cid,
        "title":    title,
        "severity": sev,
        "status":   "PASS" if passed else "FAIL",
        "detail":   detail,
        "tags":     tags,
    })


# ── main SCA runner ───────────────────────────────────────────────────────────
def run_sca() -> list[dict]:
    checks: list[dict] = []

    sshd       = _read("/etc/ssh/sshd_config").lower()
    login_defs = _read("/etc/login.defs").lower()
    pam_common = _read("/etc/pam.d/common-password").lower()
    sysctl_out = _cmd("sysctl -a", timeout=5)

    # ── SSH hardening (10 checks) ─────────────────────────────────────────────
    _chk(checks, "SSH-001", "SSH: PermitRootLogin disabled", "HIGH",
         "permitrootlogin no" in sshd or "permitrootlogin prohibit-password" in sshd,
         tags="PCI-DSS:8.2.1,HIPAA:164.312(a),NIST:PR.AC-1")

    _chk(checks, "SSH-002", "SSH: PasswordAuthentication disabled", "MEDIUM",
         "passwordauthentication no" in sshd,
         tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")

    _chk(checks, "SSH-003", "SSH: Protocol 2 enforced", "HIGH",
         "protocol 1" not in sshd,
         tags="PCI-DSS:4.2.1,NIST:PR.DS-2")

    _chk(checks, "SSH-004", "SSH: MaxAuthTries <= 4", "MEDIUM",
         any(f"maxauthtries {n}" in sshd for n in ["1","2","3","4"]),
         tags="PCI-DSS:8.3.4,NIST:PR.AC-7")

    _chk(checks, "SSH-005", "SSH: X11Forwarding disabled", "LOW",
         "x11forwarding no" in sshd,
         tags="NIST:PR.AC-5")

    _chk(checks, "SSH-006", "SSH: LoginGraceTime <= 60s", "LOW",
         any(f"logingracetime {n}" in sshd for n in ["30","45","60","1m"]),
         tags="NIST:DE.CM-1")

    _chk(checks, "SSH-007", "SSH: PermitEmptyPasswords disabled", "CRITICAL",
         "permitemptypasswords no" in sshd or "permitemptypasswords" not in sshd,
         tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")

    _chk(checks, "SSH-008", "SSH: AllowUsers or AllowGroups configured", "MEDIUM",
         "allowusers" in sshd or "allowgroups" in sshd,
         detail="No user restriction configured" if not ("allowusers" in sshd or "allowgroups" in sshd) else "",
         tags="PCI-DSS:7.3,NIST:PR.AC-4")

    _chk(checks, "SSH-009", "SSH: ClientAliveInterval configured", "LOW",
         "clientaliveinterval" in sshd,
         tags="NIST:DE.CM-1")

    _chk(checks, "SSH-010", "SSH: IgnoreRhosts enabled", "HIGH",
         "ignorerhosts yes" in sshd or "ignorerhosts" not in sshd,
         tags="PCI-DSS:2.2.7,NIST:PR.AC-5")

    # ── Account / password policy (5 checks) ─────────────────────────────────
    try:
        with open("/etc/shadow") as f:
            empty = any(ln.split(":")[1] == "" for ln in f if ":" in ln)
        _chk(checks, "ACC-001", "No accounts with empty passwords", "CRITICAL", not empty,
             tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")
    except Exception:
        _chk(checks, "ACC-001", "No accounts with empty passwords", "CRITICAL", False,
             detail="Cannot read /etc/shadow", tags="PCI-DSS:8.3.6,HIPAA:164.312(d),NIST:PR.AC-1")

    pass_max = next((ln.split()[-1].strip() for ln in login_defs.splitlines()
                     if ln.strip().startswith("pass_max_days")), "")
    _chk(checks, "ACC-002", "Password max age <= 90 days", "MEDIUM",
         pass_max.isdigit() and int(pass_max) <= 90,
         detail=f"Current: {pass_max or 'unset'}",
         tags="PCI-DSS:8.3.9,HIPAA:164.308(a)(5),NIST:PR.AC-1")

    pass_min = next((ln.split()[-1].strip() for ln in login_defs.splitlines()
                     if ln.strip().startswith("pass_min_len")), "")
    _chk(checks, "ACC-003", "Password minimum length >= 14", "MEDIUM",
         pass_min.isdigit() and int(pass_min) >= 14,
         detail=f"Current: {pass_min or 'unset'}",
         tags="PCI-DSS:8.3.6,NIST:PR.AC-1")

    _chk(checks, "ACC-004", "PAM password complexity configured", "MEDIUM",
         "pam_pwquality" in pam_common or "pam_cracklib" in pam_common,
         tags="PCI-DSS:8.3.6,HIPAA:164.308(a)(5),NIST:PR.AC-1")

    root_uid0 = _cmd("awk -F: '($3==0){print $1}' /etc/passwd").strip()
    _chk(checks, "ACC-005", "Only root has UID 0", "CRITICAL",
         root_uid0 == "root",
         detail=f"UID-0 accounts: {root_uid0}",
         tags="PCI-DSS:7.2,HIPAA:164.312(a),NIST:PR.AC-4")

    # ── Filesystem permissions (4 checks) ────────────────────────────────────
    try:
        s = os.stat("/tmp")
        _chk(checks, "FS-001", "/tmp has sticky bit set", "LOW", bool(s.st_mode & 0o1000),
             tags="NIST:PR.DS-1")
    except Exception:
        _chk(checks, "FS-001", "/tmp has sticky bit set", "LOW", False)

    for path, check_id, label, tag_sev, valid_modes in [
        ("/etc/passwd", "FS-002", "644 or tighter", "HIGH",  {"644","640","600"}),
        ("/etc/shadow", "FS-003", "640 or tighter", "CRITICAL", {"640","600","000"}),
    ]:
        try:
            s   = os.stat(path)
            mode = oct(s.st_mode)[-3:]
            _chk(checks, check_id, f"{path} permissions are {label}", tag_sev,
                 mode in valid_modes, detail=f"Current: {mode}",
                 tags="PCI-DSS:10.3.2,NIST:PR.DS-1")
        except Exception:
            _chk(checks, check_id, f"{path} permissions are {label}", tag_sev, False,
                 detail=f"Cannot stat {path}")

    ww = _cmd("find / -xdev -type f -perm -0002 2>/dev/null | head -5", timeout=8).strip()
    _chk(checks, "FS-004", "No world-writable files outside /tmp", "HIGH",
         not bool(ww), detail=ww[:100] if ww else "",
         tags="NIST:PR.DS-1,PCI-DSS:10.3.2")

    # ── Network / firewall (5 checks) ─────────────────────────────────────────
    ufw_out = _cmd(["ufw", "status"])
    _chk(checks, "NET-001", "Firewall (UFW) is active", "HIGH",
         "active" in ufw_out.lower(),
         detail="ufw status: " + (ufw_out.strip().splitlines()[0] if ufw_out.strip() else "not found"),
         tags="PCI-DSS:1.3,HIPAA:164.312(e),NIST:PR.AC-5")

    def _sysctl_val(key):
        for ln in sysctl_out.splitlines():
            if key in ln:
                return ln.split("=")[-1].strip()
        return ""

    _chk(checks, "NET-002", "IPv4 forwarding disabled", "MEDIUM",
         _sysctl_val("net.ipv4.ip_forward") == "0",
         detail=f"net.ipv4.ip_forward = {_sysctl_val('net.ipv4.ip_forward') or 'unknown'}",
         tags="NIST:PR.AC-5")

    _chk(checks, "NET-003", "ICMP redirects disabled", "MEDIUM",
         _sysctl_val("net.ipv4.conf.all.accept_redirects") == "0",
         tags="PCI-DSS:1.3,NIST:PR.AC-5")

    _chk(checks, "NET-004", "Reverse path filtering enabled", "LOW",
         _sysctl_val("net.ipv4.conf.all.rp_filter") in ("1","2"),
         tags="NIST:PR.AC-5")

    _chk(checks, "NET-005", "TCP SYN cookies enabled", "MEDIUM",
         _sysctl_val("net.ipv4.tcp_syncookies") == "1",
         tags="NIST:PR.DS-4")

    # ── Kernel hardening (4 checks) ───────────────────────────────────────────
    _chk(checks, "KERN-001", "ASLR fully enabled (randomize_va_space=2)", "HIGH",
         _sysctl_val("kernel.randomize_va_space") == "2",
         tags="NIST:PR.DS-6")

    _chk(checks, "KERN-002", "dmesg restriction enabled", "LOW",
         _sysctl_val("kernel.dmesg_restrict") == "1",
         tags="NIST:PR.DS-6")

    _chk(checks, "KERN-003", "ptrace scope restricted (yama)", "MEDIUM",
         _sysctl_val("kernel.yama.ptrace_scope") in ("1","2","3"),
         tags="NIST:PR.DS-6")

    _chk(checks, "KERN-004", "kptr_restrict enabled", "MEDIUM",
         _sysctl_val("kernel.kptr_restrict") in ("1","2"),
         tags="NIST:PR.DS-6")

    # ── Services / daemons (4 checks) ────────────────────────────────────────
    def _service_active(name):
        return "active" in _cmd(["systemctl", "is-active", name])

    def _service_enabled(name):
        return "enabled" in _cmd(["systemctl", "is-enabled", name])

    _chk(checks, "SVC-001", "auditd service is running", "HIGH",
         _service_active("auditd"),
         tags="PCI-DSS:10.2,HIPAA:164.312(b),NIST:DE.CM-1")

    _chk(checks, "SVC-002", "cron restricted to authorized users", "MEDIUM",
         os.path.exists("/etc/cron.allow"),
         tags="PCI-DSS:8.7,NIST:PR.AC-4")

    _chk(checks, "SVC-003", "rsyslog or syslog service running", "MEDIUM",
         _service_active("rsyslog") or _service_active("syslog"),
         tags="PCI-DSS:10.5,HIPAA:164.312(b),NIST:DE.CM-1")

    _chk(checks, "SVC-004", "NFS not running (unless needed)", "LOW",
         not _service_active("nfs-server"),
         tags="NIST:PR.AC-5")

    return checks


# ── Compliance scorer ─────────────────────────────────────────────────────────
def compute_compliance(checks: list[dict]) -> dict:
    frameworks = {
        "PCI-DSS": {"pass": 0, "fail": 0, "crit_fail": 0},
        "HIPAA":   {"pass": 0, "fail": 0, "crit_fail": 0},
        "NIST":    {"pass": 0, "fail": 0, "crit_fail": 0},
    }
    for c in checks:
        tags = c.get("tags", "")
        for fw in frameworks:
            if fw in tags:
                if c["status"] == "PASS":
                    frameworks[fw]["pass"] += 1
                else:
                    frameworks[fw]["fail"] += 1
                    if c["severity"] in ("CRITICAL", "HIGH"):
                        frameworks[fw]["crit_fail"] += 1

    result = {}
    for fw, d in frameworks.items():
        total = d["pass"] + d["fail"]
        if total == 0:
            result[fw] = {"score": 0, "pass": 0, "fail": 0, "crit_fail": 0, "status": "NON-COMPLIANT"}
            continue
        raw     = d["pass"] / total * 100
        penalty = d["crit_fail"] * 5
        score   = max(0, round(raw - penalty))
        status  = "COMPLIANT" if score >= 80 else ("PARTIAL" if score >= 50 else "NON-COMPLIANT")
        result[fw] = {"score": score, "pass": d["pass"], "fail": d["fail"],
                       "crit_fail": d["crit_fail"], "status": status}
    return result
