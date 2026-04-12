"""
server/vuln.py — Secure Continuous Monitoring System
Vulnerability detection: queries installed packages against an offline
CVE baseline and optionally live NVD NIST API results.
"""

import subprocess
import logging
import requests

log = logging.getLogger("scms.vuln")

# ── Offline CVE baseline ──────────────────────────────────────────────────────
NVD_OFFLINE = [
    {"package": "glibc",    "cve": "CVE-2023-4911", "severity": "CRITICAL",
     "description": "Looney Tunables — local privilege escalation via GLIBC_TUNABLES"},
    {"package": "sudo",     "cve": "CVE-2021-3156", "severity": "CRITICAL",
     "description": "Baron Samedit — heap-based buffer overflow in sudoedit"},
    {"package": "polkit",   "cve": "CVE-2021-4034", "severity": "CRITICAL",
     "description": "PwnKit — local privilege escalation in pkexec"},
    {"package": "bash",     "cve": "CVE-2014-6271", "severity": "CRITICAL",
     "description": "Shellshock — arbitrary code execution via env variables"},
    {"package": "openssl",  "cve": "CVE-2022-0778", "severity": "HIGH",
     "description": "Infinite loop via crafted certificate in BN_mod_sqrt()"},
    {"package": "openssl",  "cve": "CVE-2023-0286", "severity": "HIGH",
     "description": "X.400 address type confusion in GeneralName"},
    {"package": "curl",     "cve": "CVE-2023-23914", "severity": "MEDIUM",
     "description": "HSTS bypass via clear-text downgrade"},
    {"package": "wget",     "cve": "CVE-2021-31879", "severity": "MEDIUM",
     "description": "Authorization header exposure on redirect"},
    {"package": "vim",      "cve": "CVE-2022-1898", "severity": "HIGH",
     "description": "Use-after-free in vim before 8.2.4970"},
    {"package": "git",      "cve": "CVE-2023-25652", "severity": "HIGH",
     "description": "Path traversal via git apply --reject"},
    {"package": "python3",  "cve": "CVE-2023-24329", "severity": "MEDIUM",
     "description": "urllib.parse bypass via empty string in scheme"},
    {"package": "libssl3",  "cve": "CVE-2022-0778", "severity": "HIGH",
     "description": "OpenSSL BN_mod_sqrt infinite loop"},
    {"package": "zlib1g",   "cve": "CVE-2022-37434", "severity": "CRITICAL",
     "description": "Heap buffer over-read/write in inflate via extra field"},
    {"package": "libc6",    "cve": "CVE-2022-23219", "severity": "CRITICAL",
     "description": "Buffer overflow in glibc clnt_create via long pathname"},
    {"package": "nss",      "cve": "CVE-2023-0767", "severity": "HIGH",
     "description": "Arbitrary memory write via PKCS 12 import"},
]

NVD_KEYWORDS = [
    "openssh", "openssl", "sudo", "bash", "curl", "wget",
    "glibc", "polkit", "vim", "git", "python", "zlib",
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── NVD live query ────────────────────────────────────────────────────────────
def _nvd_query(keyword: str) -> list[dict] | None:
    try:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={keyword}&resultsPerPage=5"
        )
        r = requests.get(url, timeout=3)
        if r.status_code != 200:
            return None
        data    = r.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve     = item.get("cve", {})
            cve_id  = cve.get("id", "")
            metrics = cve.get("metrics", {})
            sev     = "MEDIUM"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                m = metrics.get(key, [])
                if m:
                    sev = m[0].get("cvssData", {}).get("baseSeverity", "MEDIUM")
                    break
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
            )
            results.append({
                "cve":         cve_id,
                "severity":    sev.upper(),
                "description": desc[:120],
                "source":      "NVD-live",
            })
        return results
    except Exception as exc:
        log.debug("NVD query error for '%s': %s", keyword, exc)
        return None


# ── Installed package enumeration ─────────────────────────────────────────────
def _installed_packages() -> set[str]:
    try:
        r = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=10)
        return {
            ln.split()[1].split(":")[0].lower()
            for ln in r.stdout.splitlines()
            if ln.startswith("ii")
        }
    except Exception:
        return set()


# ── Main scanner ──────────────────────────────────────────────────────────────
def vuln_scan() -> list[dict]:
    installed = _installed_packages()
    vulns: list[dict] = []
    seen_cve: set[str] = set()

    # Try NVD live for key packages
    for kw in NVD_KEYWORDS:
        if any(kw in p for p in installed):
            live = _nvd_query(kw)
            if live:
                for v in live[:2]:
                    if v["cve"] not in seen_cve:
                        seen_cve.add(v["cve"])
                        vulns.append({"package": kw, **v})

    # Fill with offline baseline
    for entry in NVD_OFFLINE:
        pkg = entry["package"].split(":")[0].lower()
        if entry["cve"] not in seen_cve and (pkg in installed or not installed):
            seen_cve.add(entry["cve"])
            vulns.append({**entry, "source": "offline"})

    vulns.sort(key=lambda v: SEV_ORDER.get(v.get("severity", "INFO"), 4))
    return vulns
