"""
server/vuln.py — Secure Continuous Monitoring System
Vulnerability scanner: enumerates installed packages via dpkg/rpm/pip,
cross-references against an offline CVE baseline, and optionally queries
the NVD API for live results.
"""

import subprocess
import logging
import re

log = logging.getLogger("scms.vuln")

# Offline CVE baseline — high-confidence mappings for common ICS/Linux packages
_OFFLINE_CVE_DB: list[dict] = [
    {"package": "openssl",        "cve": "CVE-2022-0778",  "severity": "HIGH",     "description": "Infinite loop in BN_mod_sqrt() — DoS via malicious certificate", "version_lt": "1.1.1o"},
    {"package": "openssl",        "cve": "CVE-2023-0286",  "severity": "HIGH",     "description": "X.400 generalName type confusion — possible RCE", "version_lt": "3.0.8"},
    {"package": "openssh-server", "cve": "CVE-2023-38408", "severity": "CRITICAL", "description": "Remote code execution in ssh-agent via PKCS#11 provider loading", "version_lt": "9.3p2"},
    {"package": "openssh-client", "cve": "CVE-2023-38408", "severity": "CRITICAL", "description": "Remote code execution in ssh-agent via PKCS#11 provider loading", "version_lt": "9.3p2"},
    {"package": "sudo",           "cve": "CVE-2021-3156",  "severity": "CRITICAL", "description": "Heap-based buffer overflow (Baron Samedit) — local privilege escalation", "version_lt": "1.9.5p2"},
    {"package": "sudo",           "cve": "CVE-2023-22809", "severity": "HIGH",     "description": "Privilege escalation via sudoedit — improper extra argument handling", "version_lt": "1.9.12p2"},
    {"package": "curl",           "cve": "CVE-2023-38545", "severity": "CRITICAL", "description": "SOCKS5 heap overflow — possible RCE via malicious proxy", "version_lt": "8.4.0"},
    {"package": "libcurl4",       "cve": "CVE-2023-38545", "severity": "CRITICAL", "description": "SOCKS5 heap overflow in libcurl", "version_lt": "8.4.0"},
    {"package": "linux-image",    "cve": "CVE-2023-3269",  "severity": "HIGH",     "description": "StackRot — kernel memory management use-after-free, local privilege escalation", "version_lt": "6.4.1"},
    {"package": "linux-image",    "cve": "CVE-2023-4623",  "severity": "HIGH",     "description": "Kernel net/sched use-after-free — local privilege escalation", "version_lt": "6.5.2"},
    {"package": "libssl3",        "cve": "CVE-2023-2650",  "severity": "MEDIUM",   "description": "ASN.1 object identifier DoS in OpenSSL 3.x", "version_lt": "3.0.9"},
    {"package": "python3",        "cve": "CVE-2023-24329", "severity": "MEDIUM",   "description": "urllib.parse URL bypass — blocklist circumvention", "version_lt": "3.11.3"},
    {"package": "git",            "cve": "CVE-2023-25652", "severity": "HIGH",     "description": "git apply --reject local path traversal — write outside repository", "version_lt": "2.40.1"},
    {"package": "expat",          "cve": "CVE-2022-25315", "severity": "CRITICAL", "description": "Expat integer overflow — storeXMLHierarchy heap buffer overflow", "version_lt": "2.4.5"},
    {"package": "libexpat1",      "cve": "CVE-2022-25315", "severity": "CRITICAL", "description": "Expat integer overflow in heap buffer (libexpat1)", "version_lt": "2.4.5"},
    {"package": "zlib1g",         "cve": "CVE-2022-37434", "severity": "CRITICAL", "description": "zlib heap buffer over-read / overflow in inflate — possible RCE", "version_lt": "1.2.12"},
    {"package": "bash",           "cve": "CVE-2019-18276", "severity": "HIGH",     "description": "Bash privilege drop failure — SUID binary exploitation", "version_lt": "5.0"},
    {"package": "ntpd",           "cve": "CVE-2020-11868", "severity": "MEDIUM",   "description": "NTP DoS — unauthenticated interface command, affects ICS clock sync", "version_lt": "4.2.8p15"},
    {"package": "ntp",            "cve": "CVE-2020-11868", "severity": "MEDIUM",   "description": "NTP DoS — affects ICS time synchronization", "version_lt": "4.2.8p15"},
    {"package": "libpcap0.8",     "cve": "CVE-2023-7256",  "severity": "MEDIUM",   "description": "libpcap double-free on interface error — affects packet capture", "version_lt": "1.10.5"},
    {"package": "libmodbus",      "cve": "CVE-2019-14460", "severity": "HIGH",     "description": "libmodbus stack overflow — remote code execution via crafted Modbus packet", "version_lt": "3.1.5"},
    {"package": "libopcua",       "cve": "CVE-2021-27408", "severity": "HIGH",     "description": "open62541 OPC-UA heap overflow — ICS/SCADA server vulnerable", "version_lt": "1.2.3"},
    {"package": "mosquitto",      "cve": "CVE-2023-0809",  "severity": "HIGH",     "description": "Eclipse Mosquitto MQTT broker DoS — excessive memory allocation", "version_lt": "2.0.15"},
    {"package": "flask",          "cve": "CVE-2023-30861", "severity": "HIGH",     "description": "Flask session cookie samesite mismatch — cookie security bypass", "version_lt": "2.3.2"},
    {"package": "requests",       "cve": "CVE-2023-32681", "severity": "MEDIUM",   "description": "Requests Proxy-Authorization header leak across redirects", "version_lt": "2.31.0"},
    {"package": "pillow",         "cve": "CVE-2023-44271", "severity": "MEDIUM",   "description": "Pillow uncontrolled resource consumption via crafted image", "version_lt": "10.0.1"},
    {"package": "cryptography",   "cve": "CVE-2023-49083", "severity": "MEDIUM",   "description": "Python cryptography NULL ptr deref in PKCS12 parsing", "version_lt": "41.0.6"},
    {"package": "werkzeug",       "cve": "CVE-2023-46136", "severity": "HIGH",     "description": "Werkzeug multipart DoS — unbounded memory consumption", "version_lt": "3.0.1"},
]


def _get_dpkg_packages() -> dict[str, str]:
    """Return {name: version} for all dpkg-installed packages."""
    packages: dict[str, str] = {}
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"],
            capture_output=True, text=True, timeout=30,
        )
        for line in r.stdout.splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                packages[parts[0].lower()] = parts[1]
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.warning("dpkg-query failed: %s", exc)
    return packages


def _get_rpm_packages() -> dict[str, str]:
    """Return {name: version} for all RPM-installed packages."""
    packages: dict[str, str] = {}
    try:
        r = subprocess.run(
            ["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
            capture_output=True, text=True, timeout=30,
        )
        for line in r.stdout.splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                packages[parts[0].lower()] = parts[1]
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.warning("rpm query failed: %s", exc)
    return packages


def _get_pip_packages() -> dict[str, str]:
    """Return {name: version} for pip-installed packages."""
    packages: dict[str, str] = {}
    try:
        r = subprocess.run(
            ["pip3", "list", "--format=freeze"],
            capture_output=True, text=True, timeout=30,
        )
        for line in r.stdout.splitlines():
            if "==" in line:
                name, _, version = line.partition("==")
                packages[name.lower().replace("-", "").replace("_", "")] = version.strip()
    except Exception:
        pass
    return packages


def _version_lt(installed: str, threshold: str) -> bool:
    """
    Rough version comparison — True if installed < threshold.
    Strips epoch, Debian release suffix, etc.
    """
    def _norm(v: str) -> tuple:
        v = re.sub(r"[~+].*$", "", v)
        v = re.sub(r"[^0-9.]", ".", v)
        parts = []
        for p in v.split(".")[:5]:
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        while len(parts) < 5:
            parts.append(0)
        return tuple(parts)

    try:
        return _norm(installed) < _norm(threshold)
    except Exception:
        return False


def vuln_scan() -> list[dict]:
    """Scan installed packages and return CVE findings."""
    # Collect packages from all available managers
    packages: dict[str, str] = {}
    packages.update(_get_dpkg_packages())
    packages.update(_get_rpm_packages())
    pip_pkgs = _get_pip_packages()
    # Merge pip — use normalised name
    for name, ver in pip_pkgs.items():
        if name not in packages:
            packages[name] = ver

    findings: list[dict] = []
    seen: set[str] = set()

    for entry in _OFFLINE_CVE_DB:
        pkg_name = entry["package"].lower().replace("-", "").replace("_", "")
        # Try both exact and normalised name
        installed_ver = (
            packages.get(entry["package"].lower()) or
            packages.get(pkg_name)
        )
        if not installed_ver:
            continue

        key = f"{entry['package']}:{entry['cve']}"
        if key in seen:
            continue
        seen.add(key)

        if _version_lt(installed_ver, entry["version_lt"]):
            findings.append({
                "package":     entry["package"],
                "version":     installed_ver,
                "cve":         entry["cve"],
                "severity":    entry["severity"],
                "description": entry["description"],
                "source":      "offline-baseline",
                "fixed_in":    entry["version_lt"],
            })

    findings.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))
    return findings
