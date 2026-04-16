"""

Log line parsing: text logs, journald, and ICS/SCADA protocol decode.
Maps raw lines to structured event dicts for DB insertion.
"""

import re
import logging
from datetime import datetime, timezone

log = logging.getLogger("scms.parser")

# ICS ports → protocol name
ICS_PORTS = {
    502:   "Modbus",
    20000: "DNP3",
    44818: "EtherNet/IP",
    102:   "S7comm",
    47808: "BACnet",
    2404:  "IEC104",
    4840:  "OPC-UA",
}

# Modbus function code descriptions
MODBUS_FC = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    43: "Read Device Identification", 8: "Diagnostics",
}

# MITRE mappings by event type
MITRE_MAP = {
    "AUTH":               "T1110",
    "AUTH_FAIL":          "T1110,T1110.001",
    "SUDO":               "T1548.003",
    "SUSPICIOUS_COMMAND": "T1059.004,T0807",
    "BASH_HISTORY":       "T1552.003",
    "ICS_MODBUS":         "T0836,T0855",
    "ICS_DNP3":           "T0855,T0831",
    "ICS_ENIP":           "T0855,T0836",
    "ICS_IEC104":         "T0855,T0836",
    "NETWORK_ANOMALY":    "T0846,T0888",
}

# Suspicious shell commands
_SUSP_CMDS = re.compile(
    r"\b(wget|curl|nc|ncat|netcat|base64|python.*-c|perl.*-e|bash.*-i|"
    r"chmod.*\+s|chown.*root|iptables|nmap|masscan|sqlmap|msfconsole|"
    r"/etc/shadow|/etc/passwd.*w|dd.*if=/dev|mkfs|rm.*-rf|>.*authorized_keys)\b",
    re.IGNORECASE,
)

# ── Auth patterns ─────────────────────────────────────────────────────────────
_AUTH_FAIL_RE = re.compile(
    r"(?:Failed password|authentication failure|FAILED LOGIN|Invalid user|"
    r"pam_unix.*auth.*failure|error: PAM|Connection closed by.*\[preauth\])",
    re.IGNORECASE,
)
_AUTH_OK_RE = re.compile(
    r"(?:Accepted password|Accepted publickey|session opened for user|"
    r"pam_unix.*session.*opened|Successful SU)",
    re.IGNORECASE,
)
_SUDO_RE  = re.compile(r"\bsudo\b.*COMMAND=(.*)", re.IGNORECASE)
_CRON_RE  = re.compile(r"\b(cron|CRON|crond)\b", re.IGNORECASE)
_PKG_RE   = re.compile(r"\b(apt|dpkg|yum|dnf|rpm|pip|pip3|npm|gem)\b", re.IGNORECASE)
_NET_RE   = re.compile(r"\b(ifconfig|ip addr|NetworkManager|dhclient|wpa_supplicant)\b", re.IGNORECASE)
_ERR_RE   = re.compile(r"\b(error|critical|panic|segfault|kernel.*oops|oom-killer)\b", re.IGNORECASE)
_IP_RE    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_RE  = re.compile(r"for (?:invalid user )?(\w[\w\-\.]*) from", re.IGNORECASE)
_PORT_RE  = re.compile(r"port (\d+)", re.IGNORECASE)
_SYS_RE   = re.compile(r"\b(systemd|kernel|dbus|NetworkManager|udev)\b", re.IGNORECASE)


def parse(line: str, source_type: str = "SYS") -> dict | None:
    """Parse a raw log line into a structured event dict."""
    if not line or not line.strip():
        return None
    line = line.strip()

    now = datetime.now(timezone.utc).isoformat()

    event = {
        "EventTime":  now,
        "EventType":  "SYS",
        "Success":    1,
        "UserName":   None,
        "HostName":   None,
        "SourceIp":   None,
        "DestIp":     None,
        "Protocol":   None,
        "Port":       None,
        "Message":    line[:700],
        "RawLine":    line[:700],
        "Severity":   "LOW",
        "MitreIds":   None,
    }

    # ── Auth failures ──────────────────────────────────────────────
    if _AUTH_FAIL_RE.search(line):
        event["EventType"] = "AUTH_FAIL"
        event["Success"]   = 0
        event["Severity"]  = "HIGH"
        event["MitreIds"]  = MITRE_MAP["AUTH_FAIL"]
        m = _IP_RE.search(line)
        if m: event["SourceIp"] = m.group(1)
        m = _USER_RE.search(line)
        if m: event["UserName"] = m.group(1)
        m = _PORT_RE.search(line)
        if m: event["Port"] = int(m.group(1))
        return event

    # ── Auth success ───────────────────────────────────────────────
    if _AUTH_OK_RE.search(line):
        event["EventType"] = "AUTH"
        event["Success"]   = 1
        event["Severity"]  = "LOW"
        event["MitreIds"]  = MITRE_MAP["AUTH"]
        m = _IP_RE.search(line)
        if m: event["SourceIp"] = m.group(1)
        m = _USER_RE.search(line)
        if m: event["UserName"] = m.group(1)
        return event

    # ── Sudo ───────────────────────────────────────────────────────
    if _SUDO_RE.search(line):
        cmd_m = _SUDO_RE.search(line)
        event["EventType"] = "SUDO"
        event["Severity"]  = "MEDIUM"
        event["MitreIds"]  = MITRE_MAP["SUDO"]
        if cmd_m:
            cmd = cmd_m.group(1).strip()
            if _SUSP_CMDS.search(cmd):
                event["EventType"] = "SUSPICIOUS_COMMAND"
                event["Severity"]  = "HIGH"
                event["MitreIds"]  = MITRE_MAP["SUSPICIOUS_COMMAND"]
        m = re.search(r"(\w[\w\-\.]+)\s*:", line)
        if m: event["UserName"] = m.group(1)
        return event

    # ── Bash history / suspicious commands ────────────────────────
    if _SUSP_CMDS.search(line):
        event["EventType"] = "SUSPICIOUS_COMMAND"
        event["Severity"]  = "HIGH"
        event["MitreIds"]  = MITRE_MAP["SUSPICIOUS_COMMAND"]
        return event

    if "HISTORY" in line or ".bash_history" in line:
        event["EventType"] = "BASH_HISTORY"
        event["Severity"]  = "MEDIUM"
        event["MitreIds"]  = MITRE_MAP["BASH_HISTORY"]
        return event

    # ── Package management ─────────────────────────────────────────
    if _PKG_RE.search(line):
        event["EventType"] = "PKG_MGMT"
        event["Severity"]  = "LOW"
        return event

    # ── Network changes ────────────────────────────────────────────
    if _NET_RE.search(line):
        event["EventType"] = "NET_CHANGE"
        event["Severity"]  = "LOW"
        return event

    # ── Cron ───────────────────────────────────────────────────────
    if _CRON_RE.search(line):
        event["EventType"] = "CRON"
        event["Severity"]  = "LOW"
        return event

    # ── System errors ──────────────────────────────────────────────
    if _ERR_RE.search(line):
        event["EventType"] = "SYS_ERROR"
        event["Severity"]  = "MEDIUM"
        return event

    # ── Systemd / kernel ───────────────────────────────────────────
    if _SYS_RE.search(line):
        event["EventType"] = "SYS"
        event["Severity"]  = "LOW"
        return event

    # ── Fallback ───────────────────────────────────────────────────
    return event


def parse_packet(raw: dict) -> dict:
    """
    Decode a raw packet dict (from scapy/tshark) into a richer structured
    dict, including ICS protocol identification and anomaly scoring.
    """
    src_ip   = raw.get("src_ip",   raw.get("SrcIp",   ""))
    dst_ip   = raw.get("dst_ip",   raw.get("DstIp",   ""))
    src_port = int(raw.get("src_port", raw.get("SrcPort", 0)) or 0)
    dst_port = int(raw.get("dst_port", raw.get("DstPort", 0)) or 0)
    proto    = raw.get("protocol", raw.get("Protocol", "OTHER")).upper()
    length   = int(raw.get("length", raw.get("Length", 0)) or 0)
    ttl      = int(raw.get("ttl",    raw.get("TTL", 64)) or 64)
    flags    = raw.get("flags",    raw.get("Flags", ""))
    iface    = raw.get("interface", raw.get("Interface", "eth0"))

    payload = raw.get("payload_bytes") or raw.get("Payload") or b""
    if isinstance(payload, str):
        try:
            payload = bytes.fromhex(payload.replace(":", "").replace(" ", ""))
        except ValueError:
            payload = payload.encode("latin-1", errors="replace")

    pkt = {
        "SrcIp":    src_ip,  "DstIp":    dst_ip,
        "SrcPort":  src_port,"DstPort":  dst_port,
        "Protocol": proto,   "Length":   length,
        "TTL":      ttl,     "Flags":    flags,
        "Interface": iface,
        "Payload":  payload[:64].hex() if payload else "",
        "PayloadHex": payload[:128].hex() if payload else "",
        "RawHex":   payload[:256].hex() if payload else "",
        "ICSProtocol": None, "ICSFunctionCode": None,
        "ICSFunctionName": None, "ICSAddress": None, "ICSValue": None,
        "Anomaly": False, "AnomalyReason": None,
        "ThreatScore": 0,
    }

    # ICS protocol identification by port
    ics_proto = ICS_PORTS.get(dst_port) or ICS_PORTS.get(src_port)
    if ics_proto:
        pkt["ICSProtocol"] = ics_proto
        _decode_ics(pkt, ics_proto, payload)

    # Basic anomaly detection
    _score_anomalies(pkt, src_ip)

    return pkt


def _decode_ics(pkt: dict, proto: str, payload: bytes):
    if proto == "Modbus" and len(payload) >= 8:
        try:
            # Modbus TCP: bytes 6-7 are unit ID and function code
            fc = payload[7] if len(payload) > 7 else payload[-1]
            fc = fc & 0x7F  # mask error bit
            pkt["ICSFunctionCode"] = fc
            pkt["ICSFunctionName"] = MODBUS_FC.get(fc, f"FC-{fc}")
            if len(payload) >= 10:
                addr = int.from_bytes(payload[8:10], "big")
                pkt["ICSAddress"] = addr
            if fc in (5, 6, 15, 16):
                pkt["ThreatScore"] = max(pkt["ThreatScore"], 40)
                if fc in (15, 16) and len(payload) >= 12:
                    count = int.from_bytes(payload[10:12], "big")
                    pkt["ICSValue"] = f"{count} registers"
                    if count > 50:
                        pkt["Anomaly"] = True
                        pkt["AnomalyReason"] = f"Modbus mass write: {count} registers"
                        pkt["ThreatScore"] = max(pkt["ThreatScore"], 75)
        except Exception:
            pass

    elif proto == "DNP3" and len(payload) >= 10:
        try:
            pkt["ICSFunctionCode"] = payload[9] if len(payload) > 9 else None
            pkt["ICSFunctionName"] = "DNP3 Application Layer"
        except Exception:
            pass

    elif proto == "EtherNet/IP" and len(payload) >= 4:
        try:
            cmd = int.from_bytes(payload[0:2], "little")
            pkt["ICSFunctionCode"] = cmd
            pkt["ICSFunctionName"] = {0x65: "RegisterSession", 0x66: "UnRegisterSession",
                                       0x6F: "SendRRData", 0x70: "SendUnitData"}.get(cmd, f"CIP-{cmd:#x}")
        except Exception:
            pass


def _score_anomalies(pkt: dict, src_ip: str):
    # SYN flood / port scan heuristic
    if pkt.get("Flags") == "S" and pkt.get("Length", 0) < 60:
        pkt["ThreatScore"] = max(pkt["ThreatScore"], 30)

    # Tiny TTL (traceroute / source routing)
    if 0 < (pkt.get("TTL") or 64) < 5:
        pkt["ThreatScore"] = max(pkt["ThreatScore"], 50)
        pkt["Anomaly"] = True
        pkt["AnomalyReason"] = (pkt.get("AnomalyReason") or "") + "; TTL < 5 — possible traceroute"

    # ICS from external IP
    if pkt.get("ICSProtocol") and src_ip and not _is_private(src_ip):
        pkt["ThreatScore"] = max(pkt["ThreatScore"], 80)
        pkt["Anomaly"] = True
        pkt["AnomalyReason"] = (pkt.get("AnomalyReason") or "") + f"; External ICS traffic from {src_ip}"


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def correlate_packet_to_event(pkt: dict) -> dict:
    """Convert a decoded packet dict into a Logs-compatible event dict."""
    ics_proto = pkt.get("ICSProtocol")
    fc_name   = pkt.get("ICSFunctionName", "")
    src_ip    = pkt.get("SrcIp", "")

    if ics_proto:
        etype = f"ICS_{ics_proto.upper().replace('-', '_').replace('/', '_')}"
    elif pkt.get("Anomaly"):
        etype = "NETWORK_ANOMALY"
    else:
        etype = "SYS"

    threat  = pkt.get("ThreatScore", 0)
    sev = "CRITICAL" if threat >= 80 else "HIGH" if threat >= 60 else "MEDIUM" if threat >= 30 else "LOW"
    mitre = MITRE_MAP.get(etype, "")

    msg_parts = []
    if ics_proto:
        msg_parts.append(f"{ics_proto} {fc_name}")
    if pkt.get("ICSAddress") is not None:
        msg_parts.append(f"addr={pkt['ICSAddress']}")
    if pkt.get("ICSValue"):
        msg_parts.append(f"val={pkt['ICSValue']}")
    if pkt.get("AnomalyReason"):
        msg_parts.append(pkt["AnomalyReason"].lstrip("; "))
    message = " | ".join(msg_parts) or f"Packet {pkt.get('Protocol','')} {src_ip}→{pkt.get('DstIp','')}"

    from datetime import datetime, timezone
    return {
        "EventTime": datetime.now(timezone.utc).isoformat(),
        "EventType": etype,
        "Success":   0 if pkt.get("Anomaly") else 1,
        "SourceIp":  src_ip,
        "DestIp":    pkt.get("DstIp"),
        "Protocol":  ics_proto or pkt.get("Protocol"),
        "Port":      pkt.get("DstPort"),
        "Message":   message[:700],
        "RawLine":   f"{src_ip}:{pkt.get('SrcPort',0)} → {pkt.get('DstIp','')}:{pkt.get('DstPort',0)} [{pkt.get('Protocol','')}]",
        "Severity":  sev,
        "MitreIds":  mitre,
    }
