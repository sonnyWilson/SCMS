"""
server/sis.py — Secure Continuous Monitoring System
Safety Instrumented System (SIS) trip rule engine.
Evaluates decoded ICS packets against 13 predefined SIL-rated rules
covering Modbus, DNP3, EtherNet/IP, and IEC-104.
"""

import logging
from datetime import datetime, timezone

log = logging.getLogger("scms.sis")

# ── Rule definitions ──────────────────────────────────────────────
# Each rule maps to an IEC 62443 / ISA-84 safety function.
# Fields: id, name, protocol, function_codes (set|None=any), address_range,
#         value_range, zone, severity, description, action.
_RULES = [
    {
        "id":      "SIS-001",
        "name":    "Unauthorized Modbus Write to Safety PLC",
        "protocol": "Modbus",
        "function_codes": {5, 6, 15, 16},
        "address_range": (0, 9999),
        "value_range":   None,
        "zone":     "Safety Zone",
        "severity": "CRITICAL",
        "description": "Write command to safety PLC coil/register area — potential safety override",
        "action":   "Alert + Log + Isolate safety zone",
    },
    {
        "id":      "SIS-002",
        "name":    "Modbus Emergency Stop Override Attempt",
        "protocol": "Modbus",
        "function_codes": {5},
        "address_range": (100, 199),
        "value_range":   None,
        "zone":     "Safety Zone",
        "severity": "CRITICAL",
        "description": "Write to E-stop coil range — possible SIS bypass attempt",
        "action":   "Immediate alert + Isolate + Notify operator",
    },
    {
        "id":      "SIS-003",
        "name":    "Mass Modbus Register Write (Bulk Override)",
        "protocol": "Modbus",
        "function_codes": {15, 16},
        "address_range": None,
        "value_range":   (50, 9999),   # value = register count
        "zone":     "ICS Zone",
        "severity": "HIGH",
        "description": "Writing more than 50 registers in a single request — possible parameter tampering",
        "action":   "Alert + Rate limit",
    },
    {
        "id":      "SIS-004",
        "name":    "DNP3 Unauthorized Control Block",
        "protocol": "DNP3",
        "function_codes": {3, 4, 129, 130},   # Operate / Direct Operate
        "address_range": None,
        "value_range":   None,
        "zone":     "OT Zone",
        "severity": "CRITICAL",
        "description": "DNP3 control function from unexpected source — possible relay misoperation risk",
        "action":   "Alert + Log + Block source IP",
    },
    {
        "id":      "SIS-005",
        "name":    "Modbus Coil Write Burst (DoS / Scan)",
        "protocol": "Modbus",
        "function_codes": {5, 6},
        "address_range": None,
        "value_range":   None,
        "zone":     "ICS Zone",
        "severity": "HIGH",
        "description": "High-frequency single-coil writes — possible DoS or automated scan",
        "action":   "Alert + Rate limit source",
    },
    {
        "id":      "SIS-006",
        "name":    "EtherNet/IP CIP Service to Safety Assembly",
        "protocol": "EtherNet/IP",
        "function_codes": {0x4C, 0x4E},   # Get/Set Attribute
        "address_range": (0x8000, 0xFFFF),  # Safety assembly range
        "value_range":   None,
        "zone":     "Safety Zone",
        "severity": "CRITICAL",
        "description": "CIP attribute access to safety assembly object — SIS integrity risk",
        "action":   "Alert + Isolate",
    },
    {
        "id":      "SIS-007",
        "name":    "IEC-104 ASDU Command to Critical Function",
        "protocol": "IEC104",
        "function_codes": {45, 46, 58, 59, 62},  # Single/Double command types
        "address_range": None,
        "value_range":   None,
        "zone":     "SCADA Zone",
        "severity": "HIGH",
        "description": "IEC-104 command ASDU on control channel — verify authorization",
        "action":   "Alert + Log",
    },
    {
        "id":      "SIS-008",
        "name":    "External Source ICS Traffic",
        "protocol": None,  # Any ICS protocol
        "function_codes": None,
        "address_range": None,
        "value_range":   None,
        "zone":     "Perimeter",
        "severity": "CRITICAL",
        "description": "ICS protocol traffic originating from non-OT IP range — network boundary violation",
        "action":   "Block + Alert + Incident",
    },
    {
        "id":      "SIS-009",
        "name":    "Modbus Read of Diagnostics Register",
        "protocol": "Modbus",
        "function_codes": {8},
        "address_range": None,
        "value_range":   None,
        "zone":     "ICS Zone",
        "severity": "MEDIUM",
        "description": "Modbus diagnostics function — may indicate reconnaissance",
        "action":   "Log",
    },
    {
        "id":      "SIS-010",
        "name":    "DNP3 Application Layer Disabled (NULL function)",
        "protocol": "DNP3",
        "function_codes": {0},
        "address_range": None,
        "value_range":   None,
        "zone":     "OT Zone",
        "severity": "HIGH",
        "description": "DNP3 NULL application-layer function — possible keep-alive flood or fuzzing",
        "action":   "Alert + Investigate",
    },
    {
        "id":      "SIS-011",
        "name":    "S7comm Read System Status List",
        "protocol": "S7comm",
        "function_codes": {0x00},
        "address_range": None,
        "value_range":   None,
        "zone":     "ICS Zone",
        "severity": "MEDIUM",
        "description": "S7 System Status List (SSL) read — possible footprinting of Siemens PLC",
        "action":   "Log + Alert",
    },
    {
        "id":      "SIS-012",
        "name":    "BACnet Read Property to Critical Object",
        "protocol": "BACnet",
        "function_codes": {12},  # ReadProperty
        "address_range": (0, 99),
        "value_range":   None,
        "zone":     "BAS Zone",
        "severity": "MEDIUM",
        "description": "BACnet ReadProperty on low-numbered object — critical BAS asset interrogation",
        "action":   "Log",
    },
    {
        "id":      "SIS-013",
        "name":    "OPC-UA Session Establish from Unknown Client",
        "protocol": "OPC-UA",
        "function_codes": {0x461},  # CreateSession service
        "address_range": None,
        "value_range":   None,
        "zone":     "SCADA Zone",
        "severity": "HIGH",
        "description": "OPC-UA CreateSession from unrecognized endpoint — verify whitelist",
        "action":   "Alert + Log",
    },
]


def get_all_rules() -> list[dict]:
    """Return all SIS rules (for the dashboard table)."""
    return [
        {
            "id":       r["id"],
            "name":     r["name"],
            "protocol": r["protocol"] or "Any ICS",
            "zone":     r["zone"],
            "severity": r["severity"],
            "description": r["description"],
            "action":   r["action"],
        }
        for r in _RULES
    ]


def _is_external(ip: str) -> bool:
    if not ip:
        return False
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except Exception:
        return False


def evaluate_packet(pkt: dict) -> list[dict]:
    """
    Evaluate a decoded packet against all SIS rules.
    Returns a list of trip event dicts for any rules that fired.
    """
    trips: list[dict] = []
    ics_proto = pkt.get("ICSProtocol")
    if not ics_proto:
        return trips

    fc        = pkt.get("ICSFunctionCode")
    addr      = pkt.get("ICSAddress")
    val_raw   = pkt.get("ICSValue", "")
    src_ip    = pkt.get("SrcIp", "")
    dst_ip    = pkt.get("DstIp", "")

    # Try to parse a numeric value from ICSValue
    val_num = None
    try:
        val_num = int(str(val_raw).split()[0])
    except Exception:
        pass

    now = datetime.now(timezone.utc).isoformat()

    for rule in _RULES:
        # Rule SIS-008: external ICS traffic — protocol-agnostic
        if rule["id"] == "SIS-008":
            if ics_proto and _is_external(src_ip):
                trips.append(_make_trip(rule, pkt, now))
            continue

        # Protocol match
        if rule["protocol"] and rule["protocol"].lower() not in ics_proto.lower():
            continue

        # Function code match
        if rule["function_codes"] is not None:
            if fc is None or fc not in rule["function_codes"]:
                continue

        # Address range match
        if rule["address_range"] is not None and addr is not None:
            lo, hi = rule["address_range"]
            if not (lo <= addr <= hi):
                continue

        # Value range match (used as count threshold for SIS-003)
        if rule["value_range"] is not None and val_num is not None:
            lo, hi = rule["value_range"]
            if not (lo <= val_num <= hi):
                continue

        trips.append(_make_trip(rule, pkt, now))
        log.warning("SIS trip: %s — %s src=%s dst=%s", rule["id"], rule["name"], src_ip, dst_ip)

    return trips


def _make_trip(rule: dict, pkt: dict, ts: str) -> dict:
    return {
        "RuleId":           rule["id"],
        "RuleName":         rule["name"],
        "Severity":         rule["severity"],
        "TriggerProtocol":  pkt.get("ICSProtocol"),
        "TriggerFunction":  pkt.get("ICSFunctionName"),
        "TriggerAddress":   pkt.get("ICSAddress"),
        "TriggerValue":     str(pkt.get("ICSValue", ""))[:200],
        "SrcIp":            pkt.get("SrcIp"),
        "DstIp":            pkt.get("DstIp"),
        "AffectedZone":     rule["zone"],
        "Action":           rule["action"],
        "EventTime":        ts,
    }
