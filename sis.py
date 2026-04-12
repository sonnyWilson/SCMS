"""
server/sis.py — Secure Continuous Monitoring System
Safety Instrumented System (SIS) trip rule engine.

Pre-built rules for:
  - Power plant (turbine control, generator, transformer protection)
  - Water treatment (pump control, valve operation, chemical dosing)
  - General ICS (broadcast scans, external access, replay attacks)

Each rule fires when a decoded packet or log event matches its conditions.
On match: creates a SIS_Event record, optionally auto-trips the process
          (simulated here — wire to your actual OPC/SCADA interface),
          creates an Incident, and sends an alert email.
"""

import logging
import threading
import json
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger("scms.sis")

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ─────────────────────────────────────────────────────────────────────────────
# Each rule is a dict with:
#   id          : unique string ID
#   name        : human-readable name
#   severity    : CRITICAL / HIGH / MEDIUM
#   protocol    : ICS protocol to match (or ANY)
#   fc_codes    : list of function codes to match (or None = any)
#   dst_ports   : list of destination ports to match (or None = any)
#   address_range: (min, max) Modbus/DNP3 address range, or None
#   condition_fn: optional callable(pkt_record) -> bool for complex conditions
#   action      : description of SIS trip action
#   zone        : site zone this rule applies to (or ANY)
#   mitre       : list of MITRE ATT&CK ICS technique IDs
#   remediation : step-by-step response instructions

SIS_RULES = [

    # ── POWER PLANT RULES ─────────────────────────────────────────────────────
    {
        "id":        "PWR-001",
        "name":      "Unauthorized Write to Turbine Control Register",
        "severity":  "CRITICAL",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6, 15, 16],
        "dst_ports": [502],
        "address_range": (1000, 1999),
        "action":    "TRIP turbine governor — isolate control network segment — notify shift supervisor",
        "zone":      "Turbine Control",
        "mitre":     ["T0836", "T0855", "T0831"],
        "remediation": [
            "1. Immediately trip turbine governor via local HMI panel",
            "2. Isolate the source IP from the control network via VLAN reconfiguration",
            "3. Capture full PCAP of the offending session",
            "4. Engage physical runback on generator load",
            "5. Notify shift supervisor and ICS security team",
            "6. Do NOT restore automation until forensic review complete",
        ],
        "violations": [
            "NERC CIP-007: Unauthorized modification of turbine setpoint registers",
            "IEC 62443-3-3: SR 3.6 violation — integrity of control commands",
            "NIST SP 800-82: Unauthorized actuator command",
        ]
    },
    {
        "id":        "PWR-002",
        "name":      "Modbus Write to Generator Excitation Control",
        "severity":  "CRITICAL",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6],
        "dst_ports": [502],
        "address_range": (2000, 2499),
        "action":    "TRIP generator exciter — open generator breaker — alarm DCS",
        "zone":      "Generator",
        "mitre":     ["T0836", "T0855"],
        "remediation": [
            "1. Open generator main breaker from local panel",
            "2. Trip excitation system to de-energize field winding",
            "3. Block the source IP in switch ACL immediately",
            "4. Review DCS historian for unauthorized setpoint changes",
            "5. Initiate controlled rundown of turbine",
        ],
        "violations": [
            "NERC CIP-005: Unexpected control command from unrecognized source",
            "IEC 61850: Protection relay bypass attempt",
        ]
    },
    {
        "id":        "PWR-003",
        "name":      "DNP3 DIRECT_OPERATE to Transformer Protection Relay",
        "severity":  "CRITICAL",
        "protocol":  "DNP3",
        "fc_codes":  [5, 6],   # DIRECT_OPERATE, DIRECT_OPERATE_NR
        "dst_ports": [20000],
        "action":    "LOCK OUT transformer — open HV and LV breakers — engage lockout relay 86",
        "zone":      "Transformer Bay",
        "mitre":     ["T0855", "T0831", "T0816"],
        "remediation": [
            "1. Engage lockout relay 86 to hold breakers open",
            "2. Verify transformer differential protection status",
            "3. Inspect transformer for physical damage or fault indicators",
            "4. Block DNP3 master station IP in RTU configuration",
            "5. Review RTU access control logs",
        ],
        "violations": [
            "NERC CIP-005: Rogue DNP3 master impersonating SCADA",
            "IEC 60870-5: Unauthorized operate command on protection relay",
        ]
    },
    {
        "id":        "PWR-004",
        "name":      "DNP3 Cold/Warm Restart to Energy Management System RTU",
        "severity":  "CRITICAL",
        "protocol":  "DNP3",
        "fc_codes":  [13, 14],   # COLD_RESTART, WARM_RESTART
        "dst_ports": [20000],
        "action":    "ISOLATE RTU from SCADA network — switch to manual local control — alert NOC",
        "zone":      "EMS",
        "mitre":     ["T0816", "T0813"],
        "remediation": [
            "1. Physically disconnect RTU from OT network",
            "2. Switch to manual local operator control at field panel",
            "3. Alert Network Operations Center (NOC)",
            "4. Audit DNP3 master station logs for unauthorized sessions",
        ],
        "violations": [
            "NERC CIP-007: Unauthorized RTU restart = availability attack",
            "NIST SP 800-82: ICS denial-of-service via restart command",
        ]
    },

    # ── WATER TREATMENT RULES ─────────────────────────────────────────────────
    {
        "id":        "WTR-001",
        "name":      "Unauthorized Modbus Write to Chemical Dosing Pump",
        "severity":  "CRITICAL",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6, 15, 16],
        "dst_ports": [502],
        "address_range": (3000, 3499),
        "action":    "EMERGENCY STOP chemical dosing pumps — activate manual bypass — notify plant manager",
        "zone":      "Chemical Dosing",
        "mitre":     ["T0836", "T0855", "T0831"],
        "remediation": [
            "1. Emergency stop all chemical dosing pumps immediately",
            "2. Activate manual chlorination bypass",
            "3. Sample and test treated water for chemical levels",
            "4. Notify plant manager and Health Department if dosing altered",
            "5. Isolate SCADA segment — forensic review required",
            "6. Do NOT restore automated dosing until investigation complete",
        ],
        "violations": [
            "EPA Safe Drinking Water Act: Unauthorized alteration of treatment chemical dosing",
            "AWWA Cybersecurity Guidance: Water treatment control system breach",
            "IEC 62443: Safety function bypass",
        ]
    },
    {
        "id":        "WTR-002",
        "name":      "Write to Effluent Discharge Valve Register",
        "severity":  "CRITICAL",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6],
        "dst_ports": [502],
        "address_range": (3500, 3999),
        "action":    "CLOSE all effluent discharge valves — alert environmental compliance officer",
        "zone":      "Effluent Discharge",
        "mitre":     ["T0836", "T0855"],
        "remediation": [
            "1. Manually close all effluent discharge valves",
            "2. Alert environmental compliance officer and site management",
            "3. Document current effluent readings for regulatory reporting",
            "4. Block source IP in PLC firewall rules",
        ],
        "violations": [
            "Clean Water Act: Risk of unauthorized discharge",
            "USEPA: Environmental control system tampering",
        ]
    },
    {
        "id":        "WTR-003",
        "name":      "Unauthorized Write to High-Lift Pump Control",
        "severity":  "HIGH",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6, 15, 16],
        "dst_ports": [502],
        "address_range": (4000, 4499),
        "action":    "STOP high-lift pumps — switch to backup supply — alert operations",
        "zone":      "High-Lift Pumping",
        "mitre":     ["T0836", "T0855"],
        "remediation": [
            "1. Switch high-lift supply to backup/gravity feed if available",
            "2. Stop high-lift pumps via local panel override",
            "3. Notify operations and distribution team",
            "4. Audit PLC access logs for session origin",
        ],
        "violations": [
            "AWWA: Water distribution pressure control tampered",
        ]
    },

    # ── GENERAL ICS RULES ─────────────────────────────────────────────────────
    {
        "id":        "ICS-001",
        "name":      "ICS Port Access from External (Non-RFC1918) IP",
        "severity":  "CRITICAL",
        "protocol":  "ANY",
        "fc_codes":  None,
        "dst_ports": [502, 20000, 44818, 2404, 47808, 102],
        "condition_fn": None,  # handled by ThreatScore>=90 in packet anomaly detection
        "action":    "BLOCK source IP — alert SOC — initiate incident response",
        "zone":      "ANY",
        "mitre":     ["T0883", "T0846", "T0888"],
        "remediation": [
            "1. Immediately block source IP in perimeter firewall",
            "2. Capture and preserve full PCAP session",
            "3. Alert SOC and ICS security team",
            "4. Determine if ICS protocol session was established",
            "5. If session established: treat as active compromise — initiate IR playbook",
        ],
        "violations": [
            "NERC CIP-005: Electronic Security Perimeter breach",
            "IEC 62443-3-3: SR 5.1 Network segmentation violation",
        ]
    },
    {
        "id":        "ICS-002",
        "name":      "Modbus Broadcast Scan (Unit ID 0 or 255)",
        "severity":  "HIGH",
        "protocol":  "Modbus",
        "fc_codes":  None,
        "dst_ports": [502],
        "condition_fn": lambda p: p.get("ICSAddress") in (0, 255),
        "action":    "ALERT — network reconnaissance of Modbus devices detected",
        "zone":      "ANY",
        "mitre":     ["T0846", "T0888"],
        "remediation": [
            "1. Alert SOC of active reconnaissance",
            "2. Review recent access logs for the source IP",
            "3. Consider blocking source IP if not in authorized scanner list",
            "4. Audit Modbus slave devices for unauthorized configuration changes",
        ],
        "violations": [
            "IEC 62443: Unauthorized discovery of ICS network topology",
            "NIST SP 800-82: OT network scanning",
        ]
    },
    {
        "id":        "ICS-003",
        "name":      "IEC-104 Control Command to Remote Terminal Unit",
        "severity":  "CRITICAL",
        "protocol":  "IEC-104",
        "fc_codes":  list(range(45, 52)) + [100, 101, 103, 107],
        "dst_ports": [2404],
        "action":    "REJECT command — log session — verify master station identity",
        "zone":      "RTU/SCADA",
        "mitre":     ["T0855", "T0836"],
        "remediation": [
            "1. Verify IEC-104 master station IP against whitelist",
            "2. If not whitelisted: block IP and initiate incident response",
            "3. Check RTU for any unintended setpoint changes",
            "4. Enable IEC-104 authentication if RTU supports it (IEC 62351-5)",
        ],
        "violations": [
            "IEC 62351-5: Unauthenticated IEC-104 control command",
            "NERC CIP: Unauthorized command to protection RTU",
        ]
    },
    {
        "id":        "ICS-004",
        "name":      "EtherNet/IP Write Tag to PLC from Unknown Source",
        "severity":  "HIGH",
        "protocol":  "EtherNet/IP",
        "fc_codes":  [0x4D, 0x4F],  # Write_Tag, Write_Tag_Fragmented
        "dst_ports": [44818, 2222],
        "action":    "BLOCK source — alert PLC owner — verify tag integrity",
        "zone":      "PLC Network",
        "mitre":     ["T0855", "T0836"],
        "remediation": [
            "1. Verify source IP against authorized EtherNet/IP engineering workstation list",
            "2. If unauthorized: block in managed switch ACL",
            "3. Review PLC tag database for recent modifications",
            "4. Export and compare PLC project file against known-good backup",
        ],
        "violations": [
            "IEC 62443: Unauthorized PLC parameter modification",
            "NIST SP 800-82: Logic modification attempt",
        ]
    },
    {
        "id":        "ICS-005",
        "name":      "Multiple Modbus Write Operations in Short Time Window (Burst Attack)",
        "severity":  "CRITICAL",
        "protocol":  "Modbus",
        "fc_codes":  [5, 6, 15, 16],
        "dst_ports": [502],
        "condition_fn": None,   # evaluated by burst detector in capture thread
        "action":    "RATE LIMIT source — alert — consider emergency control isolation",
        "zone":      "ANY",
        "mitre":     ["T0831", "T0836", "T0855"],
        "remediation": [
            "1. Verify if automated process is causing burst (normal operational pattern?)",
            "2. If abnormal: rate-limit or block source IP",
            "3. Review process historian for abnormal setpoint changes",
            "4. Engage manual local control if process integrity uncertain",
        ],
        "violations": [
            "IEC 62443: Flooding attack against ICS field devices",
        ]
    },

    # ── AUTHENTICATION & NETWORK RULES ────────────────────────────────────────
    {
        "id":        "NET-001",
        "name":      "SSH Brute Force Against Engineering Workstation",
        "severity":  "HIGH",
        "protocol":  "SSH",
        "fc_codes":  None,
        "dst_ports": [22],
        "condition_fn": None,   # triggered when AUTH fail count > 10
        "action":    "BLOCK source IP — alert engineer — review for lateral movement",
        "zone":      "Engineering",
        "mitre":     ["T1110", "T1110.001"],
        "remediation": [
            "1. Block source IP in perimeter and internal firewalls",
            "2. Review SSH logs for session establishment",
            "3. Audit engineering workstation for unauthorized changes",
            "4. Check if credentials were used on other systems",
        ],
        "violations": [
            "NERC CIP-007: Attempted unauthorized access to critical cyber asset",
        ]
    },
    {
        "id":        "NET-002",
        "name":      "Suspicious Command Executed on ICS Host",
        "severity":  "CRITICAL",
        "protocol":  "SYS",
        "fc_codes":  None,
        "dst_ports": None,
        "condition_fn": None,
        "action":    "ISOLATE host — preserve memory image — initiate forensic response",
        "zone":      "ANY",
        "mitre":     ["T0807", "T0871", "T1059.004"],
        "remediation": [
            "1. Immediately isolate host from network (unplug switch port)",
            "2. Preserve volatile memory image before power cycle",
            "3. Initiate forensic investigation before touching system",
            "4. Determine if ICS processes were affected",
            "5. Restore from known-good image after forensic review",
        ],
        "violations": [
            "NERC CIP-007: Malicious code event on critical cyber asset",
            "IEC 62443: Command injection in ICS operator environment",
        ]
    },
]

# Build lookup index
_RULE_INDEX = {r["id"]: r for r in SIS_RULES}


# ─────────────────────────────────────────────────────────────────────────────
# SIS Trip Engine
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_packet(pkt_record: dict) -> list[dict]:
    """
    Evaluate a decoded packet record against all SIS rules.
    Returns a list of triggered SIS event dicts (empty if no rules fired).
    """
    triggered = []
    proto     = pkt_record.get("ICSProtocol") or pkt_record.get("Protocol","")
    fc        = pkt_record.get("ICSFunctionCode")
    dst_port  = pkt_record.get("DstPort", 0) or 0
    ics_addr  = pkt_record.get("ICSAddress")
    threat    = pkt_record.get("ThreatScore", 0)

    for rule in SIS_RULES:
        # Protocol check
        if rule["protocol"] not in ("ANY", "SYS") and rule["protocol"] != proto:
            continue

        # Port check
        if rule.get("dst_ports") and dst_port not in rule["dst_ports"]:
            continue

        # Function code check
        if rule.get("fc_codes") and (fc is None or fc not in rule["fc_codes"]):
            continue

        # Address range check
        if rule.get("address_range") and ics_addr is not None:
            lo, hi = rule["address_range"]
            if not (lo <= ics_addr <= hi):
                continue

        # Custom condition
        if rule.get("condition_fn") and not rule["condition_fn"](pkt_record):
            continue

        # External IP check for ICS-001
        if rule["id"] == "ICS-001" and threat < 90:
            continue

        # FIRE the rule
        sis_event = {
            "RuleId":          rule["id"],
            "RuleName":        rule["name"],
            "Severity":        rule["severity"],
            "TriggerProtocol": proto,
            "TriggerFunction": pkt_record.get("ICSFunctionName",""),
            "TriggerAddress":  ics_addr,
            "TriggerValue":    pkt_record.get("ICSValue",""),
            "SrcIp":           pkt_record.get("SrcIp",""),
            "DstIp":           pkt_record.get("DstIp",""),
            "AffectedZone":    rule.get("zone","ANY"),
            "Action":          rule["action"],
            "ActionTaken":     False,
            "Violations":      rule.get("violations",[]),
            "MitreIds":        ",".join(rule.get("mitre",[])),
            "Remediation":     rule.get("remediation",[]),
        }
        triggered.append(sis_event)
        log.warning("SIS TRIP: rule=%s name='%s' src=%s dst=%s fc=%s",
                    rule["id"], rule["name"],
                    pkt_record.get("SrcIp","?"), pkt_record.get("DstIp","?"), fc)

    return triggered


def evaluate_log_event(event: dict) -> list[dict]:
    """Evaluate a parsed log event dict against SIS rules."""
    triggered = []
    etype    = event.get("EventType","")
    severity = event.get("Severity","LOW")

    for rule in SIS_RULES:
        if rule["protocol"] != "SYS" and etype not in ("SUSPICIOUS_COMMAND","AUTH"):
            continue
        if rule["id"] == "NET-002" and etype == "SUSPICIOUS_COMMAND":
            sis_event = {
                "RuleId":          rule["id"],
                "RuleName":        rule["name"],
                "Severity":        rule["severity"],
                "TriggerProtocol": "SYS",
                "TriggerFunction": etype,
                "TriggerAddress":  None,
                "TriggerValue":    event.get("Message","")[:200],
                "SrcIp":           event.get("SourceIp",""),
                "DstIp":           event.get("DestIp",""),
                "AffectedZone":    rule.get("zone","ANY"),
                "Action":          rule["action"],
                "ActionTaken":     False,
                "Violations":      rule.get("violations",[]),
                "MitreIds":        ",".join(rule.get("mitre",[])),
                "Remediation":     rule.get("remediation",[]),
            }
            triggered.append(sis_event)

    return triggered


def get_all_rules() -> list[dict]:
    """Return all SIS rules for display in dashboard."""
    return [
        {
            "id":        r["id"],
            "name":      r["name"],
            "severity":  r["severity"],
            "protocol":  r["protocol"],
            "zone":      r.get("zone","ANY"),
            "action":    r["action"],
            "mitre":     r.get("mitre",[]),
            "violations":r.get("violations",[]),
        }
        for r in SIS_RULES
    ]
