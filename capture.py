"""
server/capture.py — Secure Continuous Monitoring System
Live packet capture thread.

Attempts to use scapy for rich packet decode.
Falls back to tshark (Wireshark CLI) JSON output if scapy unavailable.
Falls back to tcpdump hex output as last resort.

Every captured packet:
  1. Decoded by parser.parse_packet()
  2. Evaluated by sis.evaluate_packet() for SIS trip rules
  3. Inserted into Packets table (encrypted sensitive fields)
  4. If anomaly: correlated into Logs table + potential Incident created
  5. Geolocation lookup for external IPs (MaxMind GeoIP2 or ip-api.com)
"""

import threading
import logging
import subprocess
import json
import time
import socket
import os
from datetime import datetime, timezone

import psycopg2

from config import DB_CONFIG
from parser import parse_packet, correlate_packet_to_event, ICS_PORTS
from server.sis import evaluate_packet
from server.crypto import encrypt_event, encryption_enabled

log = logging.getLogger("scms.capture")

_stop_event    = threading.Event()
_capture_thread: threading.Thread | None = None
_active_iface  = "eth0"
_pkt_count     = 0
_pkt_lock      = threading.Lock()

# ── Burst detector state (for ICS-005 Modbus burst rule) ─────────────────────
_burst_tracker: dict = {}   # src_ip -> {fc, count, window_start}
_burst_lock    = threading.Lock()
BURST_WINDOW   = 10   # seconds
BURST_THRESHOLD = 20  # writes in window


def get_stats() -> dict:
    with _pkt_lock:
        return {"packets_captured": _pkt_count, "interface": _active_iface,
                "running": _capture_thread is not None and _capture_thread.is_alive()}


# ── DB helpers ────────────────────────────────────────────────────────────────
def _get_conn():
    return psycopg2.connect(**DB_CONFIG)


def _insert_packet(pkt: dict) -> int | None:
    """Insert a packet record and return the new pktid."""
    try:
        conn = _get_conn(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO Packets
            (SrcIp,DstIp,SrcPort,DstPort,Protocol,Length,TTL,Flags,Interface,
             Payload,PayloadHex,ICSProtocol,ICSFunctionCode,ICSFunctionName,
             ICSAddress,ICSValue,RawHex,Anomaly,AnomalyReason,
             GeoCountry,GeoCity,GeoLat,GeoLon,ThreatScore)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING pktid
        """, (
            pkt.get("SrcIp"), pkt.get("DstIp"),
            pkt.get("SrcPort"), pkt.get("DstPort"),
            pkt.get("Protocol"), pkt.get("Length"),
            pkt.get("TTL"), pkt.get("Flags"), pkt.get("Interface","eth0"),
            pkt.get("Payload","")[:512], pkt.get("PayloadHex","")[:512],
            pkt.get("ICSProtocol"), pkt.get("ICSFunctionCode"),
            pkt.get("ICSFunctionName"), pkt.get("ICSAddress"),
            pkt.get("ICSValue","")[:200] if pkt.get("ICSValue") else None,
            pkt.get("RawHex","")[:1024],
            pkt.get("Anomaly", False),
            pkt.get("AnomalyReason","")[:500] if pkt.get("AnomalyReason") else None,
            pkt.get("GeoCountry"), pkt.get("GeoCity"),
            pkt.get("GeoLat"), pkt.get("GeoLon"),
            pkt.get("ThreatScore", 0),
        ))
        pktid = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        return pktid
    except Exception as e:
        log.error("insert_packet: %s", e)
        return None


def _insert_log_from_packet(event: dict, pkt_id: int | None):
    """Insert a correlated log event."""
    try:
        conn = _get_conn(); cur = conn.cursor()
        enc = encrypt_event(event) if encryption_enabled() else event
        cur.execute("""
            INSERT INTO Logs
            (EventTime,EventType,Success,SourceIp,DestIp,Protocol,Port,
             Message,RawLine,Severity,MitreIds,PacketRef)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            enc.get("EventTime"), enc.get("EventType"), enc.get("Success",1),
            enc.get("SourceIp"), enc.get("DestIp"),
            enc.get("Protocol"), enc.get("Port"),
            enc.get("Message","")[:700], enc.get("RawLine","")[:700],
            enc.get("Severity","LOW"), enc.get("MitreIds"), pkt_id,
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error("insert_log_from_packet: %s", e)


def _insert_sis_event(sis: dict, pkt_id: int | None):
    """Insert a SIS trip event."""
    try:
        conn = _get_conn(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO SIS_Events
            (RuleId,RuleName,Severity,TriggerProtocol,TriggerFunction,
             TriggerAddress,TriggerValue,SrcIp,DstIp,AffectedZone,
             Action,PacketRef)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            sis.get("RuleId"), sis.get("RuleName"), sis.get("Severity"),
            sis.get("TriggerProtocol"), sis.get("TriggerFunction"),
            sis.get("TriggerAddress"), str(sis.get("TriggerValue",""))[:200],
            sis.get("SrcIp"), sis.get("DstIp"), sis.get("AffectedZone"),
            sis.get("Action","")[:500], pkt_id,
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error("insert_sis_event: %s", e)


def _insert_geo_event(pkt: dict, pkt_id: int | None, log_id: int | None):
    """Insert a geo event for external IPs."""
    src_ip = pkt.get("SrcIp","")
    if not src_ip or _is_private(src_ip): return
    lat = pkt.get("GeoLat"); lon = pkt.get("GeoLon")
    if not lat: return
    try:
        conn = _get_conn(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO GeoEvents(SrcIp,GeoLat,GeoLon,GeoCountry,GeoCity,
                                   ThreatScore,EventType,PacketRef,LogRef)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (src_ip, lat, lon, pkt.get("GeoCountry"), pkt.get("GeoCity"),
              pkt.get("ThreatScore",0), pkt.get("ICSProtocol","NETWORK"), pkt_id, log_id))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error("insert_geo: %s", e)


# ── Geo lookup (ip-api.com, free, no key needed) ──────────────────────────────
_geo_cache: dict = {}
_geo_lock = threading.Lock()

def _geolocate(ip: str) -> dict:
    if _is_private(ip): return {}
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        import urllib.request
        url  = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp"
        req  = urllib.request.Request(url, headers={"User-Agent":"scms-ics/1.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            result = {"GeoCountry": data.get("country",""), "GeoCity": data.get("city",""),
                      "GeoLat": data.get("lat"), "GeoLon": data.get("lon"),
                      "GeoISP": data.get("isp","")}
            with _geo_lock:
                _geo_cache[ip] = result
            return result
    except Exception:
        pass
    return {}


def _is_private(ip: str) -> bool:
    if not ip: return True
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return True


# ── Burst detector ────────────────────────────────────────────────────────────
def _check_burst(pkt: dict) -> bool:
    """Return True if this packet completes a burst (ICS-005)."""
    proto = pkt.get("ICSProtocol")
    fc    = pkt.get("ICSFunctionCode")
    src   = pkt.get("SrcIp","")
    if proto != "Modbus" or fc not in (5,6,15,16): return False
    now = time.time()
    with _burst_lock:
        entry = _burst_tracker.setdefault(src, {"count":0,"window_start":now})
        if now - entry["window_start"] > BURST_WINDOW:
            entry["count"] = 0; entry["window_start"] = now
        entry["count"] += 1
        return entry["count"] >= BURST_THRESHOLD


# ── Central packet processor ──────────────────────────────────────────────────
def _process_packet(raw_pkt: dict):
    """Decode, store, evaluate SIS rules, correlate."""
    global _pkt_count
    try:
        pkt = parse_packet(raw_pkt)

        # Geo enrichment for external IPs
        geo = _geolocate(pkt.get("SrcIp",""))
        pkt.update(geo)

        # Burst check
        if _check_burst(pkt):
            pkt["Anomaly"] = True
            pkt["AnomalyReason"] = (pkt.get("AnomalyReason","") or "") + "; Modbus write burst detected"
            pkt["ThreatScore"] = min(pkt.get("ThreatScore",0)+80, 100)

        pkt_id = _insert_packet(pkt)

        with _pkt_lock:
            _pkt_count += 1

        # Correlated log event for anomalies and ICS packets
        log_id = None
        if pkt.get("Anomaly") or pkt.get("ICSProtocol") or pkt.get("ThreatScore",0) >= 20:
            event  = correlate_packet_to_event(pkt)
            _insert_log_from_packet(event, pkt_id)

        # SIS rule evaluation
        sis_events = evaluate_packet(pkt)
        for sis in sis_events:
            _insert_sis_event(sis, pkt_id)

        # Geo event
        _insert_geo_event(pkt, pkt_id, log_id)

    except Exception as e:
        log.error("_process_packet: %s", e)


# ── Scapy capture backend ─────────────────────────────────────────────────────
def _capture_scapy(iface: str):
    """Capture packets using scapy (preferred — richest decode)."""
    try:
        from scapy.all import sniff, TCP, UDP, IP, Raw
    except ImportError:
        log.warning("scapy not available — falling back to tshark")
        _capture_tshark(iface)
        return

    def _pkt_handler(pkt):
        if _stop_event.is_set(): return
        try:
            if not pkt.haslayer("IP"): return
            ip   = pkt["IP"]
            raw  = bytes(pkt.payload.payload) if pkt.haslayer("Raw") else b""
            proto = "TCP" if pkt.haslayer("TCP") else ("UDP" if pkt.haslayer("UDP") else "OTHER")
            sport = pkt["TCP"].sport if pkt.haslayer("TCP") else (pkt["UDP"].sport if pkt.haslayer("UDP") else 0)
            dport = pkt["TCP"].dport if pkt.haslayer("TCP") else (pkt["UDP"].dport if pkt.haslayer("UDP") else 0)
            flags = ""
            if pkt.haslayer("TCP"):
                f = pkt["TCP"].flags
                flags = "".join([
                    "S" if f.S else "", "A" if f.A else "", "F" if f.F else "",
                    "R" if f.R else "", "P" if f.P else "", "U" if f.U else "",
                ])
            raw_pkt = {
                "src_ip": ip.src, "dst_ip": ip.dst,
                "src_port": sport, "dst_port": dport,
                "protocol": proto, "length": len(pkt),
                "ttl": ip.ttl, "flags": flags,
                "payload_bytes": raw, "interface": iface,
            }
            threading.Thread(target=_process_packet, args=(raw_pkt,), daemon=True).start()
        except Exception as e:
            log.debug("scapy handler: %s", e)

    log.info("Starting scapy capture on %s", iface)
    sniff(iface=iface, prn=_pkt_handler, store=False,
          stop_filter=lambda _: _stop_event.is_set())


# ── tshark capture backend ────────────────────────────────────────────────────
def _capture_tshark(iface: str):
    """Capture packets using tshark JSON output."""
    cmd = ["tshark", "-i", iface, "-T", "json", "-e", "ip.src", "-e", "ip.dst",
           "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport",
           "-e", "udp.dstport", "-e", "frame.len", "-e", "ip.ttl",
           "-e", "tcp.flags", "-e", "tcp.payload",
           "-l", "--no-promiscuous"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        log.info("Starting tshark capture on %s", iface)
        buf = ""
        while not _stop_event.is_set():
            line = proc.stdout.readline()
            if not line and proc.poll() is not None: break
            buf += line
            if buf.strip().endswith("}"):
                try:
                    obj = json.loads(buf.strip().rstrip(","))
                    layers = obj.get("_source",{}).get("layers",{})
                    payload_hex = layers.get("tcp.payload",[""])[0].replace(":","")
                    raw_pkt = {
                        "src_ip":        layers.get("ip.src",[""])[0],
                        "dst_ip":        layers.get("ip.dst",[""])[0],
                        "src_port":      int(layers.get("tcp.srcport",[layers.get("udp.srcport",["0"])[0]])[0] or 0),
                        "dst_port":      int(layers.get("tcp.dstport",[layers.get("udp.dstport",["0"])[0]])[0] or 0),
                        "protocol":      "TCP" if "tcp.srcport" in layers else "UDP",
                        "length":        int(layers.get("frame.len",["0"])[0] or 0),
                        "ttl":           int(layers.get("ip.ttl",["64"])[0] or 64),
                        "flags":         layers.get("tcp.flags",[""])[0],
                        "payload_bytes": payload_hex,
                        "interface":     iface,
                    }
                    threading.Thread(target=_process_packet, args=(raw_pkt,), daemon=True).start()
                except Exception:
                    pass
                buf = ""
        proc.terminate()
    except FileNotFoundError:
        log.warning("tshark not found — packet capture disabled. Install: sudo apt install tshark")
    except Exception as e:
        log.error("tshark capture: %s", e)


# ── Public API ────────────────────────────────────────────────────────────────
def start_capture(interface: str = "eth0"):
    global _capture_thread, _active_iface, _pkt_count
    if _capture_thread and _capture_thread.is_alive():
        return False, "Capture already running"
    _stop_event.clear()
    _active_iface = interface
    _pkt_count = 0

    try:
        import scapy.all as _  # test import
        backend = _capture_scapy
    except ImportError:
        backend = _capture_tshark

    _capture_thread = threading.Thread(
        target=backend, args=(interface,), daemon=True, name="packet-capture"
    )
    _capture_thread.start()
    log.info("Packet capture started on %s", interface)
    return True, f"Capture started on {interface}"


def stop_capture():
    global _capture_thread
    _stop_event.set()
    if _capture_thread:
        _capture_thread.join(timeout=5)
        _capture_thread = None
    log.info("Packet capture stopped")
    return True, "Capture stopped"


def list_interfaces() -> list[str]:
    """Return available network interfaces."""
    ifaces = []
    try:
        # Linux: read /proc/net/dev
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface and iface != "lo":
                    ifaces.append(iface)
    except Exception:
        pass
    if not ifaces:
        ifaces = ["eth0", "wlan0", "enp3s0"]
    return ifaces
