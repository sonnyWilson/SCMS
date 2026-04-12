"""
parser.py — Secure Continuous Monitoring System
Full ICS protocol parser: Modbus, DNP3, EtherNet/IP, IEC-104, BACnet, S7comm.
Includes anomaly detection, MITRE ATT&CK ICS mapping, and packet-to-log correlation.
"""
import re, struct, logging
from datetime import datetime, timezone

log = logging.getLogger("scms.parser")

MODBUS_FC = {1:"Read Coils",2:"Read Discrete Inputs",3:"Read Holding Registers",
    4:"Read Input Registers",5:"Write Single Coil",6:"Write Single Register",
    7:"Read Exception Status",8:"Diagnostics",11:"Get Comm Event Counter",
    15:"Write Multiple Coils",16:"Write Multiple Registers",17:"Report Server ID",
    20:"Read File Record",21:"Write File Record",22:"Mask Write Register",
    23:"Read/Write Multiple Registers",43:"Encapsulated Interface",
    129:"ERR:Read Coils",130:"ERR:Read Discrete",131:"ERR:Read Holding",
    132:"ERR:Read Input",133:"ERR:Write Coil",134:"ERR:Write Register",
    144:"ERR:Write Coils",145:"ERR:Write Registers"}

DNP3_FC = {0:"CONFIRM",1:"READ",2:"WRITE",3:"SELECT",4:"OPERATE",5:"DIRECT_OPERATE",
    6:"DIRECT_OPERATE_NR",7:"IMMED_FREEZE",8:"IMMED_FREEZE_NR",9:"FREEZE_CLEAR",
    10:"FREEZE_CLEAR_NR",11:"FREEZE_AT_TIME",12:"FREEZE_AT_TIME_NR",
    13:"COLD_RESTART",14:"WARM_RESTART",15:"INITIALIZE_DATA",16:"INITIALIZE_APPL",
    17:"START_APPL",18:"STOP_APPL",19:"SAVE_CONFIG",20:"ENABLE_UNSOLICITED",
    21:"DISABLE_UNSOLICITED",22:"ASSIGN_CLASS",23:"DELAY_MEASURE",
    129:"RESPONSE",130:"UNSOLICITED_RESPONSE"}

DNP3_DANGEROUS = {3,4,5,6,13,14,15,16,17,18,19}

ENIP_SVC = {0x01:"Get_Attributes_All",0x05:"Reset",0x06:"Start",0x07:"Stop",
    0x0E:"Get_Attribute_Single",0x10:"Set_Attribute_Single",
    0x4C:"Read_Tag",0x4D:"Write_Tag",0x4E:"Read_Tag_Frag",0x4F:"Write_Tag_Frag",
    0x65:"RegisterSession",0x66:"UnRegisterSession",0x6F:"SendRRData",0x70:"SendUnitData"}

IEC104_TYPES = {1:"M_SP_NA_1",3:"M_DP_NA_1",9:"M_ME_NA_1",11:"M_ME_NB_1",
    13:"M_ME_NC_1",30:"M_SP_TB_1",45:"C_SC_NA_1",46:"C_DC_NA_1",47:"C_RC_NA_1",
    48:"C_SE_NA_1",49:"C_SE_NB_1",50:"C_SE_NC_1",100:"C_IC_NA_1",
    103:"C_CS_NA_1",107:"C_TS_TA_1"}
IEC104_CMDS = {45,46,47,48,49,50,51,100,101,103,107,110,111,112,113}

ICS_PORTS = {502:"Modbus",20000:"DNP3",44818:"EtherNet/IP",2404:"IEC-104",
    47808:"BACnet",102:"S7comm",4000:"PROFINET",9600:"OMRON-FINS",
    1911:"NiagaraFox",18245:"GE-SRTP",2222:"EtherNet/IP-Implicit"}

MITRE_ICS = {
    "Modbus_WRITE":["T0836","T0855","T0831"],
    "DNP3_CTRL":["T0855","T0831"],
    "DNP3_RESTART":["T0816","T0813"],
    "ENIP_WRITE":["T0855","T0836"],
    "IEC104_CMD":["T0855","T0836"],
    "SCAN":["T0846","T0888"],
    "AUTH_FAIL":["T1110","T1110.001"],
    "SUSPICIOUS":["T0807","T0871"],
}

def parse(line:str, source_type:str="SYS") -> dict|None:
    if not line or not line.strip(): return None
    orig = line.strip(); lower = orig.lower()
    if any(x in line for x in ["sshd","sudo","systemd"]):
        if orig.startswith("--") or "logs begin" in lower or "no entries" in lower: return None
    if any(x in lower for x in ["type=proctitle","type=path","type=syscall","type=execve","msg=audit("]): return None
    event = {"EventTime":datetime.now(timezone.utc).isoformat(),"EventType":"SYS",
        "Success":1,"UserName":None,"SourceIp":None,"DestIp":None,"Protocol":None,"Port":None,
        "Message":orig[:700],"RawLine":orig,"Severity":"LOW","MitreIds":None,"SiteZone":None}
    for pat in [r'from\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})',r'rhost=([0-9]{1,3}(?:\.[0-9]{1,3}){3})',
        r'addr=([0-9]{1,3}(?:\.[0-9]{1,3}){3})',r'src[= ]([0-9]{1,3}(?:\.[0-9]{1,3}){3})',r'\b(127\.0\.0\.1|::1)\b']:
        m=re.search(pat,lower)
        if m:
            cap=m.group(1) if m.lastindex and m.group(1) else m.group(0)
            event["SourceIp"]="127.0.0.1" if cap in ("127.0.0.1","::1") else cap; break
    dm=re.search(r'dst[= ]([0-9]{1,3}(?:\.[0-9]{1,3}){3})',lower)
    if dm: event["DestIp"]=dm.group(1)
    pm=re.search(r'(?:port|dport|sport)[= ](\d+)',lower)
    if pm: event["Port"]=int(pm.group(1))
    for pat in [r'failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+)',
        r'accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+)',
        r'authentication failure.*user=([a-zA-Z0-9_\-\.]+)',r'sudo:\s+([a-zA-Z0-9_\-\.]+)\s*:',
        r'for user ([a-zA-Z0-9_\-\.]+)']:
        m=re.search(pat,lower)
        if m:
            c=m.group(1)
            if c not in {"user","invalid","unknown","from","port","ssh2","tty"}: event["UserName"]=c; break
    if "failed password" in lower or "authentication failure" in lower or "invalid user" in lower:
        event["EventType"]="AUTH"; event["Success"]=0; event["Severity"]="HIGH"; event["MitreIds"]="T1110,T1110.001"
    elif "accepted password" in lower or "accepted publickey" in lower:
        event["EventType"]="AUTH"
    elif "sudo:" in lower:
        event["EventType"]="SUDO"; event["Severity"]="HIGH"; event["MitreIds"]="T1548.003"
        if any(x in lower for x in ["sudo -l","/etc/sudoers","/etc/shadow"]): event["Success"]=0; event["Severity"]="CRITICAL"
    elif any(p in lower for p in ["bash -i","/dev/tcp","nc -e","rm -rf","history -c","unset histfile",
        "histsize=0","cat /etc/shadow",":(){ :|:& };:"]):
        event["EventType"]="SUSPICIOUS_COMMAND"; event["Success"]=0; event["Severity"]="CRITICAL"; event["MitreIds"]="T1059.004,T0807"
    elif re.match(r'^\d{4}-\d{2}-\d{2}',orig) or "bash_cmd:" in lower:
        event["EventType"]="BASH_HISTORY"
    if "modbus" in lower: event["EventType"]="ICS_MODBUS"; event["Protocol"]="Modbus"; event["Severity"]="HIGH"
    elif "dnp3" in lower: event["EventType"]="ICS_DNP3"; event["Protocol"]="DNP3"; event["Severity"]="HIGH"
    elif "ethernet/ip" in lower or "enip" in lower: event["EventType"]="ICS_ENIP"; event["Protocol"]="EtherNet/IP"; event["Severity"]="HIGH"
    elif "iec104" in lower or "iec-104" in lower: event["EventType"]="ICS_IEC104"; event["Protocol"]="IEC-104"; event["Severity"]="HIGH"
    elif "bacnet" in lower: event["EventType"]="ICS_BACNET"; event["Protocol"]="BACnet"; event["Severity"]="MEDIUM"
    elif "s7comm" in lower or "siemens s7" in lower: event["EventType"]="ICS_S7"; event["Protocol"]="S7comm"; event["Severity"]="HIGH"
    elif "profinet" in lower: event["EventType"]="ICS_PROFINET"; event["Protocol"]="PROFINET"; event["Severity"]="MEDIUM"
    return event

def parse_packet(pkt_dict:dict) -> dict:
    payload_raw=pkt_dict.get("payload_bytes",b"")
    if isinstance(payload_raw,str):
        try: payload_raw=bytes.fromhex(payload_raw.replace(" ","").replace(":",""))
        except: payload_raw=b""
    dst_port=int(pkt_dict.get("dst_port",0) or 0)
    src_port=int(pkt_dict.get("src_port",0) or 0)
    protocol=(pkt_dict.get("protocol","TCP") or "TCP").upper()
    record={"SrcIp":pkt_dict.get("src_ip",""),"DstIp":pkt_dict.get("dst_ip",""),
        "SrcPort":src_port,"DstPort":dst_port,"Protocol":protocol,
        "Length":int(pkt_dict.get("length",0) or 0),"TTL":int(pkt_dict.get("ttl",64) or 64),
        "Flags":pkt_dict.get("flags",""),"Interface":pkt_dict.get("interface","eth0"),
        "Payload":payload_raw[:512].decode("latin-1",errors="replace"),
        "PayloadHex":payload_raw[:256].hex(),"RawHex":payload_raw.hex(),
        "ICSProtocol":None,"ICSFunctionCode":None,"ICSFunctionName":None,
        "ICSAddress":None,"ICSValue":None,"Anomaly":False,"AnomalyReason":None,"ThreatScore":0}
    ics_proto=ICS_PORTS.get(dst_port) or ICS_PORTS.get(src_port)
    if ics_proto: record["ICSProtocol"]=ics_proto
    if dst_port==502 or src_port==502: record=_decode_modbus(record,payload_raw)
    elif dst_port==20000 or src_port==20000: record=_decode_dnp3(record,payload_raw)
    elif dst_port in (44818,2222) or src_port in (44818,2222): record=_decode_enip(record,payload_raw)
    elif dst_port==2404 or src_port==2404: record=_decode_iec104(record,payload_raw)
    record=_detect_anomalies(record,pkt_dict)
    return record

def _decode_modbus(record,payload):
    record["ICSProtocol"]="Modbus"
    if len(payload)<8: return record
    try:
        trans_id,proto_id,length,unit_id=struct.unpack(">HHHB",payload[:7])
        if proto_id!=0: return record
        fc=payload[7]; record["ICSFunctionCode"]=fc; record["ICSFunctionName"]=MODBUS_FC.get(fc,f"FC{fc}")
        record["ICSAddress"]=unit_id; data=payload[8:]
        if fc in (3,4) and len(data)>=4:
            s=struct.unpack(">H",data[:2])[0]; c=struct.unpack(">H",data[2:4])[0]
            record["ICSValue"]=f"start={s} count={c}"
        elif fc==6 and len(data)>=4:
            a=struct.unpack(">H",data[:2])[0]; v=struct.unpack(">H",data[2:4])[0]
            record["ICSValue"]=f"addr={a} value={v}"; record["ThreatScore"]+=30
        elif fc==5 and len(data)>=4:
            a=struct.unpack(">H",data[:2])[0]; v=struct.unpack(">H",data[2:4])[0]
            record["ICSValue"]=f"addr={a} coil={'ON' if v==0xFF00 else 'OFF'}"; record["ThreatScore"]+=40
        elif fc in (15,16) and len(data)>=2:
            a=struct.unpack(">H",data[:2])[0]; record["ICSValue"]=f"start={a}"; record["ThreatScore"]+=35
        if fc>128:
            ec=data[0] if data else 0
            record["ICSValue"]=f"exception={ec}"; record["Anomaly"]=True
            record["AnomalyReason"]=f"Modbus exception FC{fc-128} code={ec}"
    except Exception as e: log.debug("Modbus: %s",e)
    return record

def _decode_dnp3(record,payload):
    record["ICSProtocol"]="DNP3"
    if len(payload)<10: return record
    try:
        if payload[0]==0x05 and payload[1]==0x64:
            dst=struct.unpack("<H",payload[4:6])[0]; src=struct.unpack("<H",payload[6:8])[0]
            record["ICSAddress"]=dst
            if len(payload)>=12:
                fc=payload[11]; record["ICSFunctionCode"]=fc
                fname=DNP3_FC.get(fc,f"FC{fc}"); record["ICSFunctionName"]=fname
                record["ICSValue"]=f"src={src} dst={dst} {fname}"
                if fc in DNP3_DANGEROUS: record["ThreatScore"]+=50
                if fc in (13,14):
                    record["ThreatScore"]+=80; record["Anomaly"]=True
                    record["AnomalyReason"]=f"DNP3 {fname} — device restart"
    except Exception as e: log.debug("DNP3: %s",e)
    return record

def _decode_enip(record,payload):
    record["ICSProtocol"]="EtherNet/IP"
    if len(payload)<24: return record
    try:
        cmd=struct.unpack("<H",payload[0:2])[0]; session=struct.unpack("<I",payload[4:8])[0]
        status=struct.unpack("<I",payload[8:12])[0]
        svc=ENIP_SVC.get(cmd,f"CMD_0x{cmd:02X}")
        record["ICSFunctionCode"]=cmd; record["ICSFunctionName"]=svc
        record["ICSValue"]=f"cmd={svc} session=0x{session:08X} status={status}"
        if cmd in (0x4D,0x4F): record["ThreatScore"]+=35
        if status!=0: record["Anomaly"]=True; record["AnomalyReason"]=f"EtherNet/IP error status=0x{status:08X}"
    except Exception as e: log.debug("EtherNet/IP: %s",e)
    return record

def _decode_iec104(record,payload):
    record["ICSProtocol"]="IEC-104"
    if len(payload)<6 or payload[0]!=0x68: return record
    try:
        ctrl1=payload[2]
        if ctrl1 & 0x01==0 and len(payload)>=12:
            tid=payload[6]; cause=struct.unpack("<H",payload[8:10])[0]
            addr=struct.unpack("<H",payload[10:12])[0]
            tname=IEC104_TYPES.get(tid,f"TypeID_{tid}")
            record["ICSFunctionCode"]=tid; record["ICSFunctionName"]=tname
            record["ICSAddress"]=addr; record["ICSValue"]=f"type={tname} cause={cause} addr={addr}"
            if tid in IEC104_CMDS:
                record["ThreatScore"]+=60
                if cause in (6,7): record["Anomaly"]=True; record["AnomalyReason"]=f"IEC-104 control {tname} cause={cause}"
        elif ctrl1==0x03:
            d={0x07:"STARTDT_ACT",0x0B:"STARTDT_CON",0x13:"STOPDT_ACT",0x23:"STOPDT_CON",0x43:"TESTFR_ACT",0x83:"TESTFR_CON"}
            record["ICSFunctionName"]=d.get(payload[3],"U-frame")
    except Exception as e: log.debug("IEC-104: %s",e)
    return record

def _detect_anomalies(record,original_pkt):
    dst_port=record.get("DstPort",0) or 0; src_ip=record.get("SrcIp","") or ""
    flags=(record.get("Flags","") or "").upper(); length=record.get("Length",0) or 0
    if dst_port in ICS_PORTS and not _is_private_ip(src_ip):
        record["Anomaly"]=True
        record["AnomalyReason"]=(record.get("AnomalyReason","") or "")+f"; ICS port {dst_port} from external IP {src_ip}"
        record["ThreatScore"]+=90
    if flags=="" and record.get("Protocol")=="TCP":
        record["Anomaly"]=True; record["AnomalyReason"]=(record.get("AnomalyReason","") or "")+"; TCP NULL scan"
        record["ThreatScore"]+=20
    if record.get("ICSProtocol")=="Modbus" and record.get("ICSAddress")==0:
        record["Anomaly"]=True; record["AnomalyReason"]=(record.get("AnomalyReason","") or "")+"; Modbus broadcast unit=0"
        record["ThreatScore"]+=15
    record["ThreatScore"]=min(record.get("ThreatScore",0),100)
    return record

def _is_private_ip(ip:str) -> bool:
    if not ip: return True
    try:
        import ipaddress; a=ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except: return True

def correlate_packet_to_event(pkt_record:dict) -> dict:
    ics=pkt_record.get("ICSProtocol"); fc=pkt_record.get("ICSFunctionCode")
    anom=pkt_record.get("Anomaly",False); threat=pkt_record.get("ThreatScore",0)
    etype_map={"Modbus":"ICS_MODBUS","DNP3":"ICS_DNP3","EtherNet/IP":"ICS_ENIP","IEC-104":"ICS_IEC104"}
    etype=etype_map.get(ics,"NETWORK_ANOMALY" if anom else "NETWORK")
    sev="CRITICAL" if threat>=80 else ("HIGH" if threat>=50 else ("MEDIUM" if threat>=20 else "LOW"))
    mitre=None
    if ics=="Modbus" and fc in (5,6,15,16): mitre=",".join(["T0836","T0855","T0831"])
    elif ics=="DNP3" and fc in DNP3_DANGEROUS: mitre=",".join(["T0855","T0831"])
    elif ics=="IEC-104" and fc in IEC104_CMDS: mitre=",".join(["T0855","T0836"])
    fn=pkt_record.get("ICSFunctionName",""); iv=pkt_record.get("ICSValue","")
    msg=(f"[{ics or pkt_record.get('Protocol','PKT')}] "
         f"{pkt_record.get('SrcIp','')}:{pkt_record.get('SrcPort','')} → "
         f"{pkt_record.get('DstIp','')}:{pkt_record.get('DstPort','')}")
    if fn: msg+=f" | {fn}"
    if iv: msg+=f" | {iv}"
    if anom: msg+=f" | ANOMALY: {pkt_record.get('AnomalyReason','')}"
    return {"EventTime":datetime.now(timezone.utc).isoformat(),"EventType":etype,
        "Success":0 if anom else 1,"SourceIp":pkt_record.get("SrcIp"),
        "DestIp":pkt_record.get("DstIp"),"Protocol":ics or pkt_record.get("Protocol"),
        "Port":pkt_record.get("DstPort"),"Message":msg[:700],
        "RawLine":pkt_record.get("PayloadHex","")[:700],"Severity":sev,"MitreIds":mitre}
