# Secure Continuous Monitoring System (SCMS)

<div align="center">

**Open-source ICS/SCADA SIEM for critical infrastructure**
Real-time packet analysis · Safety Instrumented System enforcement · Incident response · Geographic threat heatmap

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12%2B-336791?logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-green)
![Protocols](https://img.shields.io/badge/Protocols-Modbus%20%C2%B7%20DNP3%20%C2%B7%20EtherNet%2FIP%20%C2%B7%20IEC--104-orange)

</div>

---

SCMS is a self-hosted security monitoring platform built for **power plants**, **water treatment facilities**, and any environment running Industrial Control Systems or SCADA networks. It decodes ICS protocols at the packet level (Modbus TCP, DNP3, EtherNet/IP, IEC 60870-5-104), evaluates every packet against pre-built Safety Instrumented System trip rules, correlates events into full incident records, and visualises attacker geography on a live heatmap — all running on a single Linux machine with PostgreSQL as its only dependency.

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [System Requirements](#system-requirements)
3. [Project Layout](#project-layout)
4. [Installation — Quick Path](#installation--quick-path)
5. [Installation — Manual Step-by-Step](#installation--manual-step-by-step)
6. [Air-Gapped Lab Setup](#air-gapped-lab-setup)
7. [Honeypot Internet Exposure](#honeypot-internet-exposure)
8. [Configuration Reference](#configuration-reference)
9. [Starting Stopping and Status](#starting-stopping-and-status)
10. [First Login](#first-login)
11. [Dashboard Walkthrough](#dashboard-walkthrough)
12. [Packet Capture](#packet-capture)
13. [Safety Instrumented System Rules](#safety-instrumented-system-rules)
14. [Incident Response](#incident-response)
15. [Device Inventory](#device-inventory)
16. [Test Data](#test-data)
17. [Adding Agents to Remote Machines](#adding-agents-to-remote-machines)
18. [Adding Custom SIS Rules](#adding-custom-sis-rules)
19. [TLS and HTTPS Setup](#tls-and-https-setup)
20. [Email Alerts](#email-alerts)
21. [Security Hardening Checklist](#security-hardening-checklist)
22. [Troubleshooting](#troubleshooting)
23. [References and Standards](#references-and-standards)

---

## What It Does

| Capability | Detail |
|---|---|
| **Live packet capture** | Scapy or tshark backend; SPAN/mirror port or direct interface |
| **ICS protocol decode** | Modbus TCP, DNP3, EtherNet/IP (CIP), IEC 60870-5-104, BACnet, S7comm |
| **SIS trip rules** | 14 pre-built rules — turbine, generator, chemical dosing, pump station, RTU restart, external access |
| **Incident response** | Structured IR records with timeline, violations, MITRE IDs, remediation steps |
| **Device inventory** | Auto-populated registry of every networked device with ICS metadata |
| **Geographic heatmap** | Attacker source IP geolocation plotted on a live world map |
| **Host log monitoring** | Auth events, sudo, suspicious commands, bash history, journal units |
| **File integrity monitoring** | SHA-256 baseline comparison for critical system files |
| **Configuration audit** | 32 CIS Benchmark checks mapped to PCI-DSS, HIPAA, and NIST CSF |
| **Vulnerability scanner** | CVE matching against installed packages (NVD live + offline baseline) |
| **MITRE ATT&CK for ICS** | Automatic technique correlation on every event and packet |
| **Honeypot integration** | Agent ingests Conpot logs; honeypot flag on inventory devices |
| **Data-at-rest encryption** | AES-256-GCM on sensitive database fields |
| **Dashboard authentication** | bcrypt login, CSRF protection, per-request CSP nonce |

---

## System Requirements

### Hardware

| Role | Machine | Minimum Spec |
|---|---|---|
| **SCMS Server** | Kubuntu laptop | 2-core CPU, 2 GB RAM, 20 GB disk |
| **Engineering workstation** | Windows laptop | Browser only |
| **Honeypot node** | Raspberry Pi Zero W2 | 512 MB RAM |
| **OT router** | TP-Link Archer C7 (OpenWRT) | Stock hardware |
| **Internet router** | AT&T BGW320-505 | Stock hardware |

### Software (server machine)

- Ubuntu 20.04+ / Debian 11+ / Kubuntu 22.04
- Python 3.10 or newer
- PostgreSQL 12 or newer
- tshark **or** scapy (at least one required for packet capture)

---

## Project Layout

```
scms-ics/
|
+-- install.py                   # One-time guided installer
+-- scms.py                     # Runtime CLI: start / stop / status / logs
+-- run_server.py                # Production Flask launcher (SIGTERM-safe)
+-- app.py                       # Flask application factory
+-- agent.py                     # Log collection daemon (runs on monitored hosts)
+-- buffer.py                    # Offline event buffer (thread-safe, atomic write)
+-- config.py                    # Configuration loader (.env to env to defaults)
+-- parser.py                    # ICS protocol parser and packet decoder
+-- setup_db.py                  # Database schema creator
+-- alerts.py                    # Brute-force and SUDO alert queries
+-- analytics.py                 # Aggregate analytics queries
+-- db.py                        # Low-level PostgreSQL helpers
|
+-- scripts/
|   +-- populate_test_incidents.py   # One-click test data generator
|
+-- server/
|   +-- auth.py                  # Login, sessions, CSRF tokens, account lockout
|   +-- capture.py               # Live PCAP thread (scapy to tshark fallback)
|   +-- crypto.py                # AES-256-GCM field encryption and decryption
|   +-- fim.py                   # File Integrity Monitoring (SHA-256)
|   +-- login_html.py            # Login page HTML template
|   +-- dashboard_html.py        # Single-page dashboard application
|   +-- response.py              # IP blocking (iptables) and SMTP email alerts
|   +-- routes.py                # All Flask route handlers
|   +-- sca.py                   # 32-check CIS Benchmark assessment
|   +-- security.py              # Rate limiter, CSP nonce, input validators
|   +-- sis.py                   # Safety Instrumented System trip engine
|   +-- vuln.py                  # CVE vulnerability scanner
|
+-- docs/
    +-- security_report.tex      # LaTeX security report
    +-- presentation.tex         # LaTeX Beamer presentation slides
```

---

## Installation — Quick Path

Run this on the machine that will be your SCMS server:

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install -y \
    python3 python3-pip postgresql postgresql-contrib \
    tshark libpcap-dev python3-dev git

# 2. Install Python packages
pip3 install flask psycopg2-binary requests werkzeug cryptography bcrypt scapy

# 3. Clone the repository
git clone https://github.com/yourorg/scms-ics.git
cd scms-ics

# 4. Run the installer (as root for systemd registration)
sudo python3 install.py
```

The installer asks:
- **Server or Agent?** Choose **Server** on this machine
- PostgreSQL connection details (host, port, database name, username, password)
- Dashboard bind address and port (default `0.0.0.0:5000`)
- SMTP credentials for email alerts (press Enter to skip)

It writes `.env`, creates the database and all tables, registers a `scms-server` systemd service, and starts it. Open `http://localhost:5000` immediately after.

**Next step:** [Create your admin login account](#first-login)

---

## Installation — Manual Step-by-Step

Use this if you want full control or are not running as root.

### Step 1 — System packages

```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip \
    postgresql postgresql-contrib \
    tshark libpcap-dev python3-dev
```

### Step 2 — Python packages

```bash
pip3 install flask psycopg2-binary requests werkzeug cryptography bcrypt scapy
```

`bcrypt` and `scapy` are optional but strongly recommended. Without `bcrypt` the system falls back to stdlib `scrypt`. Without `scapy` it falls back to `tshark`.

### Step 3 — Create a PostgreSQL user

```bash
sudo -u postgres psql -c "CREATE USER scms WITH PASSWORD 'choose_a_strong_password';"
sudo -u postgres psql -c "GRANT CREATEDB TO scms;"
```

### Step 4 — Write the .env file

```bash
API_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ENC_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

cat > .env << EOF
SERVER_HOST="0.0.0.0"
SERVER_PORT="5000"
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="scms_ics"
DB_USER="scms"
DB_PASSWORD="choose_a_strong_password"
API_KEY="${API_KEY}"
SECRET_KEY="${SECRET_KEY}"
FIELD_ENCRYPTION_KEY="${ENC_KEY}"
ENABLE_RATE_LIMIT="true"
ENABLE_CSP="true"
RATE_LIMIT_PER_MINUTE="300"
EOF

chmod 600 .env
```

**Never commit `.env` to source control.** It contains your encryption and signing keys.

### Step 5 — Create the database

```bash
python3 setup_db.py
```

Expected output:
```
Secure Continuous Monitoring System — Database Setup
  Created database 'scms_ics'.
  All tables and indexes ready.
```

### Step 6 — Create the admin account

```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from server.auth import create_user
ok, msg = create_user('admin', 'YourStrongPassword123!', 'admin')
print('OK' if ok else 'FAILED', msg)
"
```

Password must be at least 12 characters.

### Step 7 — Start the server

```bash
# Background process (no systemd needed)
python3 scms.py start server

# Check it started
python3 scms.py status
```

Open `http://localhost:5000` and log in.

---

## Air-Gapped Lab Setup

This section sets up a mock air-gapped OT network using the hardware listed above, simulating a real power plant or water treatment facility.

### Network topology

```
Internet (WAN)
     |
AT&T BGW320-505    192.168.1.1  (internet router)
     |
     +-- LAN: 192.168.1.0/24   "Corporate network"
           |
           +-- Kubuntu Laptop   192.168.1.10   SCMS Server
           |       eth0 = 192.168.1.10   (corporate, dashboard access)
           |       eth1 = no IP          (OT mirror port, capture only)
           |
           +-- Windows Laptop  192.168.1.20   Engineering Workstation
           |       Browser to http://192.168.1.10:5000
           |
           +-- Archer C7 (OpenWRT)  WAN port 192.168.1.30
                     LAN: 192.168.100.0/24   "OT Control Network"
                     |
                     +-- Pi Zero W2   192.168.100.100   Honeypot
                     +-- ICS simulators on Windows Laptop (OT WiFi)
```

### Step 1 — Configure the Archer C7 as OT router

SSH into the Archer C7 and run:

```bash
# Set OT LAN address
uci set network.lan.ipaddr='192.168.100.1'
uci set network.lan.netmask='255.255.255.0'
uci commit network
/etc/init.d/network restart

# Air-gap: block OT devices from reaching the internet
uci add firewall rule
uci set firewall.@rule[-1].name='block-ot-to-wan'
uci set firewall.@rule[-1].src='lan'
uci set firewall.@rule[-1].dest='wan'
uci set firewall.@rule[-1].target='REJECT'
uci commit firewall
/etc/init.d/firewall restart

# Enable SPAN mirror port so Kubuntu eth1 sees all OT traffic
# Mirror all LAN ports to port 4 (cable to Kubuntu eth1)
swconfig dev switch0 set enable_mirror_rx 1
swconfig dev switch0 set enable_mirror_tx 1
swconfig dev switch0 set mirror_monitor_port 4
swconfig dev switch0 set mirror_source_port 0
swconfig dev switch0 set apply
```

### Step 2 — Prepare the Kubuntu capture interface

```bash
# Put eth1 into promiscuous mode with no IP (pure sniff)
sudo ip link set eth1 promisc on
sudo ip link set eth1 up
sudo ip addr flush dev eth1

# Grant capture permission without running as root
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Step 3 — ICS simulators on the Windows Laptop

Connect the Windows Laptop to the Archer C7 OT WiFi (192.168.100.x).

| Tool | Protocols simulated | Source |
|---|---|---|
| **ModRSsim2** | Modbus TCP slave | sourceforge.net/projects/modrssim |
| **ScadaBR** | Modbus, DNP3 HMI | scadabr.com.br |
| **pycomm3** | EtherNet/IP | `pip install pycomm3` |
| **OpenDNP3** | DNP3 outstation | github.com/automatak/dnp3 |

Start ModRSsim2 as a Modbus TCP server on port 502. As soon as you start capture on `eth1` in SCMS, every Modbus poll will appear in the Packets tab decoded.

### Step 4 — Honeypot on Pi Zero W2

```bash
# On the Pi (Raspberry Pi OS Lite)
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install conpot

# Start ICS honeypot (simulates Modbus, DNP3, IEC-104, BACnet, SNMP, HTTP)
sudo conpot --template default --logfile /var/log/conpot.log &

# Install the SCMS agent to forward honeypot events to the server
git clone https://github.com/yourorg/scms-ics.git
cd scms-ics
sudo python3 install.py
# Choose: Agent
# Server IP: 192.168.1.10
# API Key: paste your server's API_KEY from its .env
# Add log file: /var/log/conpot.log
```

---

## Honeypot Internet Exposure

**Only expose the Pi Zero W2.** Never expose real PLC or RTU ports to the internet.

### Configure the AT&T BGW320-505

1. Log in to `http://192.168.1.254`
2. Go to **Firewall → NAT/Gaming**
3. Forward these ports to the Pi's IP (`192.168.1.50` or whatever you assigned):

| External Port | Protocol | Destination | ICS Service |
|---|---|---|---|
| 502 | TCP | Pi IP | Modbus |
| 20000 | TCP | Pi IP | DNP3 |
| 44818 | TCP | Pi IP | EtherNet/IP |
| 2404 | TCP | Pi IP | IEC-104 |
| 47808 | UDP | Pi IP | BACnet |

4. Under **IP Passthrough** assign the Pi as DMZ host for full exposure.

Internet attackers probing ICS ports will reach the Pi's Conpot honeypot. Conpot logs are forwarded via the agent, appearing in your dashboard Incidents, Packets, and Geo Map tabs as real threat intelligence.

---

## Configuration Reference

All settings live in `.env` (written by `install.py`, permissions `0600`). Environment variables override `.env` when both are set.

```bash
# Server
SERVER_HOST="0.0.0.0"          # Bind address (0.0.0.0 = all interfaces)
SERVER_PORT="5000"             # Dashboard and ingest port

# Database
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="scms_ics"
DB_USER="scms"
DB_PASSWORD="your_password"

# Security keys (all generated by install.py — back these up)
API_KEY="64-char-hex"          # Agent authentication key — copy to every agent .env
SECRET_KEY="64-char-hex"       # Flask session signing key — never share
FIELD_ENCRYPTION_KEY="64-hex"  # AES-256-GCM master key — losing this = unreadable DB

# TLS (leave blank for HTTP)
TLS_CERT_PATH=""               # Absolute path to PEM certificate
TLS_KEY_PATH=""                # Absolute path to PEM private key

# Email alerts (leave blank to disable)
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="alerts@yourcompany.com"
SMTP_PASSWORD="app_password"
SMTP_FROM="alerts@yourcompany.com"
SMTP_TO="soc@yourcompany.com"

# Agent settings (used in .env on monitored machines, not the server)
SERVER_URL="http://192.168.1.10:5000/ingest"
LOG_FILES="/var/log/auth.log,/var/log/syslog,/var/log/conpot.log"
JOURNAL_UNITS="sshd,sudo,systemd,user"

# Feature flags
ENABLE_RATE_LIMIT="true"       # Set false only for development
ENABLE_CSP="true"              # Set false only for development
RATE_LIMIT_PER_MINUTE="300"
```

---

## Starting Stopping and Status

### Without systemd (any user)

```bash
python3 scms.py start both        # Start server and agent together
python3 scms.py start server      # Server only
python3 scms.py start agent       # Agent only

python3 scms.py status            # Show what is running

python3 scms.py logs server       # Last 60 lines of server log
python3 scms.py logs server -n 200  # Last 200 lines
python3 scms.py logs agent -n 100

python3 scms.py stop both         # Stop everything cleanly
python3 scms.py stop server
python3 scms.py restart server    # Stop then start
```

Logs are written to `./logs/server.log` and `./logs/agent.log`.
PID files live in `./run/`. Processes detach from the terminal automatically.

### With systemd (after `sudo python3 install.py`)

```bash
sudo systemctl status  scms-server scms-agent
sudo systemctl start   scms-server
sudo systemctl stop    scms-server scms-agent
sudo systemctl restart scms-server

sudo journalctl -u scms-server -f   # Follow server log live
sudo journalctl -u scms-agent  -f   # Follow agent log live
```

---

## First Login

1. Open a browser at `http://<server-ip>:5000`
2. You are redirected to the login page
3. Enter the username and password you set up during installation
4. You land on the **Overview** dashboard

### Create additional users

```bash
# Analyst account (read access)
python3 -c "
import sys; sys.path.insert(0,'.')
from server.auth import create_user
create_user('analyst1', 'SecurePass456!', 'analyst')
"

# Additional admin
python3 -c "
import sys; sys.path.insert(0,'.')
from server.auth import create_user
create_user('admin2', 'SecurePass789!', 'admin')
"
```

Password requirements: minimum 12 characters.
Account lockout: 5 failed attempts triggers a 15-minute lockout.
Session timeout: 8 hours of inactivity.

---

## Dashboard Walkthrough

### Overview tab

The landing page after login. Auto-refreshes every 10 seconds.

- **KPI row** — total log count, failed logins last minute, suspicious commands, unique hosts, blocked IPs
- **Event timeline** — 60-minute rolling chart of all events vs. threats
- **Live event feed** — last 200 events colour-coded by severity. Click any row to open the detail drawer showing full decoded fields, raw line, and MITRE ATT&CK technique chips
- **Top attacker IPs** — ranked by failed login count with one-click block button
- **Event type distribution** — doughnut chart breaking down AUTH, SUDO, ICS_MODBUS, ICS_DNP3, etc.
- **Sidebar alerts** — active brute-force sources, SUDO abuse, unacknowledged SIS trips

### Packets tab

Wireshark-style packet inspector for all captured network traffic.

1. Select an interface from the dropdown (e.g. `eth1` for your SPAN port)
2. Click **Start Capture** — packets appear in the table in real time
3. Use **protocol filter chips** to show only Modbus / DNP3 / EtherNet/IP / IEC-104 / Anomaly
4. Use the **search bar** to filter by IP, function code, or payload content
5. Click any row to open the **packet detail drawer**:
   - Source and destination IP:port
   - Protocol name and decoded function code
   - ICS register address and value (e.g. `addr=1050 value=9999`)
   - Raw hex payload
   - Geolocation for external source IPs
   - Threat score from 0 to 100
   - Links to related SIS events and incidents

Row colours: red = anomaly or external ICS access, orange = ICS write command, grey = normal traffic.

### Incidents tab

Full incident response lifecycle management.

- **Auto-created** when a SIS rule fires, or **manually created** for any observation
- **Key fields**: title, severity (CRITICAL/HIGH/MEDIUM/LOW), status (OPEN/INVESTIGATING/CONTAINED/RESOLVED), affected device, site zone, MITRE technique IDs, related packet IDs, JSON event timeline, regulatory violation citations, step-by-step remediation instructions, assigned analyst
- **Status progression**: OPEN → INVESTIGATING → CONTAINED → RESOLVED
- **Export CSV** for regulatory reporting (NERC CIP, EPA, etc.)

### SIS tab

Safety Instrumented System event log.

- Every fired SIS rule creates a record here with rule ID, trigger details, source/destination, affected zone, and the action description
- **Acknowledge** button records human review completion with timestamp and username
- **Rules panel** shows all 14 pre-built rules with their trigger conditions and remediation playbooks

### Inventory tab

Network device registry.

- Auto-populated as SCMS sees new IPs in packets and log events
- Edit any device to add: vendor, device type, firmware, ICS protocol, PLC model, site zone, role, criticality
- Check **Is ICS Device** for PLCs, RTUs, HMIs, protection relays
- Check **Is Honeypot** for the Pi Zero W2 and any other decoys
- Filter by zone, criticality, ICS protocol, or honeypot status

### Geo Map tab

Live world heatmap of attacker source IPs.

- Circle size represents threat score
- Circle colour: red = critical, orange = high, yellow = medium
- Hover over a circle for IP, country, city, ISP, and event count
- Filter by time range or event type

### Analytics tab

Statistical views deeper than the Overview:

- Failed logins per hour across a 24-hour heatmap
- Top attacker IPs with severity and one-click block
- SUDO user activity table
- Protocol distribution pie chart
- Success vs. anomaly ratio over time

### FIM tab

File Integrity Monitoring.

1. Click **Establish Baseline** to hash all configured paths with SHA-256
2. Click **Run Scan** at any time to compare current hashes to baseline
3. Changed files appear as **MODIFIED** in red; missing files as **ERROR**
4. Default paths: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`, `/etc/crontab`, `/root/.bashrc`, `/etc/ssh/sshd_config`
5. Add your own paths using the path input field

### Config Audit tab

Runs 32 CIS Benchmark checks against the local system. Click **Run Checks**. Each check shows PASS or FAIL with framework tags (PCI-DSS control number, HIPAA section, NIST CSF subcategory). The Admin tab Compliance section calculates aggregate scores.

### Vulnerabilities tab

Click **Scan Packages** to match installed Debian packages against CVEs. Pulls live data from the NVD API when internet is available. Always includes an offline baseline of 15 known critical ICS-relevant CVEs (glibc Looney Tunables, Baron Samedit, PwnKit, Shellshock, etc.).

### MITRE ATT&CK tab

Auto-populated from live event data. Shows all detected technique IDs from both the Enterprise and ICS matrix as clickable cards. Click any card to open the MITRE website for the full technique description, examples, and mitigations.

### Active Response tab

- **Block IP** — applies an iptables DROP rule and records the block in the registry
- **Unblock IP** — removes the iptables rule
- **Auto-block rules** — configure thresholds (e.g. block IPs with >10 failed logins automatically)
- **Process manager** — view all running processes on the server host and send SIGTERM to suspicious ones
- **Response log** — chronological log of every blocking action with timestamp, IP, and reason

### Admin tab

- **Database manager** — list, switch between, and create PostgreSQL databases
- **Log path manager** — add or remove files for the agent to monitor
- **System inventory** — server OS, Python version, monitored path count
- **System health** — Flask, PostgreSQL, and agent reachability status
- **Compliance scores** — PCI-DSS, HIPAA, and NIST CSF percentage scores from the latest Config Audit run
- **CSV import/export** — bulk operations on log event data

---

## Packet Capture

### Permissions setup (do this once)

```bash
# Option A: grant Python raw socket access directly
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Option B: use the tshark dumpcap helper
sudo groupadd pcap
sudo usermod -aG pcap $USER
sudo chgrp pcap /usr/bin/dumpcap
sudo chmod 750 /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
# Log out and back in for the group change to take effect
```

### Start from the dashboard

1. Go to the **Packets** tab
2. Select your interface (`eth1` for SPAN mirror port, `eth0` for direct)
3. Click **Start Capture**

### Capture backend priority

SCMS tries these in order and uses the first one that works:

1. **scapy** — richest decode, no subprocess, best for production
2. **tshark** — good decode via JSON output, slightly less detail
3. Capture disabled with a warning if neither is installed

### Which interface to use

```bash
ip link show       # List all interfaces

# eth1 (or enp3s0, etc.) = your second NIC connected to the OT switch SPAN port
# eth0 = monitor traffic on the server's own network
# wlan0 = wireless (requires monitor mode for passive capture)
```

---

## Safety Instrumented System Rules

All 14 rules live in `server/sis.py` and evaluate automatically on every decoded packet and log event. No manual trigger needed.

### Power plant rules

| Rule ID | What triggers it | What SCMS does |
|---|---|---|
| **PWR-001** | Modbus FC5/6/15/16 to registers 1000–1999 (turbine governor) | TRIP turbine governor — isolate control segment |
| **PWR-002** | Modbus FC5/6 to registers 2000–2499 (generator excitation) | Open generator main breaker |
| **PWR-003** | DNP3 DIRECT\_OPERATE (FC4/5/6) to transformer protection relay | Engage lockout relay 86 — open HV and LV breakers |
| **PWR-004** | DNP3 COLD\_RESTART (FC13) or WARM\_RESTART (FC14) to EMS RTU | Isolate RTU — switch to manual local control |

### Water treatment rules

| Rule ID | What triggers it | What SCMS does |
|---|---|---|
| **WTR-001** | Modbus FC5/6/15/16 to registers 3000–3499 (chemical dosing) | Emergency stop dosing pumps — manual bypass |
| **WTR-002** | Modbus FC5/6 to registers 3500–3999 (effluent discharge valves) | Close all discharge valves — alert compliance |
| **WTR-003** | Modbus FC5/6/15/16 to registers 4000–4499 (high-lift pumps) | Stop pumps — switch to backup supply |

### General ICS rules

| Rule ID | What triggers it | What SCMS does |
|---|---|---|
| **ICS-001** | Any ICS port (502, 20000, 44818, 2404, 47808, 102) from a non-RFC1918 IP | Block source IP — alert SOC — create incident |
| **ICS-002** | Modbus request with Unit ID 0 or 255 (broadcast scan) | Alert — network reconnaissance detected |
| **ICS-003** | IEC-104 command types 45–51 with activation cause | Reject — verify master station identity |
| **ICS-004** | EtherNet/IP Write\_Tag or Write\_Tag\_Fragmented from unknown source | Block source — audit PLC tag database |
| **ICS-005** | More than 20 Modbus writes from same IP within 10 seconds | Rate limit source — consider emergency isolation |

### Network and host rules

| Rule ID | What triggers it | What SCMS does |
|---|---|---|
| **NET-001** | SSH authentication failures greater than 10 from same IP | Block source IP — check for lateral movement |
| **NET-002** | Suspicious command on ICS host (bash reverse shell, shadow file read, history clear, etc.) | Isolate host — preserve memory — forensic response |

---

## Incident Response

SCMS creates incident records automatically when SIS rules fire. You can also create them manually from any event.

### Incident status workflow

```
OPEN  -->  INVESTIGATING  -->  CONTAINED  -->  RESOLVED
  |                                                |
  +-- auto-created by SIS rule                    +-- ResolvedAt timestamp set
  +-- manually created by analyst                 +-- Export CSV for reporting
```

### Every incident record includes

- Full event timeline (JSON array of timestamped observations)
- All related packet IDs linking to decoded packet records
- All related log event IDs
- Affected device, site zone, and geographic coordinates
- MITRE ATT&CK for ICS technique IDs
- Regulatory violation citations (NERC CIP, IEC 62443, EPA, AWWA)
- Step-by-step remediation instructions
- SIS trip actions that fired automatically

---

## Device Inventory

### Auto-population

The inventory fills automatically as SCMS sees source and destination IPs. After a few minutes of monitoring you will see entries for every device on the network.

### Manual enrichment

For each device, edit the record to add:

- Vendor, device type, OS/firmware version
- ICS protocol (Modbus, DNP3, EtherNet/IP, IEC-104, BACnet, S7comm)
- PLC model number (e.g. Siemens S7-1516, Allen-Bradley ControlLogix)
- Site zone (Turbine Control, Chemical Dosing, Engineering, etc.)
- Role (Turbine Governor PLC, Generator Protection RTU, SCADA HMI, etc.)
- Criticality: CRITICAL, HIGH, MEDIUM, or LOW

### Criticality guide

| Level | Examples |
|---|---|
| CRITICAL | Turbine governor PLC, generator protection RTU, chemical dosing controller |
| HIGH | Engineering workstation, SCADA server, process historian |
| MEDIUM | General IT systems in the engineering zone |
| LOW | Printers, IP phones, non-process devices |

---

## Test Data

Generate high-fidelity synthetic ICS attack scenarios for testing and demonstrations:

```bash
# Add test data to existing database
python3 scripts/populate_test_incidents.py

# Clear all existing data and repopulate from scratch
python3 scripts/populate_test_incidents.py --clear
```

This inserts:

**Inventory**: Siemens S7-1516 turbine PLC, GE UR D60 generator RTU, Allen-Bradley ControlLogix pump PLC, Modicon M340 chemical dosing PLC, SEL-411L transformer relay, ABB SCADA server, OSIsoft historian, Dell engineering workstation, and a Conpot honeypot node.

**Packets**: Decoded Modbus write from Russian IP to turbine registers, DNP3 COLD\_RESTART from Chinese IP to generator RTU, EtherNet/IP Write\_Tag from engineering workstation to pump PLC, Modbus write from Iranian IP to chemical dosing register, IEC-104 command to SCADA server, honeypot contact from Netherlands.

**Incidents**: Three fully populated incidents — Russian Modbus turbine attack, Iranian chemical dosing compromise, and Chinese DNP3 restart attack. Each includes a JSON event timeline, regulatory violation citations, and remediation steps.

**SIS events**: All relevant rules fired for the test packets, with proper cross-references.

**Geo events**: Five external attacker origins plotted on the world map.

---

## Adding Agents to Remote Machines

Install the SCMS agent on every Linux machine whose logs you want to forward.

```bash
# Copy agent files to the remote machine
scp agent.py buffer.py config.py install.py user@remote-host:/opt/scms/

# SSH in and run the agent installer
ssh user@remote-host
cd /opt/scms
sudo python3 install.py
# Choose: Agent
# Server IP: your SCMS server IP
# API Key: paste the API_KEY value from the server .env
```

The agent will:
1. Try to auto-detect the server by probing the local network
2. Ask for the server IP if not found
3. Write a local `.env` with `SERVER_URL` and `API_KEY`
4. Register a `scms-agent` systemd service that starts on boot

### Default log sources monitored

```
/var/log/auth.log        SSH logins and sudo
/var/log/syslog          General system messages
/var/log/kern.log        Kernel messages
/var/log/dpkg.log        Package installs and upgrades
/var/log/audit/audit.log SELinux and auditd events
/root/.bash_history      Root command history
```

Journal units: `sshd`, `sudo`, `systemd`, `user`

### Add custom log files

In the agent's `.env`:

```bash
LOG_FILES="/var/log/auth.log,/var/log/syslog,/var/log/conpot.log,/opt/scada/scada.log"
```

---

## Adding Custom SIS Rules

Edit `server/sis.py` and add a new dict to the `SIS_RULES` list. No other changes required — the engine picks it up on next start.

```python
{
    # Required
    "id":        "CUSTOM-001",
    "name":      "Write to Boiler Pressure Setpoint",
    "severity":  "CRITICAL",            # CRITICAL / HIGH / MEDIUM
    "protocol":  "Modbus",              # Modbus / DNP3 / EtherNet/IP / IEC-104 / ANY / SYS
    "action":    "TRIP boiler feed pump and close steam valve",

    # Match conditions — all must pass to fire the rule
    "fc_codes":      [6, 16],           # Function codes, or None for any
    "dst_ports":     [502],             # Destination ports, or None for any
    "address_range": (500, 599),        # Register address range, or None

    # Optional callable for complex logic: fn(pkt_record) -> bool
    "condition_fn": None,

    # Documentation shown in the dashboard and incident records
    "zone":      "Boiler",
    "mitre":     ["T0836", "T0855"],
    "violations": [
        "ASME Boiler and Pressure Vessel Code: Unauthorized setpoint modification",
    ],
    "remediation": [
        "1. Close main steam stop valve immediately",
        "2. Reduce boiler firing rate to minimum",
        "3. Inspect boiler water level and engage cutoff if needed",
        "4. Alert shift supervisor and maintenance team",
        "5. Capture full PCAP of the Modbus session before any network changes",
    ],
}
```

**Finding your register addresses**: Use ModRSsim2, your PLC's configuration software, or a Modbus scanner tool to identify which register addresses correspond to which physical process variables (pump speed, chemical flow rate, valve position, setpoints).

---

## TLS and HTTPS Setup

### Using Let's Encrypt (internet-exposed dashboard)

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

Add to `.env`:

```bash
TLS_CERT_PATH="/etc/letsencrypt/live/yourdomain.com/fullchain.pem"
TLS_KEY_PATH="/etc/letsencrypt/live/yourdomain.com/privkey.pem"
```

Also set in `app.py`:

```python
app.config["SESSION_COOKIE_SECURE"] = True
```

Restart the server. It serves HTTPS on port 5000.

### Self-signed certificate (internal networks)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 3650 -nodes -subj "/CN=scms-server"
```

Set `TLS_CERT_PATH` and `TLS_KEY_PATH` to the absolute paths of your files.

For agents connecting over self-signed TLS, set the CA bundle:

```bash
export REQUESTS_CA_BUNDLE=/path/to/cert.pem
python3 agent.py
```

---

## Email Alerts

SCMS sends email when a SIS rule fires or the auto-block threshold is hit.

### Gmail setup

1. Enable 2-factor authentication on the sending Gmail account
2. Generate an App Password: Google Account → Security → App Passwords → generate one for SCMS
3. Add to `.env`:

```bash
SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER="your@gmail.com"
SMTP_PASSWORD="xxxx xxxx xxxx xxxx"
SMTP_FROM="your@gmail.com"
SMTP_TO="soc@yourcompany.com"
```

### Test your email configuration

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from server.response import send_alert_email
ok = send_alert_email('SCMS Test', 'Email configuration is working.')
print('Sent' if ok else 'Failed — check SMTP settings in .env')
"
```

---

## Security Hardening Checklist

Work through this after installation:

```
[ ] Confirm .env is chmod 600 (ls -la .env should show -rw-------)
[ ] Back up FIELD_ENCRYPTION_KEY — losing it makes encrypted DB rows unreadable
[ ] Configure TLS: set TLS_CERT_PATH and TLS_KEY_PATH in .env
[ ] Set SESSION_COOKIE_SECURE = True in app.py once TLS is active
[ ] Restrict port 5000 to corporate VLAN only via firewall (never OT network, never internet)
[ ] Create the admin account with a 16+ character passphrase
[ ] Run Config Audit tab and remediate all CRITICAL failures
[ ] Run FIM tab and establish SHA-256 baseline immediately after clean install
[ ] Review SIS rule address ranges in server/sis.py — tune to your actual PLC register maps
[ ] Configure SMTP so CRITICAL SIS events generate email alerts
[ ] Test all SIS rules using populate_test_incidents.py
[ ] Verify each remote agent's API_KEY matches the server's API_KEY
[ ] Enable IEC 62351-5 Secure Authentication on RTUs if the hardware supports it
[ ] Enable OpenWRT firewall rule blocking OT-to-WAN routing
[ ] Set database password in .env to something strong (not the example value)
[ ] Run python3 scms.py status and confirm server and agent are both running
```

---

## Troubleshooting

| Symptom | Most likely cause | Fix |
|---|---|---|
| `Permission denied` on capture start | Python lacks raw socket permission | `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)` |
| No packets in the Packets tab | Wrong interface selected | Run `ip link show` — use the interface connected to your SPAN port |
| Packets appear but no ICS decode | Traffic not on expected ports | Confirm simulator is sending to port 502 (Modbus), 20000 (DNP3), etc. |
| `scapy not found` in server log | scapy not installed | `pip3 install scapy` — tshark fallback activates automatically |
| `tshark not found` in server log | tshark not installed | `sudo apt install tshark` |
| PostgreSQL connection refused | Service not running | `sudo systemctl start postgresql` |
| Tables missing on startup | setup_db.py not run | `python3 setup_db.py` |
| Login fails every time | Admin user not created | See the First Login section above |
| `403 CSRF token invalid` | Session cookie not reaching server | Verify you are accessing via the same hostname in cookie vs. address bar |
| Agent events not appearing | Wrong API key or unreachable URL | Check `API_KEY` in agent `.env` matches server `.env`; `curl http://<server>:5000/health` from agent machine |
| High CPU usage | scapy processing every packet on busy link | Uninstall scapy (`pip3 uninstall scapy`) — tshark backend uses less CPU |
| `[decryption error]` in log messages | FIELD\_ENCRYPTION\_KEY changed or rotated | Restore the original key value from your backup |
| systemd service fails to start | .env path wrong in the unit file | `sudo python3 install.py` to regenerate systemd units |
| Dashboard blank after login | JavaScript CSP error | Open browser DevTools → Console, look for Content-Security-Policy violation |

---

## References and Standards

| Standard or Resource | Relevance to SCMS |
|---|---|
| [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final) | Guide to OT/ICS Security — foundational architecture reference |
| [NERC CIP-005-7](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) | Electronic Security Perimeters — ICS-001 rule enforces boundary detection |
| [NERC CIP-007-6](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) | Systems Security Management — patch and malicious code monitoring |
| [IEC 62443-3-3](https://www.iec.ch) | IACS Security Requirements — SR mapping in all SIS violation citations |
| [IEC 60870-5-104](https://www.iec.ch) | Telecontrol protocol standard — IEC-104 decoder and ICS-003 rule |
| [IEEE 1815-2012 (DNP3)](https://standards.ieee.org) | DNP3 standard — all function code definitions |
| [Modbus Application Protocol v1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf) | Modbus TCP specification — all Modbus decoder logic |
| [ODVA EtherNet/IP Specification](https://www.odva.org) | CIP and EtherNet/IP — encapsulation header decode |
| [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) | ICS technique taxonomy — all T0xxx codes in events and SIS rules |
| [NIST SP 800-61 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) | Incident Handling Guide — IR lifecycle and record design |
| [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | Synchroniser token pattern implementation |
| [RFC 5869 — HKDF](https://tools.ietf.org/html/rfc5869) | HKDF-SHA256 for AES key derivation |
| [NIST FIPS 197 — AES](https://csrc.nist.gov/publications/detail/fips/197/final) | AES-256-GCM encryption specification |
| [AWWA Cybersecurity Guidance](https://www.awwa.org/Resources-Tools/Resource-Topics/Risk-Resilience/Cybersecurity.aspx) | Water utility security — WTR rule set design |
| [EPA SDWA Section 1433](https://www.epa.gov/waterresilience/america-water-infrastructure-act-2018) | Water treatment cybersecurity requirements |
| [CISA ICS Advisories](https://www.cisa.gov/ics) | Current ICS threat intelligence and vendor advisories |
| [Conpot ICS Honeypot](https://github.com/mushorg/conpot) | Honeypot framework used by the Pi Zero W2 decoy node |
# SCMS
# SCMS
