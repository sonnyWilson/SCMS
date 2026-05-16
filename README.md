# SCMS — Secure Continuous Monitoring System

**Self-hosted ICS/SCADA SIEM — real-time log collection, packet analysis,
threat detection, and active response on Linux hosts.**

## What Is SCMS?

SCMS is a production-grade, open-source **Security Information and Event Management (SIEM)** platform built for **Industrial Control System (ICS) and SCADA environments** — the hardest class of infrastructure to monitor because it blends IT security requirements with OT (operational technology) safety constraints.

A lightweight **agent** daemon tails system logs and systemd journals, buffering events locally on network loss and shipping them over HTTP to a central **Flask server**. The server parses, enriches, stores, and acts on every event — all state lives in **PostgreSQL**, giving you a queryable, auditable event history with MITRE ATT&CK tagging, ICS protocol decoding, Safety Instrumented System trip evaluation, CIS Benchmark compliance scoring, SHA-256 file integrity monitoring, CVE vulnerability scanning, iptables-based active response, and SMTP alerting.

---

## Table of Contents

- [Architecture]
- [Project Structure]
- [Requirements & Installation]
- [Configuration Reference]
- [Usage]
- [Security Concepts In Depth]
  - [1. Log Collection & Buffered Delivery]
  - [2. Structured Log Parsing & Event Normalization]
  - [3. ICS/SCADA Protocol Decoding]
  - [4. MITRE ATT&CK Tagging]
  - [5. Safety Instrumented System (SIS) Trip Engine]
  - [6. Security Configuration Assessment (CIS Benchmarks)]
  - [7. File Integrity Monitoring (FIM)]
  - [8. Vulnerability Scanning]
  - [9. Active Response — iptables & SMTP]
  - [10. AES-256-GCM Data-at-Rest Encryption]
  - [11. Authentication, CSRF & Account Lockout]
  - [12. Security Headers & Rate Limiting]
- [Database Schema]
- [Utility Scripts]
- [Deployment Hardening]
- [Contributing]

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Linux Host(s) — IT / OT Network                                │
│                                                                  │
│  agent.py                                                        │
│  ├── _monitor_text_file()   /var/log/auth.log                    │
│  │                          /var/log/syslog  ...                 │
│  └── _monitor_journal()     sshd · sudo · systemd · user        │
│       │                                                          │
│       │  HTTP POST /ingest (JSON + API_KEY header)               │
│       │  buffer.json  ←  offline queue on network loss           │
└───────┼──────────────────────────────────────────────────────────┘
        │
┌───────▼──────────────────────────────────────────────────────────┐
│  Flask Server  (run_server.py → app.py)                          │
│                                                                  │
│  server/routes.py       ← REST API endpoints + live dashboard    │
│  server/parser.py       ← raw log line → structured event dict   │
│  server/sis.py          ← SIS trip rule evaluation               │
│  server/response.py     ← iptables block · SMTP alert            │
│  server/sca.py          ← 32 CIS Benchmark checks                │
│  server/fim.py          ← SHA-256 file integrity hashing         │
│  server/vuln.py         ← CVE package cross-reference            │
│  server/crypto.py       ← AES-256-GCM field encryption           │
│  server/auth.py         ← login · CSRF · lockout · bcrypt        │
│  server/security.py     ← headers · CSP nonce · rate limiter     │
│  server/capture.py      ← packet capture (scapy/tshark)          │
└───────┬──────────────────────────────────────────────────────────┘
        │
┌───────▼──────────────────────────────────────────────────────────┐
│  PostgreSQL  —  scms database                                    │
│                                                                  │
│  Logs · Packets · Incidents · Inventory                          │
│  SIS_Events · GeoEvents · scms_users                             │
└──────────────────────────────────────────────────────────────────┘
```

The design is deliberately **flat and modular**: the agent and server are independent processes — start, stop, and restart them individually. The agent buffers events locally to `buffer.json` on network loss and flushes them on reconnection, which is essential in OT environments with intermittent network links.

---

## Project Structure

```
scms/
├── agent.py            # Log collection daemon — runs on monitored hosts
├── app.py              # Flask application factory
├── buffer.py           # Offline event queue — buffer.json with retry logic
├── config.py           # .env → environment variables → safe defaults
├── db.py               # PostgreSQL helpers (insert, query, connection)
├── install.py          # First-run installer: DB, tables, admin user, .env
├── run_server.py       # Production Werkzeug server with optional TLS
├── scms.py             # CLI: start / stop / restart / status / logs
├── setup_db.py         # Table and index creation (idempotent)
├── reset_all.py        # Truncate all event data, preserve schema and users
├── reset_password.py   # CLI password reset utility
├── logs/               # Rotating agent and server log files
├── run/                # PID files for process management
└── server/
    ├── auth.py            # Login, CSRF, lockout, bcrypt/scrypt hashing
    ├── capture.py         # Packet capture via scapy / tshark
    ├── crypto.py          # AES-256-GCM field encryption / decryption
    ├── dashboard_html.py  # Dashboard HTML template (server-rendered)
    ├── fim.py             # File Integrity Monitoring — SHA-256
    ├── login_html.py      # Login page HTML template
    ├── parser.py          # Raw log line → structured event dict + ICS decode
    ├── response.py        # Active response: iptables rules, SMTP alerts
    ├── routes.py          # Flask route handlers — REST API + dashboard
    ├── sca.py             # Security Configuration Assessment (CIS checks)
    ├── security.py        # Security headers, CSP nonce, per-IP rate limiter
    ├── sis.py             # SIS trip rule engine
    └── vuln.py            # Vulnerability scanner — CVE baseline lookup
```

---

## Requirements & Installation

### Dependencies

```bash
# Core
pip install flask psycopg2-binary requests cryptography bcrypt

# Optional: packet capture
pip install scapy
apt install tshark
```

- Python 3.9+
- PostgreSQL 13+
- Linux host (systemd optional but recommended for journal monitoring)
- Root or `sudo` for iptables active response and reading privileged log files

### Installation

```bash
git clone https://github.com/sonnyWilson/SCMS.git
cd SCMS
pip install -r requirements.txt

# Interactive installer — creates the database, all tables, an admin user,
# and writes a .env file with cryptographically random secrets.
sudo python3 install.py
```

The installer prompts for PostgreSQL credentials, Flask bind address and port, optional TLS paths, and optional SMTP settings. All secrets (`SECRET_KEY`, `API_KEY`, `FIELD_ENCRYPTION_KEY`) are generated with `secrets.token_hex()` — they are never hardcoded anywhere in the source.

---

## Configuration Reference

Settings resolve in priority order: `.env` file → environment variables → built-in safe defaults. The `.env` file is written `chmod 600` by the installer and must never be committed to version control.

| Variable | Default | Description |
|---|---|---|
| `SERVER_HOST` | `0.0.0.0` | Flask bind address |
| `SERVER_PORT` | `5000` | Flask port |
| `SERVER_URL` | `http://localhost:5000/ingest` | Agent ingest endpoint |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_NAME` | `scms` | Database name |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | *(empty)* | Database password |
| `API_KEY` | *(auto-generated)* | Shared secret — agent → server authentication |
| `SECRET_KEY` | *(auto-generated)* | Flask session signing key |
| `FIELD_ENCRYPTION_KEY` | *(auto-generated)* | 64-char hex key for AES-256-GCM field encryption |
| `LOG_FILES` | `/var/log/auth.log,...` | Comma-separated file paths for the agent to tail |
| `JOURNAL_UNITS` | `sshd,sudo,systemd,user` | Comma-separated systemd units to monitor |
| `TLS_CERT_PATH` | *(empty)* | Path to TLS certificate (PEM) |
| `TLS_KEY_PATH` | *(empty)* | Path to TLS private key (PEM) |
| `SMTP_HOST` | *(empty)* | SMTP server for alert emails |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | *(empty)* | SMTP authentication username |
| `SMTP_FROM` | *(empty)* | Alert sender address |
| `SMTP_TO` | *(empty)* | Alert recipients, comma-separated |
| `ENABLE_RATE_LIMIT` | `false` | Enable per-IP rate limiting |
| `ENABLE_CSP` | `true` | Enable Content-Security-Policy headers |
| `RATE_LIMIT_PER_MINUTE` | `30000000` | Max requests per IP per minute |

---

## Usage

```bash
# Start both the server and agent
python3 scms.py start

# Start components individually
python3 scms.py start server
python3 scms.py start agent

# Check component status (reads PID files from run/)
python3 scms.py status

# Tail logs (default: last 60 lines)
python3 scms.py logs server
python3 scms.py logs agent -n 100

# Restart after configuration changes
python3 scms.py restart

# Stop everything
python3 scms.py stop
```

The web dashboard is available at `http://localhost:5000` after the server starts.

---

## Security Concepts In Depth

This section explains not just *what* each module does, but *why* it is designed the way it is and how each security concept applies in real environments.

---

### 1. Log Collection & Buffered Delivery

**`agent.py` · `buffer.py`**

#### How it works

The agent runs **threaded tail workers** — one `_monitor_text_file()` thread per configured log file, one `_monitor_journal()` thread per systemd unit. Each worker reads new lines and calls `_send_log()`, which POSTs structured JSON to the `/ingest` endpoint with the `API_KEY` header. The agent registers `SIGTERM` and `SIGINT` handlers that set a shared `threading.Event`, allowing every thread to exit cleanly without error output — important when running as a managed systemd service.

```python
# From agent.py — clean shutdown on signal
def _handle_shutdown(sig, frame):
    log.info("Shutdown signal received — stopping agent …")
    _stop.set()

signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT,  _handle_shutdown)
```

If the server is unreachable (connection error or non-200 response), the event is serialized to `buffer.json` via `buffer.save()`. On the next successful send, `_flush_buffer()` drains the queue — events delivered successfully are removed; events that still fail stay buffered for the next retry. Agent logs rotate via `RotatingFileHandler` (10 MB per file, 3 backups).

#### Why this matters in production

In OT environments, the network link between the operational floor and the IT monitoring infrastructure is frequently unreliable — firewalled during maintenance windows, rate-limited, or temporarily severed during patching. A monitoring agent that silently drops events on network loss is useless for forensic purposes after an incident. The `buffer.json` approach provides delivery-eventually semantics with zero external dependencies (no Kafka, no RabbitMQ), keeping the agent deployable on minimal Linux hosts sitting next to PLCs.

---

### 2. Structured Log Parsing & Event Normalization

**`server/parser.py`**

#### The normalization problem

Raw log lines are unstructured strings. The fundamental challenge of any SIEM is converting heterogeneous, vendor-specific log formats into a common schema that correlation and detection logic can reason about uniformly. `parser.py` pattern-matches each incoming line against a hierarchy of event types and extracts structured fields into an event dict that maps directly to the `Logs` table columns:

| Event Type | What it captures | Real-world significance |
|---|---|---|
| `AUTH_FAIL` | Failed SSH/PAM logins | First indicator of brute-force or credential stuffing |
| `AUTH` | Successful logins | Baseline for who authenticates and when |
| `SUDO` | Privilege escalation via sudo | High-value event — maps to MITRE T1548.003 |
| `SUSPICIOUS_COMMAND` | Known recon or lateral-movement tooling | Post-exploitation indicator |
| `BASH_HISTORY` | Interactive shell commands | Rich forensic artefact on compromised hosts |
| `PKG_MGMT` | apt/yum/pip invocations | Common initial-access follow-on |
| `NET_CHANGE` | Interface state changes, new routes | Persistence or exfiltration setup |
| `CRON` | Scheduled task changes | Classic persistence mechanism |
| `SYS_ERROR` | Kernel panics, OOM events | Can precede or follow an attack |
| ICS events | Protocol-decoded payloads | See §3 |

Every parsed event gets a `Severity` rating (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) and a `MitreIds` field populated with the relevant ATT&CK technique IDs. Sensitive fields (`Message`, `RawLine`, `UserName`, `SourceIp`) are encrypted at rest before being written to PostgreSQL — see §10.

---

### 3. ICS/SCADA Protocol Decoding

**`server/parser.py` · `server/capture.py`**

#### Why ICS protocols need special handling

Industrial protocols were designed for reliability and determinism in isolated networks, not for security in connected ones. Modbus TCP, the most widely deployed industrial protocol in the world, has **no authentication** — any host that can send a valid frame to port 502 can read or write PLC registers without credentials. The only viable security control in this environment is *behavioural detection*: observe what normal traffic looks like and alert on deviations.

SCMS decodes the following protocols from captured packets:

| Protocol | Port | Environment | What SCMS detects |
|---|---|---|---|
| **Modbus TCP** | 502 | PLCs, RTUs, virtually all OT | Function code, register address, write vs. read, coil bursts |
| **DNP3** | 20000 | Electric utilities, water SCADA | Control block presence, NULL function floods |
| **EtherNet/IP (CIP)** | 44818 | Allen-Bradley PLCs, safety systems | Service code, safety assembly object access |
| **S7comm** | 102 | Siemens S7 PLCs | SSL read functions (data exfiltration indicator) |
| **BACnet** | 47808 | Building automation (HVAC, access) | Critical object interrogation |
| **IEC 60870-5-104** | 2404 | Power grid SCADA | ASDU type IDs, commands on the control channel |
| **OPC-UA** | 4840 | Cross-vendor data exchange | Unknown or unauthenticated sessions |

Decoded packets are stored in the `Packets` table with dedicated ICS columns (`ICSProtocol`, `ICSFunctionCode`, `ICSFunctionName`, `ICSAddress`, `ICSValue`) alongside geolocation enrichment (`GeoCountry`, `GeoCity`, `GeoLat`, `GeoLon`) and a `ThreatScore`. The `Anomaly` boolean and `AnomalyReason` fields enable rule-based packet-level flagging.

This layered approach — parsing at the log level *and* at the packet level — means SCMS can detect attacks that don't generate any syslog entry, such as a direct Modbus write from a rogue engineering workstation that bypasses the historian entirely.

---

### 4. MITRE ATT&CK Tagging

**`server/parser.py`**

The MITRE ATT&CK framework is a knowledge base of adversary tactics, techniques, and procedures observed in real-world attacks. The ICS matrix extends this to operational technology environments. Tagging every parsed event with the relevant technique ID transforms raw logs into intelligence — an analyst can query "all T1110 events in the last 24 hours" rather than manually correlating failed login patterns across multiple log files.

SCMS assigns `MitreIds` at parse time:

| Event Type | Technique ID | Technique Name |
|---|---|---|
| `AUTH_FAIL` (repeated) | T1110 | Brute Force |
| `SUDO` | T1548.003 | Abuse Elevation: Sudo |
| Modbus write to safety PLC | T0836 | Modify Parameter |
| `PKG_MGMT` | T1072 | Software Deployment Tools |
| `CRON` change | T1053 | Scheduled Task/Job |
| `NET_CHANGE` | T1562 | Impair Defenses |

Storing `MitreIds` as an indexed column in `Logs` means you can join across `Logs`, `Packets`, and `Incidents` on technique IDs to reconstruct an attack chain — for example, correlating a `T1110` brute-force campaign with a `T0836` Modbus write that followed from the same source IP 40 minutes later.

---

### 5. Safety Instrumented System (SIS) Trip Engine

**`server/sis.py`**

#### Background

A Safety Instrumented System is a dedicated control layer designed to bring a process to a safe state when predetermined conditions are met — emergency shutdown systems in chemical plants, turbine overspeed protection in power stations, pressure relief in oil refining. IEC 62443 and ISA-84 define Safety Integrity Levels (SIL 1–4) for these systems and mandate that safety functions remain operable even if the process control layer is compromised.

Attacking an SIS is among the most dangerous ICS threats. The TRITON/TRISIS malware (2017) specifically targeted Schneider Electric Triconex safety controllers, attempting to disable safety systems before triggering a process upset. SCMS implements a named rule engine in `sis.py` that evaluates decoded packets against rules derived from IEC 62443 requirements.

#### Rules implemented

| Rule ID | Trigger | SIL | Why it matters |
|---|---|---|---|
| SIS-001 | Modbus write to known safety PLC address | SIL-3 | Unauthorized parameter change on a safety function |
| SIS-002 | Modbus E-stop coil override | SIL-4 | Direct attempt to disable emergency shutdown |
| SIS-003 | Modbus mass register write (coil burst) | SIL-2 | Bulk modification — reconnaissance or sabotage |
| SIS-004 | DNP3 unauthorized control block | SIL-3 | Unsolicited control from a non-master station |
| SIS-005 | DNP3 NULL function flood | SIL-2 | Denial-of-service against SCADA master |
| SIS-006 | EtherNet/IP CIP access to safety assembly | SIL-3 | Targeted access to a safety I/O module |
| SIS-007 | IEC-104 command ASDU on control channel | SIL-3 | Unauthorized grid switching command |
| SIS-008 | ICS traffic from external source | SIL-2 | Traffic crossing the OT/IT boundary unexpectedly |
| SIS-009 | S7comm SSL read | SIL-2 | Data exfiltration from a Siemens safety PLC |
| SIS-010 | BACnet critical object interrogation | SIL-2 | Access to fire suppression or door-lock objects |
| SIS-011 | OPC-UA unknown session | SIL-2 | Unauthenticated data access attempt |

When a rule fires, the event is written to the `SIS_Events` table with full context (`RuleId`, `SrcIp`, `DstIp`, `AffectedDevice`, `AffectedZone`, `Action`, `ActionTaken`). The `Acknowledged` field and `AckBy`/`AckTime` columns support a formal acknowledgement workflow — unacknowledged SIS trips surface prominently on the dashboard so operators cannot silently dismiss safety events. The audit trail of who acknowledged what and when is preserved in PostgreSQL for post-incident review and regulatory reporting.

---

### 6. Security Configuration Assessment (CIS Benchmarks)

**`server/sca.py`**

The Center for Internet Security (CIS) publishes consensus-based security configuration guidelines for operating systems, services, and network devices. Compliance with these benchmarks is commonly required by PCI-DSS, HIPAA, and NIST CSF. `sca.py` implements 32 automated checks across six domains:

**Authentication policy** — password aging, minimum length, lockout thresholds, root login restrictions, SSH `PermitRootLogin`, `PasswordAuthentication`, and `MaxAuthTries` settings.

**Filesystem permissions** — permissions and ownership on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, and the `/tmp` mount (`noexec`/`nosuid` options).

**Network hardening** — IP forwarding disabled, ICMP redirects off, reverse path filtering enabled, SYN cookies enabled, core dump restrictions.

**Audit configuration** — auditd running, audit log size adequacy, logging of privileged command executions.

**Update policy** — unattended-upgrades installed, package cache freshness.

**ICS-specific hardening** — whether Modbus (502), DNP3 (20000), and EtherNet/IP (44818) ports are exposed on internet-facing interfaces; USB storage module status (`usb-storage` kernel module blacklisted).

Results produce a score per compliance framework with pass/fail counts and penalties for critical failures, giving operators an at-a-glance posture view without requiring a separate external scanner.

---

### 7. File Integrity Monitoring (FIM)

**`server/fim.py`**

FIM detects unauthorized changes to critical system files by comparing current cryptographic hashes against a known-good baseline. SHA-256 is used because it is collision-resistant — an attacker cannot craft a malicious `/etc/sudoers` that produces the same hash as the legitimate file.

SCMS monitors these paths by default:

```
/etc/passwd         /etc/shadow         /etc/group
/etc/sudoers        /etc/ssh/sshd_config
/etc/pam.d/common-auth                  /etc/hosts
/etc/crontab        /etc/rc.local
```

For each path, `fim.py` records the SHA-256 hash, file size, and `mtime`. Changes to any of these files are a high-confidence indicator of compromise: `/etc/passwd` modification suggests account creation or UID manipulation; `/etc/sudoers` changes can grant unprivileged users root access; `sshd_config` tampering can open backdoors via `AuthorizedKeysFile` redirection.

Note that `mtime` alone is insufficient — sophisticated attackers restore the original timestamp after modifying a file using `touch -t` or direct filesystem metadata manipulation. SHA-256 catches these cases because the hash is derived from file *content*, not metadata. SCMS stores both so analysts have two independent signals to correlate.

---

### 8. Vulnerability Scanning

**`server/vuln.py`**

`vuln.py` enumerates installed packages via `dpkg-query` (Debian/Ubuntu), `rpm` (RHEL/CentOS), and `pip3 list`, then cross-references the results against an **offline CVE baseline**. The offline approach is deliberate: OT hosts frequently cannot reach the internet, and a scanner that requires outbound connectivity to a vulnerability database is not deployable in air-gapped or restricted environments.

The baseline covers high-impact CVEs across packages most likely to be present on Linux ICS hosts:

- **OpenSSL** — underlying nearly every TLS connection on the host
- **OpenSSH** — remote access, the most commonly exposed service
- **sudo** — privilege escalation; CVE-2021-3156 (Baron Samedit) is included
- **curl / libcurl** — used by ICS software for historian REST API calls
- **Linux kernel** — local privilege escalation CVEs
- **Flask / Werkzeug** — relevant since SCMS itself runs on these
- **libmodbus** — the most common Modbus library in Linux-based SCADA gateways
- **Mosquitto** — MQTT broker used in IIoT deployments
- Additional ICS middleware packages

Results are sorted by severity and exposed in the dashboard. The baseline can be extended by adding entries to the CVE dict in `vuln.py` — no internet connectivity, subscription, or separate scanner agent required.

---

### 9. Active Response — iptables & SMTP

**`server/response.py`**

#### iptables IP blocking

When a brute-force threshold is crossed (configurable number of `AUTH_FAIL` events from a single source IP within a time window), `response.py` calls `block_ip()`, which inserts an `iptables -I INPUT 1 -s <ip> -j DROP` rule and records the block in an in-memory registry. `unblock_ip()` removes the rule and the registry entry. The module gracefully degrades to a simulated block (logged but not applied) if iptables is unavailable — useful when running in containers or without `CAP_NET_ADMIN`.

`block_ip()` requires root or `CAP_NET_ADMIN`. For deployments running the server as a non-root user, the correct approach is a sudoers rule scoped specifically to the `iptables` binary:

```
scms ALL=(root) NOPASSWD: /usr/sbin/iptables
```

Granting blanket sudo to the server process would itself be a significant privilege escalation risk.

#### SMTP alerts

Alert emails are dispatched in a daemon thread (non-blocking) using SMTP with STARTTLS on port 587. The thread model ensures a slow or unresponsive mail server cannot block the event ingestion pipeline. Credentials are read from environment variables.

#### Real-world consideration

Automated IP blocking in an ICS environment requires calibration. A Modbus master that is legitimately polling a PLC but has a misconfigured authentication module could generate enough `AUTH_FAIL` events to trigger an auto-block, silently stopping legitimate SCADA polling. Thresholds should be set against the observed baseline polling rate, and the block registry should be reviewed regularly.

---

### 10. AES-256-GCM Data-at-Rest Encryption

**`server/crypto.py`**

#### Why field-level encryption

Encrypting the entire PostgreSQL volume (disk encryption) protects data if physical media is stolen, but provides no protection against SQL injection, database credential theft, or a compromised application layer — an attacker with valid DB credentials can read every column in plaintext. Field-level encryption adds defense-in-depth: even with direct database access, sensitive columns are ciphertext blobs.

SCMS encrypts four `Logs` fields before writing them to PostgreSQL:

- `Message` — the human-readable log message
- `RawLine` — the original unparsed log line
- `UserName` — the username involved in the event
- `SourceIp` — the originating IP address

#### AES-256-GCM specifics

AES-256-GCM (Galois/Counter Mode) provides both **confidentiality** (data cannot be read without the key) and **authenticity** (any tampering with the ciphertext is detected via the authentication tag). The authentication guarantee is critical for a security tool — an attacker who can silently modify log entries can cover their tracks. GCM's auth tag ensures tampered ciphertext is rejected at decryption time.

The encryption key is derived from `FIELD_ENCRYPTION_KEY` using **HKDF-SHA256** (HMAC-based Key Derivation Function). Deriving a purpose-specific key from a master key rather than using the master key directly provides cryptographic separation between contexts and follows standard key derivation practice.

Encrypted values are stored with an `enc:` prefix, allowing the application to transparently pass through unencrypted values (when no key is configured) without code path changes. **Losing `FIELD_ENCRYPTION_KEY` makes the encrypted columns permanently unrecoverable** — the key must be backed up independently from the database.

---

### 11. Authentication, CSRF & Account Lockout

**`server/auth.py`**

#### Password hashing

SCMS uses **bcrypt** for password hashing (with Python's stdlib `scrypt` as a fallback). Bcrypt is purpose-built for password storage: it is intentionally slow (tunable work factor), incorporates a random salt per hash (preventing rainbow table and precomputed-hash attacks), and produces a self-contained string embedding the algorithm, work factor, and salt. A full database dump does not expose user passwords in any usable form.

#### Session security

Flask's session system uses a cryptographically signed cookie (`SECRET_KEY` is the signing key). The server validates the signature on every request — a tampered or forged session cookie is detected and rejected. Sessions are configured in `app.py` with security flags set at the application factory level:

```python
app.config["SESSION_COOKIE_HTTPONLY"] = True    # JS cannot read the cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # mitigates CSRF via cross-site requests
app.config["SESSION_COOKIE_SECURE"]  = False     # set True when TLS is enabled
app.config["PERMANENT_SESSION_LIFETIME"] = 8 * 3600  # 8-hour session expiry
```

`@login_required` and `@api_login_required` decorators gate every protected route. API endpoints that the agent calls use `@api_login_required`, which validates the `API_KEY` header rather than a session cookie — keeping agent authentication stateless.

#### CSRF protection

Cross-Site Request Forgery attacks trick an authenticated user's browser into making state-changing requests to the server from a different origin. SCMS issues a CSRF token per session and validates it on all state-mutating endpoints via the `@csrf_required` decorator. The token must be present in either the `X-CSRF-Token` header (AJAX dashboard calls) or the `_csrf_token` form field. An attacker operating from a different origin cannot read the token from the victim's session, so forged requests are rejected.

#### Account lockout

`auth.py` maintains an in-memory `_lockout` dict. After 10 consecutive failed login attempts, the account is locked for 5 minutes, preventing online brute-force attacks without added database complexity. The trade-off: the lockout state resets on server restart. For environments requiring persistent lockout across restarts, add `failed_attempts INTEGER DEFAULT 0` and `locked_until TIMESTAMPTZ` columns to `scms_users` and update `auth.py` to read/write them.

---

### 12. Security Headers & Rate Limiting

**`server/security.py`**

#### HTTP security headers

`add_security_headers()` is registered as a Flask `after_request` hook — every response, regardless of route, receives these headers:

| Header | Value | What it prevents |
|---|---|---|
| `Content-Security-Policy` | Per-request nonce on `script-src` | XSS via injected scripts that don't carry the nonce |
| `X-Frame-Options` | `DENY` | Clickjacking — the dashboard cannot be embedded in an iframe |
| `X-Content-Type-Options` | `nosniff` | MIME-sniffing attacks — browser honours the declared `Content-Type` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Leaking dashboard URLs in the `Referer` header to third parties |
| `Permissions-Policy` | Disables camera, microphone, geolocation | Limits browser API surface for any injected code |
| `Cache-Control` | `no-store` | Prevents sensitive dashboard data from being cached by proxies or browsers |

The CSP nonce is regenerated per request using `secrets.token_urlsafe()`. A static nonce is equivalent to no nonce — it must be unique per response for the protection to be meaningful against XSS injection.

#### Per-IP rate limiting

When `ENABLE_RATE_LIMIT=true`, `security.py` enforces a per-IP request limit using an in-memory counter dict. A background GC thread runs every 5 minutes to clear stale entries and prevent unbounded memory growth. Rate limiting protects against automated scanning, credential stuffing against the login endpoint, and denial-of-service against `/ingest` from a misbehaving agent.

---

## Database Schema

All tables are created by `setup_db.py` with `IF NOT EXISTS` (idempotent). Indexes are placed on every column that appears in dashboard `WHERE` clauses — time, IP, severity, status, and ICS protocol — ensuring sub-second queries across millions of rows.

| Table | Purpose | Key columns |
|---|---|---|
| `Logs` | Parsed log events | `EventTime`, `EventType`, `Severity`, `SourceIp`, `MitreIds`, `UserName`, `Protocol` |
| `Packets` | Captured network packets | `CaptureTime`, `SrcIp`, `DstIp`, `ICSProtocol`, `ICSFunctionCode`, `ThreatScore`, `Anomaly` |
| `Incidents` | Security incidents | `Severity`, `Status`, `MitreIds`, `AffectedHost`, `SisTripped`, `TimelineJson` |
| `Inventory` | Network asset inventory | `IpAddress`, `DeviceType`, `ICSProtocol`, `Criticality`, `Zone`, `IsICS` |
| `SIS_Events` | Safety trip events | `RuleId`, `Severity`, `TriggerProtocol`, `Acknowledged`, `AckBy`, `AckTime` |
| `GeoEvents` | IP geolocation enrichment | `SrcIp`, `GeoCountry`, `GeoCity`, `GeoLat`, `GeoLon`, `ThreatScore` |
| `scms_users` | User accounts | `username`, `password_hash`, `role`, `last_login`, `active` |

### Useful queries

```sql
-- Recent high-severity events
SELECT EventTime, EventType, Severity, SourceIp, UserName, Message
FROM Logs
WHERE Severity IN ('HIGH', 'CRITICAL')
ORDER BY EventTime DESC
LIMIT 50;

-- Brute-force candidates (>10 failures from same IP in the last hour)
SELECT SourceIp, COUNT(*) AS failures
FROM Logs
WHERE EventType = 'AUTH_FAIL'
  AND EventTime > NOW() - INTERVAL '1 hour'
GROUP BY SourceIp
HAVING COUNT(*) > 10
ORDER BY failures DESC;

-- Unacknowledged SIS trips
SELECT EventTime, RuleId, RuleName, SrcIp, AffectedDevice, Action
FROM SIS_Events
WHERE Acknowledged = FALSE
ORDER BY EventTime DESC;

-- ICS packet breakdown by protocol
SELECT ICSProtocol, COUNT(*) AS total,
       SUM(CASE WHEN Anomaly THEN 1 ELSE 0 END) AS flagged
FROM Packets
WHERE ICSProtocol IS NOT NULL
GROUP BY ICSProtocol
ORDER BY total DESC;

-- Events by MITRE technique
SELECT MitreIds, COUNT(*) AS n
FROM Logs
WHERE MitreIds IS NOT NULL
GROUP BY MitreIds
ORDER BY n DESC;
```

---

## Utility Scripts

| Script | Usage |
|---|---|
| `install.py` | First-run: DB creation, tables, admin user, `.env` generation |
| `setup_db.py` | Re-create tables and indexes without running the full installer |
| `reset_password.py` | `python3 reset_password.py [username]` — CLI password reset |
| `reset_all.py` | `python3 reset_all.py [--yes]` — truncate all event data, preserve schema and users |

---

## Deployment Hardening

Beyond the built-in controls, the following steps are strongly recommended for any production deployment:

**TLS termination** — set `TLS_CERT_PATH` and `TLS_KEY_PATH` in `.env`, then set `SESSION_COOKIE_SECURE = True` in `app.py`. Alternatively, terminate TLS at nginx or Caddy and proxy to Flask on localhost only.

**Restrict the ingest endpoint** — the `/ingest` endpoint only needs to be reachable by agent hosts. Firewall it to the agent IP range at the OS or network level.

**Non-root server process** — run the Flask server as a dedicated low-privilege user. Grant iptables access via a sudoers rule scoped to the `iptables` binary:
```
scms ALL=(root) NOPASSWD: /usr/sbin/iptables
```

**`.env` hygiene** — the file is `chmod 600` by the installer. Add it to `.gitignore`. Never commit it. Rotating `FIELD_ENCRYPTION_KEY` requires re-encrypting all encrypted columns — plan this into your key management process.

**Persistent account lockout** — the default in-memory lockout resets on restart. For production, add `failed_attempts INTEGER DEFAULT 0` and `locked_until TIMESTAMPTZ` to `scms_users` and update `auth.py` to persist lockout state across restarts.

**Separate agent credentials** — the `API_KEY` should be rotated periodically. Update it in `.env` on each agent host and on the server, then restart both.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Follow the existing style: type hints, `log = logging.getLogger("scms.<module>")`, docstrings on public functions.
3. Open a pull request with a description of the change and any security implications.

Report security vulnerabilities with me before opening a public issue.
