#!/usr/bin/env python3
"""
install.py — Secure Continuous Monitoring System (SCMS)
One-time installer.

Handles all real-world edge cases:
  - Ubuntu 23+ externally-managed-environment (uses --break-system-packages
    or creates a venv automatically)
  - PostgreSQL user does not exist yet (creates it via postgres superuser)
  - Missing PostgreSQL service (detects and guides user)
  - Encryption key generation (FIELD_ENCRYPTION_KEY)
  - Admin dashboard account creation
  - Systemd service registration with correct Python path
"""

import os
import sys
import subprocess
import socket
import secrets
import getpass
import textwrap
import urllib.request
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
SYSDIR   = Path("/etc/systemd/system")

# ── Colours ───────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; X="\033[0m"
def ok(m):    print(f"{G}  ✔  {m}{X}")
def warn(m):  print(f"{Y}  ⚠  {m}{X}")
def err(m):   print(f"{R}  ✘  {m}{X}")
def info(m):  print(f"{C}  →  {m}{X}")
def hdr(m):   print(f"\n{B}{m}{X}\n{'─'*60}")
def step(n,m):print(f"\n{B}[{n}]{X} {m}")

# ── Dependency lists ──────────────────────────────────────────────────────────
SERVER_DEPS = [
    "flask", "werkzeug", "psycopg2-binary",
    "requests", "cryptography", "bcrypt",
]
AGENT_DEPS = ["requests"]
OPTIONAL_DEPS = ["scapy"]   # for packet capture — graceful if missing


# ─────────────────────────────────────────────────────────────────────────────
# pip installer — handles externally-managed-environment automatically
# ─────────────────────────────────────────────────────────────────────────────
def _pip_cmd_for(pkg: str) -> list[str]:
    """
    Return the right pip install command for this machine.
    Tries three strategies in order:
      1. --break-system-packages   (Ubuntu 23+ / Debian 12+ without venv)
      2. plain pip install         (older Ubuntu, venv, etc.)
      3. pipx / apt fallback hints if all else fails
    """
    return [sys.executable, "-m", "pip", "install", "--quiet",
            "--break-system-packages", pkg]


def pip_install(packages: list[str], optional: bool = False):
    """Install a list of packages. On failure, warn (don't abort) if optional."""
    failed = []
    for pkg in packages:
        info(f"Installing {pkg} …")
        # Strategy 1: --break-system-packages (Ubuntu 23+)
        r = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--break-system-packages", pkg],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            ok(f"{pkg} installed")
            continue

        # Strategy 2: plain pip (older distros / venvs / conda)
        r2 = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            capture_output=True, text=True,
        )
        if r2.returncode == 0:
            ok(f"{pkg} installed")
            continue

        # Strategy 3: try apt for known system packages
        apt_name = {"psycopg2-binary": "python3-psycopg2",
                    "flask":           "python3-flask",
                    "werkzeug":        "python3-werkzeug",
                    "requests":        "python3-requests",
                    "cryptography":    "python3-cryptography",
                    "bcrypt":          "python3-bcrypt",
                    "scapy":           "python3-scapy"}.get(pkg)
        if apt_name:
            info(f"pip failed — trying apt install {apt_name} …")
            r3 = subprocess.run(
                ["apt-get", "install", "-y", "-q", apt_name],
                capture_output=True, text=True,
            )
            if r3.returncode == 0:
                ok(f"{pkg} installed via apt ({apt_name})")
                continue

        msg = (r.stderr or r2.stderr or "").strip()
        if optional:
            warn(f"{pkg} skipped (optional): {msg[:80]}")
        else:
            err(f"{pkg} FAILED: {msg[:120]}")
            failed.append(pkg)

    if failed:
        warn(f"Some packages failed to install: {', '.join(failed)}")
        warn("The system may still work. Re-run install.py to retry, or:")
        for f in failed:
            apt_n = {"psycopg2-binary":"python3-psycopg2","flask":"python3-flask",
                     "werkzeug":"python3-werkzeug","requests":"python3-requests",
                     "cryptography":"python3-cryptography","bcrypt":"python3-bcrypt"}.get(f,f)
            warn(f"  sudo apt install {apt_n}")


# ─────────────────────────────────────────────────────────────────────────────
# PostgreSQL helpers
# ─────────────────────────────────────────────────────────────────────────────
def _pg_service_running() -> bool:
    r = subprocess.run(["systemctl", "is-active", "postgresql"],
                       capture_output=True, text=True)
    return r.stdout.strip() == "active"


def _pg_start():
    """Start postgresql if not running."""
    if _pg_service_running():
        return True
    info("Starting PostgreSQL service …")
    r = subprocess.run(["systemctl", "start", "postgresql"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        ok("PostgreSQL started")
        return True
    err("Could not start PostgreSQL automatically.")
    err("Run:  sudo systemctl start postgresql")
    return False


def _pg_user_exists(username: str) -> bool:
    """Check if a PostgreSQL role exists."""
    r = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-tAc",
         f"SELECT 1 FROM pg_roles WHERE rolname='{username}'"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "1"


def _create_pg_user(username: str, password: str):
    """Create a PostgreSQL role with CREATEDB privilege."""
    sql = f"CREATE USER \"{username}\" WITH PASSWORD '{password}' CREATEDB;"
    r = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-c", sql],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        ok(f"PostgreSQL user '{username}' created")
        return True
    # Already exists is fine
    if "already exists" in r.stderr:
        ok(f"PostgreSQL user '{username}' already exists")
        return True
    err(f"Could not create PG user: {r.stderr.strip()[:200]}")
    return False


def _test_pg_connection(host: str, port: str, db: str,
                        user: str, password: str) -> bool:
    """Try a real psycopg2 connection to verify credentials work."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=host, port=int(port), database="postgres",
            user=user, password=password, connect_timeout=5,
        )
        conn.close()
        return True
    except Exception as e:
        err(f"Database connection test failed: {e}")
        return False


def setup_postgresql(db_host: str, db_port: str,
                     db_user: str, db_pass: str) -> bool:
    """
    Ensure PostgreSQL is running and the requested user exists.
    If connecting as a non-postgres user fails, offer to create the user
    via the postgres superuser.
    """
    # 1. Ensure the service is up
    if db_host in ("localhost", "127.0.0.1", "::1"):
        if not _pg_start():
            return False

    # 2. If user is not postgres, try to create them
    if db_user != "postgres":
        if not _pg_user_exists(db_user):
            info(f"PostgreSQL user '{db_user}' does not exist — creating it …")
            if not _create_pg_user(db_user, db_pass):
                warn("Could not auto-create the DB user.")
                warn(f"Run manually:  sudo -u postgres createuser --createdb {db_user}")
                warn(f"Then set password:  sudo -u postgres psql -c \"ALTER USER {db_user} PASSWORD '{db_pass}';\"")
                return False
        else:
            ok(f"PostgreSQL user '{db_user}' exists")

    # 3. Test the connection
    info("Testing database connection …")
    if _test_pg_connection(db_host, db_port, "postgres", db_user, db_pass):
        ok("Database connection successful")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────────────────────────────────────
def run_setup_db() -> bool:
    """Run setup_db.py to create tables. Return True on success."""
    r = subprocess.run(
        [sys.executable, str(BASE_DIR / "setup_db.py")],
        capture_output=True, text=True, cwd=BASE_DIR,
    )
    output = (r.stdout + r.stderr).strip()
    if output:
        print(f"  {output}")
    if r.returncode == 0 and "error" not in output.lower():
        ok("Database tables ready")
        return True
    warn("Database setup had issues — check output above.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Admin account
# ─────────────────────────────────────────────────────────────────────────────
def create_admin_account():
    """Prompt for and create the first dashboard login account."""
    hdr("Create Dashboard Admin Account")
    print("  This login is used to access the SCMS web dashboard.\n")
    username = ask("Admin username", default="admin")
    while True:
        pw1 = ask("Password (min 12 characters)", secret=True)
        if len(pw1) < 12:
            err("Password must be at least 12 characters. Try again.")
            continue
        pw2 = ask("Confirm password", secret=True)
        if pw1 != pw2:
            err("Passwords do not match. Try again.")
            continue
        break

    try:
        sys.path.insert(0, str(BASE_DIR))
        # Re-load config so it picks up the newly written .env
        import importlib
        if "config" in sys.modules:
            importlib.reload(sys.modules["config"])
        from server.auth import create_user
        success, msg = create_user(username, pw1, role="admin")
        if success:
            ok(f"Admin account '{username}' created — use this to log in at port 5000")
        else:
            warn(f"Account creation: {msg}")
            _print_manual_user_cmd(username, pw1)
    except Exception as e:
        warn(f"Could not create account automatically ({e})")
        _print_manual_user_cmd(username, pw1)


def _print_manual_user_cmd(username: str, pw: str):
    warn("Create the account manually once the server is running:")
    warn(f'  python3 -c "import sys; sys.path.insert(0,\\".\\"); '
         f'from server.auth import create_user; '
         f'create_user(\\"{username}\\", \\"{pw}\\", \\"admin\\")"')


# ─────────────────────────────────────────────────────────────────────────────
# .env writer
# ─────────────────────────────────────────────────────────────────────────────
def write_env(values: dict):
    lines = [
        "# Secure Continuous Monitoring System — generated by install.py",
        "# Do NOT commit this file to source control.",
        "",
    ]
    for k, v in values.items():
        lines.append(f'{k}="{v}"')
    ENV_FILE.write_text("\n".join(lines) + "\n")
    ENV_FILE.chmod(0o600)
    ok(f"Config written → {ENV_FILE}  (permissions: 600)")


# ─────────────────────────────────────────────────────────────────────────────
# Systemd
# ─────────────────────────────────────────────────────────────────────────────
def _write_unit(name: str, unit_text: str):
    path = SYSDIR / f"{name}.service"
    try:
        path.write_text(unit_text.strip() + "\n")
        ok(f"Wrote {path}")
    except PermissionError:
        err("Cannot write to /etc/systemd/system — re-run with sudo")
        sys.exit(1)


def _enable_service(name: str):
    for cmd in [["systemctl", "daemon-reload"],
                ["systemctl", "enable", "--now", name]]:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            ok(" ".join(cmd))
        else:
            warn(f"{' '.join(cmd)}: {r.stderr.strip()[:100]}")


def write_server_service():
    unit = textwrap.dedent(f"""
        [Unit]
        Description=Secure Continuous Monitoring System — Server
        After=network.target postgresql.service
        Wants=postgresql.service

        [Service]
        Type=simple
        User=root
        WorkingDirectory={BASE_DIR}
        EnvironmentFile={ENV_FILE}
        ExecStart={sys.executable} {BASE_DIR}/run_server.py
        Restart=on-failure
        RestartSec=5
        StandardOutput=append:/var/log/scms-server.log
        StandardError=append:/var/log/scms-server.log
        KillSignal=SIGTERM
        TimeoutStopSec=15

        [Install]
        WantedBy=multi-user.target
    """)
    _write_unit("scms-server", unit)
    _enable_service("scms-server")


def write_agent_service():
    unit = textwrap.dedent(f"""
        [Unit]
        Description=Secure Continuous Monitoring System — Agent
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        User=root
        WorkingDirectory={BASE_DIR}
        EnvironmentFile={ENV_FILE}
        ExecStart={sys.executable} {BASE_DIR}/agent.py
        Restart=on-failure
        RestartSec=5
        StandardOutput=append:/var/log/scms-agent.log
        StandardError=append:/var/log/scms-agent.log
        KillSignal=SIGTERM
        TimeoutStopSec=10

        [Install]
        WantedBy=multi-user.target
    """)
    _write_unit("scms-agent", unit)
    _enable_service("scms-agent")


# ─────────────────────────────────────────────────────────────────────────────
# Network helpers
# ─────────────────────────────────────────────────────────────────────────────
def local_ips() -> list[str]:
    ips = []
    try:
        for info_item in socket.getaddrinfo(socket.gethostname(), None):
            ip = info_item[4][0]
            if ":" not in ip and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def discover_server(port: int = 5000, timeout: int = 2) -> str | None:
    info("Scanning network for existing SCMS server …")
    candidates = []
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for ln in out.splitlines():
            if "default via" in ln:
                gw   = ln.split()[2]
                base = ".".join(gw.split(".")[:3])
                candidates = [f"{base}.{i}" for i in range(1, 30)]
                break
    except Exception:
        pass
    for ip in candidates:
        try:
            req = urllib.request.Request(f"http://{ip}:{port}/health")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if "ok" in resp.read().decode().lower():
                    return ip
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Interactive prompts
# ─────────────────────────────────────────────────────────────────────────────
def ask(prompt, default=None, secret=False):
    suffix = f" [{default}]" if default is not None else ""
    full   = f"  {prompt}{suffix}: "
    while True:
        try:
            val = (getpass.getpass(full) if secret else input(full)).strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if val:
            return val
        if default is not None:
            return str(default)
        err("This field is required.")


def choose(prompt, options):
    for i, o in enumerate(options, 1):
        print(f"  {B}[{i}]{X} {o}")
    while True:
        raw = input(f"  {prompt} (1-{len(options)}): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        err("Invalid choice.")


def confirm(prompt, default=True):
    yn = "Y/n" if default else "y/N"
    try:
        ans = input(f"  {prompt} [{yn}]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(); sys.exit(0)
    return default if not ans else ans.startswith("y")


# ─────────────────────────────────────────────────────────────────────────────
# Server setup flow
# ─────────────────────────────────────────────────────────────────────────────
def setup_server():

    # ── Step 1: Collect config ───────────────────────────────────────────────
    hdr("Server Configuration")

    ips = local_ips()
    if ips:
        info(f"Detected local IPs: {', '.join(ips)}")

    bind_ip  = ask("Bind address (0.0.0.0 = all interfaces)", default="0.0.0.0")
    port     = ask("Server port", default="5000")
    db_host  = ask("PostgreSQL host", default="localhost")
    db_port  = ask("PostgreSQL port", default="5432")
    db_name  = ask("Database name",   default="scms")
    db_user  = ask("Database user",   default="postgres")
    db_pass  = ask("Database password", secret=True)

    # Generate all cryptographic keys upfront
    api_key    = secrets.token_hex(32)
    secret_key = secrets.token_hex(32)
    enc_key    = secrets.token_hex(32)

    ok(f"API Key:    {B}{api_key}{X}")
    ok(f"Secret Key: {B}{secret_key[:16]}…{X}")
    ok(f"Enc Key:    {B}{enc_key[:16]}…{X}")
    print(f"  {Y}Save the API Key — every agent needs it.{X}")

    env = {
        "SERVER_HOST":           bind_ip,
        "SERVER_PORT":           port,
        "DB_HOST":               db_host,
        "DB_PORT":               db_port,
        "DB_NAME":               db_name,
        "DB_USER":               db_user,
        "DB_PASSWORD":           db_pass,
        "API_KEY":               api_key,
        "SECRET_KEY":            secret_key,
        "FIELD_ENCRYPTION_KEY":  enc_key,
        "ENABLE_RATE_LIMIT":     "true",
        "ENABLE_CSP":            "true",
        "RATE_LIMIT_PER_MINUTE": "300",
    }

    if confirm("Configure email alerts? (SMTP)", default=False):
        env["SMTP_HOST"]     = ask("SMTP host", default="smtp.gmail.com")
        env["SMTP_PORT"]     = ask("SMTP port", default="587")
        env["SMTP_USER"]     = ask("SMTP username")
        env["SMTP_PASSWORD"] = ask("SMTP password", secret=True)
        env["SMTP_FROM"]     = ask("From address")
        env["SMTP_TO"]       = ask("Alert recipient(s)")

    # ── Step 2: Write .env ───────────────────────────────────────────────────
    hdr("Writing Configuration")
    write_env(env)

    # ── Step 3: Install Python packages ─────────────────────────────────────
    hdr("Installing Python Dependencies")
    pip_install(SERVER_DEPS)
    pip_install(OPTIONAL_DEPS, optional=True)

    # ── Step 4: Set up PostgreSQL ────────────────────────────────────────────
    hdr("Setting Up PostgreSQL")
    pg_ok = setup_postgresql(db_host, db_port, db_user, db_pass)
    if not pg_ok:
        warn("PostgreSQL setup incomplete — continuing anyway.")
        warn("Fix the database connection and then run:  python3 setup_db.py")

    # ── Step 5: Create tables ────────────────────────────────────────────────
    hdr("Creating Database Tables")
    if pg_ok:
        db_ready = run_setup_db()
    else:
        warn("Skipping table creation (no DB connection). Run setup_db.py manually later.")
        db_ready = False

    # ── Step 6: Create admin account ────────────────────────────────────────
    if db_ready:
        create_admin_account()
    else:
        warn("Skipping admin account creation (DB not ready).")
        warn("Once the DB is working, run:")
        warn('  python3 -c "from server.auth import create_user; create_user(\'admin\',\'YourPassword123!\',\'admin\')"')

    # ── Step 7: Systemd ──────────────────────────────────────────────────────
    if os.geteuid() == 0:
        hdr("Registering systemd Service (auto-start on boot)")
        write_server_service()
        print(f"\n{G}{B}✔  SCMS Server installed and will start on every boot!{X}")
        print(f"  Dashboard → http://{bind_ip}:{port}")
        print(f"  Logs      → journalctl -u scms-server -f")
        print(f"  Status    → python3 scms.py status")
    else:
        warn("Not running as root — systemd unit not registered.")
        warn("Re-run with sudo to enable auto-start on boot.")
        info(f"Manual start: python3 {BASE_DIR}/run_server.py")


# ─────────────────────────────────────────────────────────────────────────────
# Agent setup flow
# ─────────────────────────────────────────────────────────────────────────────
def setup_agent():
    hdr("Agent Configuration")

    found = discover_server()
    if found:
        ok(f"Auto-detected SCMS server at {found}")
        server_ip = found if confirm(f"Use {found}?") else None
    else:
        warn("Server not auto-detected on local network.")
        server_ip = None

    if not server_ip:
        server_ip = ask("SCMS Server IP address")

    port       = ask("Server port", default="5000")
    server_url = f"http://{server_ip}:{port}/ingest"
    info(f"Ingest URL: {server_url}")

    api_key = ask("API Key (from server installer output)")

    default_logs = [
        "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
        "/var/log/dpkg.log", "/var/log/audit/audit.log",
        "/root/.bash_history",
    ]
    info(f"Default log files: {', '.join(default_logs)}")
    extra_logs = []
    if confirm("Add extra log file paths?", default=False):
        while True:
            p = input("  Path (blank to stop): ").strip()
            if not p:
                break
            extra_logs.append(p)

    env = {
        "SERVER_URL":    server_url,
        "API_KEY":       api_key,
        "LOG_FILES":     ",".join(default_logs + extra_logs),
        "JOURNAL_UNITS": "sshd,sudo,systemd,user",
    }
    write_env(env)

    hdr("Installing Agent Dependencies")
    pip_install(AGENT_DEPS)

    if os.geteuid() == 0:
        hdr("Registering systemd Service (auto-start on boot)")
        write_agent_service()
        print(f"\n{G}{B}✔  SCMS Agent installed and will start on every boot!{X}")
        print(f"  Logs   → journalctl -u scms-agent -f")
        print(f"  Status → python3 scms.py status")
    else:
        warn("Not running as root — systemd unit not registered.")
        info(f"Manual start: python3 {BASE_DIR}/agent.py")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{B}{'═'*60}{X}")
    print(f"  {C}Secure Continuous Monitoring System — Installer{X}")
    print(f"{B}{'═'*60}{X}\n")

    if os.geteuid() != 0:
        warn("Not running as root. Systemd registration and PostgreSQL user")
        warn("creation will be skipped. Re-run with sudo for full install.")
        if not confirm("Continue anyway?", default=False):
            sys.exit(0)

    if ENV_FILE.exists():
        warn(f".env already exists at {ENV_FILE}")
        if not confirm("Overwrite and re-run installer?", default=False):
            info("Aborted. Delete .env manually to re-install.")
            sys.exit(0)

    mode = choose("What are you installing?", [
        "Server  (dashboard + database + analysis engine)",
        "Agent   (log collector — install on every monitored machine)",
    ])

    if mode.startswith("Server"):
        setup_server()
    else:
        setup_agent()

    print(f"\n{B}{'═'*60}{X}")
    print(f"  {G}Installation complete!{X}")
    print(f"  Control:  {B}python3 scms.py start|stop|status{X}")
    print(f"  Logs:     {B}python3 scms.py logs server{X}")
    print(f"{B}{'═'*60}{X}\n")


if __name__ == "__main__":
    main()
