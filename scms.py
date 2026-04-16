#!/usr/bin/env python3
"""
scms.py — Secure Continuous Monitoring System CLI control
Manages server and agent processes
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RUN_DIR  = BASE_DIR / "run"
LOG_DIR  = BASE_DIR / "logs"

SERVICES = {
    "server": {
        "script":  BASE_DIR / "run_server.py",
        "pidfile": RUN_DIR  / "server.pid",
        "logfile": LOG_DIR  / "server.log",
        "label":   "SCMS Server",
    },
    "agent": {
        "script":  BASE_DIR / "agent.py",
        "pidfile": RUN_DIR  / "agent.pid",
        "logfile": LOG_DIR  / "agent.log",
        "label":   "SCMS Agent",
    },
}

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"; B="\033[1m"; X="\033[0m"


def _read_pid(pidfile):
    try:
        return int(pidfile.read_text().strip())
    except Exception:
        return None


def _write_pid(pidfile, pid):
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.write_text(str(pid))


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _is_running(name):
    svc = SERVICES[name]
    pid = _read_pid(svc["pidfile"])
    if pid and _pid_alive(pid):
        return True, pid
    return False, pid


def _clean_pidfile(svc):
    svc["pidfile"].unlink(missing_ok=True)


def cmd_start(name):
    svc = SERVICES[name]
    running, pid = _is_running(name)
    if running:
        print(f"  {Y}  {svc['label']} already running (PID {pid}){X}")
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # FIXED: use with-block so parent's file handle is closed after Popen
    with open(svc["logfile"], "a") as logfile:
        proc = subprocess.Popen(
            [sys.executable, str(svc["script"])],
            stdout=logfile, stderr=logfile,
            cwd=BASE_DIR,
            start_new_session=True,
        )

    _write_pid(svc["pidfile"], proc.pid)
    time.sleep(0.5)

    if _pid_alive(proc.pid):
        print(f"  {G}  {svc['label']} started  (PID {proc.pid}){X}")
        print(f"     Log → {svc['logfile']}")
    else:
        print(f"  {R}  {svc['label']} crashed immediately — check {svc['logfile']}{X}")
        _clean_pidfile(svc)


def cmd_stop(name, timeout=10):
    svc = SERVICES[name]
    running, pid = _is_running(name)
    if not running:
        print(f"  {Y}  {svc['label']} is not running{X}")
        _clean_pidfile(svc)
        return

    print(f"  {C}→  Stopping {svc['label']} (PID {pid}) …{X}")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_alive(pid):
            break
        time.sleep(0.3)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    _clean_pidfile(svc)
    print(f"  {G}  {svc['label']} stopped{X}")


def cmd_status():
    print(f"\n  {B}SCMS Service Status{X}\n  {'─'*40}")
    for name, svc in SERVICES.items():
        running, pid = _is_running(name)
        state = f"{G} RUNNING{X} (PID {pid})" if running else f"{R} STOPPED{X}"
        print(f"  {B}{svc['label']:<26}{X}  {state}")
    print()


def cmd_logs(name, lines):
    svc = SERVICES[name]
    if not svc["logfile"].exists():
        print(f"  {Y}No log file: {svc['logfile']}{X}")
        return
    print(f"\n  {B}=== {svc['label']} — last {lines} lines ==={X}")
    r = subprocess.run(["tail", "-n", str(lines), str(svc["logfile"])],
                       capture_output=True, text=True)
    print(r.stdout)


def _targets(t):
    if t in ("both", None):
        return list(SERVICES)
    if t in SERVICES:
        return [t]
    print(f"  {R}Unknown target '{t}'{X}")
    sys.exit(1)


def main():
    p = argparse.ArgumentParser(prog="scms", description="SCMS control")
    p.add_argument("command", choices=["start","stop","restart","status","logs"])
    p.add_argument("target", nargs="?", default="both",
                   choices=["server","agent","both"])
    p.add_argument("-n","--lines", type=int, default=60)
    args = p.parse_args()

    if args.command == "status":
        cmd_status(); return

    if args.command == "logs":
        t = args.target if args.target != "both" else "server"
        cmd_logs(t, args.lines); return

    targets = _targets(args.target)

    if args.command == "start":
        for t in targets: cmd_start(t)
    elif args.command == "stop":
        for t in reversed(targets): cmd_stop(t)
    elif args.command == "restart":
        for t in reversed(targets): cmd_stop(t)
        time.sleep(1)
        for t in targets: cmd_start(t)


if __name__ == "__main__":
    main()
