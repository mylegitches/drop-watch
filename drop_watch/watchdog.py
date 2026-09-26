"""
drop_watch.watchdog
====================
Tiny watchdog: if drop-watch is not running, start it.
Runs as a separate background process. Sleep 30s, check, repeat.
Never dies on its own — kill it via Task Manager.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

CHECK_INTERVAL_S = 30
STARTUP_GRACE_S = 10  # give a freshly-started process this long before checking again

PROJECT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_DIR / "config.local.json"


def is_running() -> bool:
    """Return True if a python -m drop_watch run process is alive."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV", "/NH"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            text=True,
            timeout=5,
        )
    except Exception:
        return False
    # tasklist CSV rows have format: "python.exe","PID","SessionName","Session#","MemUsage"
    # We can't tell from just the image name which python is ours. Better: check by window title.
    # Fallback: assume if a python.exe is running with the monitor script path open, we have it.
    # Simplest heuristic that actually works: search the running tasklist for our log file handle.
    # Since that's hard cross-platform, instead check that the DB is being written to.
    db = PROJECT_DIR / "drop_watch.db"
    if not db.exists():
        return False
    age = time.time() - db.stat().st_mtime
    return age < CHECK_INTERVAL_S * 2  # DB touched within 2 check intervals = alive


def start_monitor() -> subprocess.Popen:
    """Launch drop-watch in the background. Returns the Popen."""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) | getattr(
        subprocess, "DETACHED_PROCESS", 0x00000008
    )
    log_file = open(PROJECT_DIR / "logs" / "drop_watch.log", "a", encoding="utf-8")
    log_file.write(f"\n[watchdog] starting drop-watch at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    log_file.flush()
    return subprocess.Popen(
        [sys.executable, "-m", "drop_watch", "run", "--config", str(CONFIG_PATH)],
        cwd=str(PROJECT_DIR),
        stdout=log_file,
        stderr=log_file,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
        close_fds=True,
    )


def main() -> int:
    print(f"[watchdog] starting; will check every {CHECK_INTERVAL_S}s")
    print(f"[watchdog] project: {PROJECT_DIR}")
    while True:
        if is_running():
            print(f"[watchdog] {time.strftime('%H:%M:%S')} drop-watch alive")
        else:
            print(f"[watchdog] {time.strftime('%H:%M:%S')} drop-watch NOT running — starting it")
            try:
                start_monitor()
                time.sleep(STARTUP_GRACE_S)
            except Exception as e:
                print(f"[watchdog] failed to start: {e}")
        time.sleep(CHECK_INTERVAL_S)


if __name__ == "__main__":
    sys.exit(main())
