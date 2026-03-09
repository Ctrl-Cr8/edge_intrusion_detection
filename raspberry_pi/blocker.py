# blocker.py — Linux/Pi only, must run as sudo

import subprocess
import threading

# ── Protected IPs — never blocked ─────────────────────────────────────────────
PROTECTED_IPS = {
    "192.168.1.5",
    
}

active_timers = {}
_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────
def _run(cmd):
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"[BLOCKER] iptables error: {e.stderr.decode().strip()}")

def _save():
    """Persist iptables rules so they survive reboot."""
    _run(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])

def _get_timeout(anomaly_score: float) -> int:
    """Scale timeout based on anomaly score (score 40–69 range)."""
    if anomaly_score >= 65:
        return 600   # 10 minutes
    elif anomaly_score >= 55:
        return 300   # 5 minutes
    else:
        return 120   # 2 minutes

def _unblock_and_cleanup(ip: str):
    """Called automatically when a temporary block timer expires."""
    unblock_ip(ip)
    with _lock:
        if ip in active_timers:
            del active_timers[ip]

# ── Core functions ─────────────────────────────────────────────────────────────
def block_ip(ip: str, permanent: bool = False, anomaly_score: float = 50.0):
    if ip in PROTECTED_IPS:
        print(f"[BLOCKER] Skipped block for protected IP: {ip}")
        return

    if is_blocked(ip):
        print(f"[BLOCKER] {ip} already blocked, skipping")
        return

    with _lock:
        if ip in active_timers:
            active_timers[ip].cancel()
            del active_timers[ip]

    _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    _save()

    if permanent:
        print(f"[BLOCKER] Permanently blocked {ip} (score={anomaly_score})")
    else:
        timeout = _get_timeout(anomaly_score)
        print(f"[BLOCKER] Temporarily blocked {ip} for {timeout}s (score={anomaly_score})")
        timer = threading.Timer(timeout, _unblock_and_cleanup, args=[ip])
        timer.daemon = True
        with _lock:
            active_timers[ip] = timer
        timer.start()

def unblock_ip(ip: str):
    if ip in PROTECTED_IPS:
        print(f"[BLOCKER] Refused to unblock protected IP: {ip}")
        return
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    _save()
    print(f"[BLOCKER] Unblocked {ip}")

def is_blocked(ip: str) -> bool:
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0

def get_active_timers() -> dict:
    """Return which IPs are on temporary blocks."""
    with _lock:
        return {ip: "temporary" for ip in active_timers}