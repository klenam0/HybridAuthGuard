# backend/live_simulator.py
"""
Live event simulator - sends realistic login events to /api/ingest.

Simulates a running enterprise system:
- Continuous normal business-day login traffic
- Attack scenarios injected at configurable intervals
- Each scenario uses a fresh external IP

Usage:
    python live_simulator.py                        # defaults
    python live_simulator.py --rate 1.0             # 1 event/sec
    python live_simulator.py --attack-interval 60   # attack every 60s
    python live_simulator.py --no-attacks           # normal traffic only
"""

import os
import time
import random
import argparse
import requests
import sys
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

API_INGEST = "http://localhost:5000/api/ingest"
# /api/ingest requires the token configured as INGEST_TOKEN in backend/.env.
INGEST_HEADERS = {"X-Ingest-Token": os.environ.get("INGEST_TOKEN", "")}

# ── Normal enterprise users ────────────────────────────────────────────────────
USERS = {
    "Akua":   ["192.168.1.10", "192.168.1.11"],
    "Kofi":     ["192.168.1.15", "192.168.1.16"],
    "Kojo": ["10.0.0.5"],
    "Daisy":   ["10.0.0.10"],
    "Frank":   ["192.168.1.20"],
    "Grace":   ["10.0.1.5"],
    "Henry":   ["192.168.1.25"],
}
USER_LIST = list(USERS.keys())

# ── Attack scenario tracking ───────────────────────────────────────────────────
_used_attacker_ips = set()

def fresh_external_ip():
    """Generate an external IP not previously used in this session."""
    while True:
        ip = (
            f"{random.randint(45, 200)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}."
            f"{random.randint(1, 254)}"
        )
        if ip not in _used_attacker_ips:
            _used_attacker_ips.add(ip)
            return ip


# ── Event sender ───────────────────────────────────────────────────────────────
def send(user, ip, status, country="GH", device="desktop", timestamp=None):
    """Send a login event to the ingest API."""
    event = {
        "timestamp":   timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":        user,
        "ip":          ip,
        "status":      status,
        "country":     country,
        "device_type": device,
    }
    try:
        r = requests.post(API_INGEST, json=event, headers=INGEST_HEADERS, timeout=2)
        if r.status_code == 401:
            print("⚠  /api/ingest rejected the token - set INGEST_TOKEN in backend/.env")
            sys.exit(1)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        print("⚠  Cannot reach API - is api.py running?")
        sys.exit(1)
    except Exception:
        return False


# ── Normal traffic generator ───────────────────────────────────────────────────
def normal_event():
    """Send one realistic normal login event."""
    user   = random.choice(USER_LIST)
    ip     = random.choice(USERS[user])
    hour   = datetime.now().hour
    # Higher failure rate outside business hours (realistic)
    fail_rate = 0.03 if 8 <= hour <= 18 else 0.08
    status = "FAILED" if random.random() < fail_rate else "SUCCESS"
    ok = send(user, ip, status)
    marker = "✓" if ok else "✗"
    print(
        f"  {marker} {datetime.now().strftime('%H:%M:%S')} "
        f"| {user:10} | {ip:15} | {status}",
        flush=True
    )


# ── Attack scenarios ───────────────────────────────────────────────────────────
def attack_fast_brute_force():
    print("\n  🔴 ATTACK: Fast Brute Force")
    ip = fresh_external_ip()
    for _ in range(6):
        send("admin", ip, "FAILED", country="RU", device="bot")
        time.sleep(0.4)
    print(f"     IP: {ip} | 6 rapid failures\n")


def attack_slow_brute_force():
    print("\n  🔴 ATTACK: Slow Brute Force (4 attempts, backdated timestamps)")
    ip  = fresh_external_ip()
    now = datetime.now()
    for i in range(4):
        ts = (now - timedelta(minutes=(3 - i) * 10)).strftime("%Y-%m-%d %H:%M:%S")
        send("admin", ip, "FAILED", country="CN", device="unknown", timestamp=ts)
        time.sleep(0.3)
    print(f"     IP: {ip} | 4 failures over 30 minutes\n")


def attack_credential_stuffing():
    print("\n  🔴 ATTACK: Credential Stuffing")
    ip      = fresh_external_ip()
    targets = [
        "Akua", "Kofi", "Kojo", "admin", "root",
        "guest", "administrator", "service", "backup", "test"
    ]
    for user in targets:
        send(user, ip, "FAILED", country="BR", device="bot")
        time.sleep(0.2)
    print(f"     IP: {ip} | {len(targets)} unique usernames\n")


def attack_multiple_ip_login():
    print("\n  🔴 ATTACK: Multiple IP Login")
    user    = random.choice(USER_LIST)
    good_ip = random.choice(USERS[user])
    bad_ip  = fresh_external_ip()
    send(user, good_ip, "SUCCESS", country="GH")
    time.sleep(1)
    send(user, bad_ip,  "SUCCESS", country="NG")
    print(f"     User: {user} | {good_ip} then {bad_ip} (30s apart)\n")


def attack_suspicious_time():
    print("\n  🔴 ATTACK: Suspicious Login Time")
    user = random.choice(USER_LIST)
    ip   = random.choice(USERS[user])
    ts   = datetime.now().replace(
        hour=random.choice([1, 2, 3, 4]),
        minute=random.randint(0, 59)
    ).strftime("%Y-%m-%d %H:%M:%S")
    send(user, ip, "SUCCESS", timestamp=ts)
    print(f"     User: {user} | Timestamp: {ts}\n")


def attack_ml_anomaly():
    print("\n  🔴 ATTACK: ML Anomaly (unknown external IP)")
    ip = fresh_external_ip()
    for _ in range(3):
        send("admin", ip, "FAILED", country="KP", device="bot")
        time.sleep(0.5)
    print(f"     IP: {ip} | Unknown country + bot device + failures\n")


ALL_ATTACKS = [
    attack_fast_brute_force,
    attack_slow_brute_force,
    attack_credential_stuffing,
    attack_multiple_ip_login,
    attack_suspicious_time,
    attack_ml_anomaly,
]


# ── Main loop ──────────────────────────────────────────────────────────────────
def run(event_interval=1.0, attack_interval=120, no_attacks=False):
    """
    Main simulation loop.

    Args:
        event_interval:  seconds between normal login events
        attack_interval: seconds between attack scenario injections
        no_attacks:      if True, only send normal traffic
    """
    print("=" * 55)
    print("  LIVE EVENT SIMULATOR")
    print("=" * 55)
    print(f"\n  Event rate:      1 event every {event_interval}s")
    if no_attacks:
        print("  Attack mode:     disabled")
    else:
        print(f"  Attack interval: every {attack_interval}s")
    print(f"  API endpoint:    {API_INGEST}")
    print("\n  Press Ctrl+C to stop\n")
    print("-" * 55)

    # Verify API is reachable before starting
    try:
        requests.get("http://localhost:5000/api/status", timeout=3)
    except Exception:
        print("❌ Cannot reach api.py - start it first:")
        print("   python api.py")
        sys.exit(1)

    events_sent     = 0
    attacks_sent    = 0
    last_attack_time = time.time()
    attack_index    = 0

    try:
        while True:
            # Send one normal event
            normal_event()
            events_sent += 1

            # Check if it's time for an attack
            if not no_attacks:
                if time.time() - last_attack_time >= attack_interval:
                    scenario = ALL_ATTACKS[attack_index % len(ALL_ATTACKS)]
                    scenario()
                    attacks_sent     += 1
                    attack_index     += 1
                    last_attack_time  = time.time()

            time.sleep(event_interval)

    except KeyboardInterrupt:
        print(f"\n{'─' * 55}")
        print(f"⏹  Simulator stopped")
        print(f"   Normal events sent: {events_sent:,}")
        print(f"   Attack scenarios:   {attacks_sent}")
        print(f"   Unique attacker IPs: {len(_used_attacker_ips)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Live login event simulator for SOC system"
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Seconds between normal events (default: 1.0)"
    )
    parser.add_argument(
        "--attack-interval",
        type=int,
        default=120,
        help="Seconds between attack injections (default: 120)"
    )
    parser.add_argument(
        "--no-attacks",
        action="store_true",
        help="Send only normal traffic (no attacks)"
    )
    args = parser.parse_args()
    run(
        event_interval=args.rate,
        attack_interval=args.attack_interval,
        no_attacks=args.no_attacks,
    )