# backend/utils/log_generator.py
"""
Synthetic log generator.

Two modes:
  generate_logs()          - batch demo mode (all 6 attack scenarios guaranteed)
  generate_training_data() - normal-only data for offline ML training
"""

import logging
import json
import random
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


# ── Dedicated IPs - never shared between background and attack scenarios ────────
_INTERNAL_IPS    = ["192.168.1.10", "192.168.1.15", "10.0.0.5"]
_NORMAL_USERS    = ["Akua", "Kofi", "Kojo", "Daisy", "Frank"]

_IP_FAST_BRUTE   = "203.0.113.45"    # Scenario 1: fast brute force
_IP_SUSPICIOUS   = "192.168.1.10"    # Scenario 2: suspicious time (internal)
_IP_MULTI_A      = "192.168.1.15"    # Scenario 3: multiple IP - first login
_IP_MULTI_B      = "203.0.113.99"    # Scenario 3: multiple IP - second login
_IP_SLOW_BRUTE   = "45.33.32.156"    # Scenario 4: slow brute force
_IP_STUFFING     = "198.51.100.23"   # Scenario 5: credential stuffing
_IP_ML_ANOMALY   = "185.220.101.45"  # Scenario 6: ML anomaly (unknown external)
_IP_SECOND_BRUTE = "91.108.56.190"   # Extra: second fast brute force attacker


def generate_logs(output_path="backend/data/raw_logs.txt", n_background=300):
    """
    Generate synthetic login events guaranteeing all 6 attack scenarios fire.

    Background traffic:
    - Max 5% failure rate per internal IP
    - Hard cap: no internal IP fails more than 3 times
      (prevents accidental brute force triggers)
    - All background failures spread across different IPs

    Attack scenarios (all guaranteed):
    1. Fast Brute Force       - 6 rapid failures from _IP_FAST_BRUTE
    2. Suspicious Login Time  - 4 successful logins at 01:30–04:15
    3. Multiple IP Login      - Kojo logs in from two IPs 30s apart
    4. Slow Brute Force       - 4 failures over 30+ minutes from _IP_SLOW_BRUTE
    5. Credential Stuffing    - 10 unique usernames from _IP_STUFFING
    6. ML Anomaly             - unknown external IP with repeated failures
    """
    logs = []
    start_time = datetime(2026, 2, 27, 8, 0, 0)

    # ── Background: controlled normal activity ─────────────────────────────────
    ip_failure_counts = {ip: 0 for ip in _INTERNAL_IPS}

    timestamps = sorted([
        start_time + timedelta(minutes=random.randint(1, 600))
        for _ in range(n_background)
    ])

    for ts in timestamps:
        user = random.choice(_NORMAL_USERS)
        ip   = random.choice(_INTERNAL_IPS)

        # Enforce failure cap - prevents accidental brute force triggers
        if ip_failure_counts[ip] >= 3:
            status = "SUCCESS"
        else:
            # 5% natural failure rate (forgotten password etc.)
            status = "FAILED" if random.random() < 0.05 else "SUCCESS"
            if status == "FAILED":
                ip_failure_counts[ip] += 1

        logs.append(
            f"{ts.strftime('%Y-%m-%d %H:%M:%S')} "
            f"user={user} ip={ip} status={status}"
        )

    # ── Scenario 1: Fast Brute Force (18:25) ──────────────────────────────────
    for i in range(6):
        logs.append(
            f"2026-02-27 18:25:0{i} user=admin ip={_IP_FAST_BRUTE} status=FAILED"
        )

    # ── Scenario 2: Suspicious Login Time (01:30–04:15) ───────────────────────
    suspicious_events = [
        ("Kojo", _IP_SUSPICIOUS, "01:30:00"),
        ("Akua",   _IP_SUSPICIOUS, "02:12:00"),
        ("Kofi",     "10.0.0.5",     "03:45:00"),
        ("admin",   _IP_SUSPICIOUS, "04:15:00"),
    ]
    for user, ip, t in suspicious_events:
        logs.append(f"2026-02-27 {t} user={user} ip={ip} status=SUCCESS")

    # ── Scenario 3: Multiple IP Login - Kojo (10:00) ───────────────────────
    logs.append(f"2026-02-27 10:00:00 user=Kojo ip={_IP_MULTI_A} status=SUCCESS")
    logs.append(f"2026-02-27 10:00:30 user=Kojo ip={_IP_MULTI_B} status=SUCCESS")

    # ── Scenario 4: Slow Brute Force (09:00–09:30, 10 min apart) ─────────────
    slow_base = datetime(2026, 2, 27, 9, 0, 0)
    for i in range(4):
        ts = slow_base + timedelta(minutes=i * 10)
        logs.append(
            f"{ts.strftime('%Y-%m-%d %H:%M:%S')} "
            f"user=admin ip={_IP_SLOW_BRUTE} status=FAILED"
        )

    # ── Scenario 5: Credential Stuffing (14:00–14:02) ────────────────────────
    stuffing_targets = [
        "Akua", "Kofi", "Kojo", "admin", "root",
        "guest", "administrator", "service", "backup", "test"
    ]
    stuffing_base = datetime(2026, 2, 27, 14, 0, 0)
    for i, target_user in enumerate(stuffing_targets):
        ts = stuffing_base + timedelta(seconds=i * 15)
        logs.append(
            f"{ts.strftime('%Y-%m-%d %H:%M:%S')} "
            f"user={target_user} ip={_IP_STUFFING} status=FAILED"
        )

    # ── Scenario 6: ML Anomaly - unknown external IP (22:05–22:35) ───────────
    ml_events = [
        ("admin",   "22:05:00", "FAILED"),
        ("admin",   "22:15:00", "FAILED"),
        ("root",    "22:25:00", "FAILED"),
        ("sysadmin","22:35:00", "FAILED"),
    ]
    for user, t, status in ml_events:
        logs.append(
            f"2026-02-27 {t} user={user} ip={_IP_ML_ANOMALY} status={status}"
        )

    # ── Extra: second fast brute force at 19:10 ───────────────────────────────
    for i in range(6):
        logs.append(
            f"2026-02-27 19:10:0{i} user=Akua ip={_IP_SECOND_BRUTE} status=FAILED"
        )

    # ── Multiple IP Login: Akua at 16:00 ─────────────────────────────────────
    logs.append(f"2026-02-27 16:00:00 user=Akua ip={_IP_MULTI_A} status=SUCCESS")
    logs.append(f"2026-02-27 16:00:45 user=Akua ip={_IP_MULTI_B} status=SUCCESS")

    # ── Sort chronologically ──────────────────────────────────────────────────
    logs.sort()

    with open(output_path, "w") as f:
        for line in logs:
            f.write(line + "\n")

    total = len(logs)
    log.info(f"✅ {total} log events generated → {output_path}")
    log.info(f"   Background: {n_background} events (capped at 3 failures/IP)")
    log.info(f"   Attack scenarios: 6 planted (all guaranteed to fire)")
    return total


def generate_training_data(
    output_path="backend/data/training_logs.json",
    n=10000
):
    """
    Generate normal-only events for offline Isolation Forest training.
    No attack scenarios - purely legitimate business activity.
    """
    users = [
        "Akua", "Kofi", "Kojo", "Daisy", "eve",
        "Frank", "Grace", "Henry", "iris", "jack",
        "admin", "sysadmin", "devops", "support"
    ]
    internal_ips = [
        "192.168.1.10", "192.168.1.11", "192.168.1.12",
        "192.168.1.15", "192.168.1.20", "192.168.1.25",
        "10.0.0.5",     "10.0.0.10",    "10.0.0.15",
        "10.0.1.5",     "10.0.1.10",    "172.16.0.5",
    ]
    user_ips = {
        user: random.sample(internal_ips, k=random.randint(1, 2))
        for user in users
    }

    events   = []
    base_date = datetime(2026, 1, 1, 0, 0, 0)

    for _ in range(n):
        user = random.choice(users)
        ip   = random.choice(user_ips[user])

        roll = random.random()
        if roll < 0.80:
            hour   = random.randint(8, 18)
            minute = random.randint(0, 59)
        elif roll < 0.92:
            hour   = random.randint(19, 22)
            minute = random.randint(0, 59)
        else:
            hour   = random.randint(0, 7)
            minute = random.randint(0, 59)

        day_offset = random.randint(0, 89)
        timestamp  = base_date + timedelta(
            days=day_offset, hours=hour, minutes=minute
        )
        status = "FAILED" if random.random() < 0.08 else "SUCCESS"

        events.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user":      user,
            "ip":        ip,
            "status":    status,
        })

    events.sort(key=lambda e: e["timestamp"])

    with open(output_path, "w") as f:
        json.dump(events, f, indent=2)

    log.info(f"✅ Training dataset: {len(events):,} normal events → {output_path}")
    log.info(f"   Users: {len(users)} | IPs: {len(internal_ips)} | Span: 90 days")
    log.info(f"   Failure rate: ~8% (realistic enterprise baseline)")


if __name__ == "__main__":
    generate_logs()
    generate_training_data()