# backend/tests/test_rules.py
"""
Rule-engine edge cases from audit experiment E5
(audit_scratch/e5_detection_edges.py), written as the CORRECT behaviour of
the v3 rule engine (config.RULES_MODE = "v3", Phase 3).

The v3 parameters are pinned here (PINNED) so these cases do not move when
the dev_val selection changes the defaults in config.py. On the legacy
engine every case below fails: that is the point of the audit findings
F01, F02, F16, F17, F18 and F19.

Events are passed through agent.analyze_all() (a list of the alerts raised
for that event). An agent without analyze_all() is driven through
analyze_event(), which returns at most one alert.

Run from backend/:  python -m pytest tests/test_rules.py -v
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents.detection_agent import DetectionAgent  # noqa: E402

BF = "Brute Force Attack"
SLOW = "Slow Brute Force"
CS = "Credential Stuffing"
DIST = "Distributed Brute Force"
SAF = "Success After Failures"
MULTI = "Multiple IP Login"
OFF_HOURS = "Suspicious Login Time"

PINNED = dict(
    RULES_MODE="v3",
    V3_BF_WINDOW_SECONDS=600, V3_BF_MIN_FAILURES=5,
    V3_SLOW_BF_WINDOW_SECONDS=6 * 3600, V3_SLOW_BF_MIN_FAILURES=4,
    V3_SLOW_BF_MIN_SPREAD_SECONDS=300,
    V3_CS_WINDOW_SECONDS=3600, V3_CS_MIN_ACCOUNTS=5,
    V3_INVALID_WINDOW_SECONDS=3600, V3_INVALID_MIN_ATTEMPTS=5,
    V3_DIST_WINDOW_SECONDS=3600, V3_DIST_MIN_IPS=5,
    V3_SAF_WINDOW_SECONDS=3600, V3_SAF_MIN_FAILURES=3,
    V3_MULTI_IP_WINDOW_SECONDS=120, V3_MULTI_IP_EXEMPT=(),
    V3_DEDUP_SECONDS={"default": 3600, OFF_HOURS: 600},
)

T = datetime(2026, 10, 12, 10, 0, 0)


@pytest.fixture
def v3(monkeypatch):
    for k, v in PINNED.items():
        monkeypatch.setattr(config, k, v, raising=False)


class FlagEverything:
    """ML stub: every event is anomalous; records which events were scored."""

    def __init__(self):
        self.scored = []

    def score_event(self, e):
        self.scored.append(e)
        return {"is_anomaly": True, "anomaly_score": -0.3,
                "confidence": "High", "feature_count": 10}


def ev(ts, user, ip, status):
    return {"timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"), "user": user, "ip": ip,
            "status": status}


def run(events, ml=None):
    """Alert types per event, as a list of sets."""
    agent = DetectionAgent(anomaly_detector=ml)
    out = []
    for e in events:
        if hasattr(agent, "analyze_all"):
            alerts = agent.analyze_all(dict(e))
        else:
            a = agent.analyze_event(dict(e))
            alerts = [a] if a else []
        out.append({a["type"] for a in alerts})
    return out


def count(types, name):
    return sum(name in s for s in types)


# ── F01: success after brute force ──────────────────────────────────────────

def test_success_after_brute_force_is_alerted_and_every_event_is_scored(v3):
    ml = FlagEverything()
    evs = [ev(T + timedelta(seconds=i), "alice", "6.6.6.6", "FAILED") for i in range(5)]
    evs.append(ev(T + timedelta(seconds=10), "alice", "6.6.6.6", "SUCCESS"))
    types = run(evs, ml=ml)
    assert BF in types[4]
    assert SAF in types[5], "the compromise (SUCCESS after 5 failures) must alert"
    assert len(ml.scored) == 6, "the ML step must see every event, blocked IP or not"


# ── F02: windows, not lifetime counters; no permanent blindness ────────────

def test_one_failure_a_day_for_five_days_is_not_brute_force(v3):
    types = run([ev(T + timedelta(days=i), "bob", "7.7.7.7", "FAILED") for i in range(5)])
    assert count(types, BF) == 0
    assert count(types, SLOW) == 0


def test_week_two_reattack_after_a_block_is_detected(v3):
    evs = [ev(T + timedelta(seconds=i), "dave", "5.5.5.5", "FAILED") for i in range(5)]
    evs += [ev(T + timedelta(days=7, seconds=i), "dave", "5.5.5.5", "FAILED") for i in range(50)]
    types = run(evs)
    assert count(types[:5], BF) >= 1
    assert count(types[5:], BF) >= 1, "a returning attacker must be alerted again"


# ── F16: per-account counting, status and username normalisation ───────────

def test_rotating_ips_against_one_account(v3):
    types = run([ev(T + timedelta(seconds=i), "ceo", f"20.0.{i // 250}.{i % 250}", "FAILED")
                 for i in range(200)])
    assert count(types, DIST) >= 1


def test_fifty_ips_four_failures_each(v3):
    evs = []
    for k in range(50):
        for j in range(4):
            evs.append(ev(T + timedelta(seconds=10 * (4 * k + j)), f"user{(k + j) % 10}",
                          f"30.0.0.{k}", "FAILED"))
    types = run(evs)
    assert count(types, DIST) >= 1


def test_lowercase_failed_counts_as_a_failure(v3):
    evs = [{"timestamp": "2026-10-12 10:00:%02d" % i, "user": "u", "ip": "1.1.1.9",
            "status": "failed"} for i in range(10)]
    types = run(evs)
    assert count(types, BF) >= 1


def test_username_case_and_whitespace_variants_are_one_account(v3):
    names = ["admin", "Admin", "ADMIN", "admin ", " admin"]
    types = run([ev(T + timedelta(seconds=i), u, "3.3.3.3", "FAILED")
                 for i, u in enumerate(names)])
    assert count(types, CS) == 0, "five spellings of one account are not stuffing"
    assert BF in types[4], "they are five failures against one account"


# ── F18: Credential Stuffing counts failing accounts only ──────────────────

def test_nat_ip_with_five_users_then_spread_out_typos(v3):
    evs = [ev(T + timedelta(minutes=i), u, "8.8.8.8", "SUCCESS") for i, u in enumerate("abcde")]
    evs += [ev(T + timedelta(hours=2 * i + 1), u, "8.8.8.8", "FAILED")
            for i, u in enumerate("abcde")]
    types = run(evs)
    assert count(types, CS) == 0
    assert all(not s for s in types), f"no alert expected, got {types}"


# ── F17: Slow Brute Force spacing, ordering, duplicate delivery ────────────

def test_slow_brute_force_spacing(v3):
    every_30_min = run([ev(T + timedelta(minutes=30 * i), "root", "9.9.9.9", "FAILED")
                        for i in range(8)])
    assert count(every_30_min, BF) == 0, "8 failures over 3.5 h are not fast brute force"
    assert SLOW in every_30_min[3], "slow brute force fires at the 4th spaced failure"

    every_10_min = run([ev(T + timedelta(minutes=10 * i), "root", "9.9.9.8", "FAILED")
                        for i in range(8)])
    assert count(every_10_min, BF) == 0
    assert SLOW in every_10_min[3]


def test_slow_brute_force_newest_first_arrival(v3):
    types = run([ev(T + timedelta(minutes=10 * (3 - i)), "root", "9.9.9.7", "FAILED")
                 for i in range(4)])
    assert SLOW in types[3], "arrival order must not change what the window holds"


def test_duplicate_delivery_counts_once(v3):
    types = run([ev(T, "gus", "4.4.4.4", "FAILED")] * 5)
    assert count(types, BF) == 0
    assert count(types, SLOW) == 0


# ── F19: every matching detector is reported; state always updated ─────────

def test_off_hours_login_with_ip_switch_reports_both(v3):
    evs = [ev(datetime(2026, 10, 12, 3, 0, 0), "erin", "1.2.3.4", "SUCCESS"),
           ev(datetime(2026, 10, 12, 3, 0, 30), "erin", "4.3.2.1", "SUCCESS")]
    types = run(evs)
    assert OFF_HOURS in types[1]
    assert MULTI in types[1]


def test_off_hours_login_still_updates_last_login(v3):
    evs = [ev(datetime(2026, 10, 12, 5, 59, 30), "fay", "1.1.1.1", "SUCCESS"),
           ev(datetime(2026, 10, 12, 6, 0, 10), "fay", "2.2.2.2", "SUCCESS")]
    types = run(evs)
    assert OFF_HOURS in types[0]
    assert MULTI in types[1], "the off-hours login must be remembered as the last login"
