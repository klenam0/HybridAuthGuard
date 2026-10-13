# backend/tests/test_rules_v3_state.py
"""
v3 state model (Phase 3.2-3.4): response-layer block list with TTL and
"event from blocked source", alert de-duplication with expiry, bounded
memory, unknown-account attempts, the windowed ML failed_rate counters and
the Multiple IP Login exemptions.

Run from backend/:  python -m pytest tests/test_rules_v3_state.py -v
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents.analysis_agent import AnalysisAgent  # noqa: E402
from agents.detection_agent import DetectionAgent  # noqa: E402
from agents.response_agent import ResponseAgent  # noqa: E402
from tests.test_rules import PINNED, FlagEverything, ev  # noqa: E402

BF, CS, INVALID = "Brute Force Attack", "Credential Stuffing", "Invalid Account Spraying"
DIST, SAF, MULTI = "Distributed Brute Force", "Success After Failures", "Multiple IP Login"
PLACEHOLDER = "-4324475583306591935"
T = datetime(2026, 10, 12, 10, 0, 0)


class _NoEmail:
    enabled = False


@pytest.fixture
def v3(monkeypatch):
    for k, v in PINNED.items():
        monkeypatch.setattr(config, k, v, raising=False)
    monkeypatch.setattr(config, "UNKNOWN_ACCOUNT_IDS", [PLACEHOLDER])
    monkeypatch.setattr(config, "V3_BLOCK_DETECTORS", (BF,))
    monkeypatch.setattr(config, "BLOCK_TTL_SECONDS", 3600)
    return monkeypatch


def types_of(agent, e):
    return {a["type"] for a in agent.analyze_all(dict(e))}


def test_blocked_source_is_still_detected_and_the_block_expires(v3):
    ml = FlagEverything()
    agent = DetectionAgent(anomaly_detector=ml)
    analysis, response = AnalysisAgent(), ResponseAgent(email_alerter=_NoEmail())
    assert agent.__class__.__name__ == "V3DetectionAgent" and response.mode == "v3"

    def process(e):
        blocked = response.is_blocked(e["ip"], e["timestamp"])
        alerts = agent.analyze_all(dict(e))
        for a in alerts:
            a["timestamp"] = e["timestamp"]
            response.take_action(analysis.evaluate_alert(a))
        return blocked, {a["type"] for a in alerts}

    out = [process(ev(T + timedelta(seconds=i), "zoe", "6.6.6.1", "FAILED")) for i in range(5)]
    assert BF in out[4][1] and not any(b for b, _ in out)
    # Within the TTL: blocked, but every detector and the ML step still run.
    blocked, _ = process(ev(T + timedelta(seconds=30), "zoe", "6.6.6.1", "SUCCESS"))
    assert blocked
    assert len(ml.scored) == 6
    # After the TTL the block has expired.
    blocked, _ = process(ev(T + timedelta(seconds=3700), "zoe", "6.6.6.1", "FAILED"))
    assert not blocked


def test_dedup_suppresses_inside_cooldown_and_expires(v3):
    agent = DetectionAgent()
    out = [types_of(agent, ev(T + timedelta(seconds=i), "a", "1.0.0.1", "FAILED"))
           for i in range(10)]
    assert sum(BF in s for s in out) == 1
    later = [types_of(agent, ev(T + timedelta(seconds=3700 + i), "a", "1.0.0.1", "FAILED"))
             for i in range(5)]
    assert BF in later[4]
    # The suppressed matches were still recorded as matches.
    agent2 = DetectionAgent()
    dets = [agent2.analyze(ev(T + timedelta(seconds=i), "a", "1.0.0.2", "FAILED")) for i in range(7)]
    assert [BF in d.matched for d in dets] == [False] * 4 + [True] * 3
    assert [bool(d.alerts) for d in dets] == [False] * 4 + [True] + [False] * 2


def test_state_stays_bounded(v3):
    v3.setattr(config, "V3_KNOWN_IP_TTL_SECONDS", 86400)
    agent = DetectionAgent()
    spacing = 10
    for i in range(200_000):
        e = ev(T + timedelta(seconds=spacing * i), f"user{i}",
               f"{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}.1", "FAILED" if i % 3 else "SUCCESS")
        agent.analyze_all(e)
    sizes = agent.state_sizes()
    slack = 4096 + 16          # eviction runs every 4096 events
    assert sizes["ips"] <= 6 * 3600 // spacing + slack
    assert sizes["accounts"] <= 3600 // spacing + slack
    assert sizes["account_history"] <= 86400 // spacing + slack
    assert sizes["cooldowns"] <= 3600 // spacing + slack
    assert sizes["recent_events"] <= 300 // spacing + slack


def test_unknown_account_attempts(v3):
    agent = DetectionAgent()
    evs = [ev(T + timedelta(seconds=i), PLACEHOLDER, "2.0.0.1", "FAILED") for i in range(5)]
    evs += [ev(T + timedelta(seconds=10 + i), f"real{i}", "2.0.0.1", "FAILED") for i in range(4)]
    out = [types_of(agent, e) for e in evs]
    assert INVALID in out[4]
    assert not any(CS in s for s in out), "the placeholder is not a distinct account"
    assert not any(BF in s for s in out), "unknown-account attempts are not counted as failures"
    assert PLACEHOLDER not in agent.accounts.d and PLACEHOLDER not in agent.history.d
    # 200 IPs failing on the placeholder are not a distributed attack on an account.
    agent = DetectionAgent()
    out = [types_of(agent, ev(T + timedelta(seconds=i), PLACEHOLDER, f"3.0.0.{i}", "FAILED"))
           for i in range(200)]
    assert not any(DIST in s for s in out)


def test_success_after_failures_account_branch_from_new_ip(v3):
    agent = DetectionAgent()
    for i in range(3):
        types_of(agent, ev(T + timedelta(seconds=i), "kim", f"4.0.0.{i}", "FAILED"))
    assert SAF in types_of(agent, ev(T + timedelta(seconds=60), "kim", "4.0.0.99", "SUCCESS"))
    assert SAF not in types_of(agent, ev(T + timedelta(seconds=7200), "kim", "4.0.0.98", "SUCCESS"))


def test_credential_stuffing_counts_failing_accounts(v3):
    agent = DetectionAgent()
    out = [types_of(agent, ev(T + timedelta(seconds=i), f"acct{i}", "5.0.0.1", "FAILED"))
           for i in range(5)]
    assert CS in out[4] and BF in out[4], "every matching detector is reported"


@pytest.mark.parametrize("exempt,second_ip,asn,expect", [
    ((), "9.9.9.2", None, True),
    (("same_prefix",), "9.9.9.2", None, False),
    (("same_prefix",), "9.9.8.2", None, True),
    (("same_asn",), "8.8.8.8", 64500, False),
    (("same_asn",), "8.8.8.8", None, True),
])
def test_multi_ip_exemptions(v3, exempt, second_ip, asn, expect):
    v3.setattr(config, "V3_MULTI_IP_EXEMPT", exempt)
    agent = DetectionAgent()
    e1 = dict(ev(T, "lee", "9.9.9.1", "SUCCESS"), asn=asn)
    e2 = dict(ev(T + timedelta(seconds=30), "lee", second_ip, "SUCCESS"), asn=asn)
    types_of(agent, e1)
    assert (MULTI in types_of(agent, e2)) is expect


def test_multi_ip_known_ip_exemption(v3):
    v3.setattr(config, "V3_MULTI_IP_EXEMPT", ("known_ip",))
    agent = DetectionAgent()
    types_of(agent, ev(T, "max", "7.0.0.2", "SUCCESS"))                       # 7.0.0.2 known
    types_of(agent, ev(T + timedelta(hours=1), "max", "7.0.0.1", "SUCCESS"))
    assert MULTI not in types_of(agent, ev(T + timedelta(hours=1, seconds=20), "max", "7.0.0.2", "SUCCESS"))
    assert MULTI in types_of(agent, ev(T + timedelta(hours=1, seconds=40), "max", "7.0.0.3", "SUCCESS"))


def test_windowed_ml_failed_rate():
    from ml.anomaly_model import AnomalyDetector
    d = AnomalyDetector()
    d.set_failed_rate_window(2)              # today and yesterday
    day = timedelta(days=1)
    for k, st in [(0, True), (0, True), (1, False), (3, False)]:
        d._count_windowed("1.1.1.1", (T + k * day).strftime("%Y-%m-%d %H:%M:%S"), st)
        if k == 1:
            assert d._windowed_failed_rate("1.1.1.1") == pytest.approx(2 / 3)
    assert d._windowed_failed_rate("1.1.1.1") == 0.0     # day 3: days 0-1 dropped
    assert len(d._ip_windows["1.1.1.1"].b) == 1
    d._count_windowed("2.2.2.2", (T + 10 * day).strftime("%Y-%m-%d %H:%M:%S"), True)
    assert "1.1.1.1" not in d._ip_windows, "idle IPs are evicted"


def test_legacy_mode_is_unchanged_engine(monkeypatch):
    monkeypatch.setattr(config, "RULES_MODE", "legacy")
    agent = DetectionAgent()
    assert agent.__class__.__name__ == "LegacyDetectionAgent"
    assert AnalysisAgent().mode == "legacy" and ResponseAgent(email_alerter=_NoEmail()).mode == "legacy"


def test_config_holds_the_val_a_selection():
    """config.py's V3_* values are the ones chosen on val_a (Phase 3b,
    amendment 3), and no detector blocks."""
    path = os.path.join(BACKEND, "results", "phase3b_selection.json")
    if not os.path.exists(path):
        pytest.skip("results/phase3b_selection.json not present")
    from eval.phase3b import chosen_settings
    _, settings = chosen_settings()
    for k, v in settings.items():
        got = getattr(config, k)
        assert (tuple(got) if isinstance(v, tuple) else got) == v, k
    assert tuple(config.V3_BLOCK_DETECTORS) == ()
