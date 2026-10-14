# backend/tests/test_phase5_policy.py
"""
Phase 5 (eval/PROTOCOL.md amendment 6): incident triage and the graded
response tiers, email per incident (cooldown, hourly limit, digest), the
SQLite alert store and the API reading it, the ingest schema, and the
model loading of main.py.

Run from backend/:  python -m pytest tests/test_phase5_policy.py -v
"""

import json
import os
import sys
from datetime import datetime, timedelta

import numpy as np
import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import triage as TR  # noqa: E402
from agents.response_agent import ResponseAgent  # noqa: E402
from tests.test_rules import PINNED, ev  # noqa: E402

BF, CS, OFF = "Brute Force Attack", "Credential Stuffing", "Suspicious Login Time"
PLACEHOLDER = "-4324475583306591935"
T = datetime(2026, 10, 12, 10, 0, 0)
DAY = 86400


class Mail:
    """Records incident emails and digests."""
    enabled = True

    def __init__(self):
        self.incidents, self.digests = [], []

    def send_incident(self, incident):
        self.incidents.append(incident["incident_id"])
        return True

    def send_digest(self, hour, incidents):
        self.digests.append((hour, [i["incident_id"] for i in incidents]))
        return True


class Store:
    def __init__(self):
        self.saved = []

    def save_alert(self, a):
        self.saved.append(a)


@pytest.fixture
def v3(monkeypatch):
    for k, v in PINNED.items():
        monkeypatch.setattr(config, k, v, raising=False)
    monkeypatch.setattr(config, "UNKNOWN_ACCOUNT_IDS", [PLACEHOLDER])
    monkeypatch.setattr(config, "ML_MODE", "legacy")
    # Amendment 6/7 mechanics; the floor (amendment 8) has its own tests.
    monkeypatch.setattr(config, "RESPONSE_FLOOR_DETECTORS", ())
    return monkeypatch


def tracker(score="T1", rates=None, floor=()):
    return TR.IncidentTriage(score=score, rates=rates or {"block": 1, "step_up": 2, "queue": 3},
                             floor=floor)


def inc(ip, tier, prev="log"):
    return {"incident_id": f"{ip}|1", "ip": ip, "tier": tier, "previous_tier": prev,
            "detectors": [BF], "score": [1, 0.5], "alerts": 1}


# ── Triage: scores, causal rate-based tiers ──────────────────────────────────

def test_scores_follow_the_amendment_6_definitions():
    tr = tracker("T2")
    e = {"ip": "1.1.1.1", "user": "a", "status": "FAILED", "asn": 7}
    tr.observe(e, 100)
    tr.observe(dict(e, status="SUCCESS"), 101)
    i = tr.assess(e, 101, [CS, OFF, "ML Anomaly Detected"])
    p = config.TRIAGE_DETECTOR_PRECISION
    # ASN 7: first event ratio 0, second 1/1 -> max 1.0; ML alerts are ignored.
    assert i["score"] == [max(p[CS], p[OFF]), 1.0] and i["detectors"] == [CS, OFF]
    assert tracker("T1").score_name == "T1"
    assert tr.assess(e, 101, ["ML Anomaly Detected"]) is None


def test_tiers_use_the_previous_days_cutoff_and_are_sticky():
    tr = tracker("T1")
    ip = lambda k: f"10.0.0.{k}"   # noqa: E731
    # Day 0: four incidents with 1..4 detectors: no completed day -> all log.
    dets = [BF, CS, OFF, "Slow Brute Force"]
    for k in range(1, 5):
        e = {"ip": ip(k), "user": "u", "status": "FAILED", "asn": k}
        tr.observe(e, 10 + k)
        assert tr.assess(e, 10 + k, dets[:k])["tier"] == "log"
    # Day 1: cutoffs = 1st (block), 2nd (step-up), 3rd (queue) of day 0's finals.
    out = {}
    for k in range(1, 5):
        e = {"ip": ip(k), "user": "u", "status": "FAILED", "asn": k}
        tr.observe(e, DAY + k)
        out[k] = tr.assess(e, DAY + k, dets[:k])["tier"]
    assert out == {1: "log", 2: "queue", 3: "step_up", 4: "block"}
    # Sticky: a later alert cannot lower the tier.
    e = {"ip": ip(4), "user": "u", "status": "FAILED", "asn": 4}
    assert tr.assess(e, DAY + 50, [BF])["tier"] == "block"
    # Fewer incidents than the rate: everyone qualifies the next day.
    tr2 = tracker("T1", {"block": 0, "step_up": 0, "queue": 10})
    tr2.observe({"ip": "9.9.9.9", "status": "FAILED"}, 5)
    tr2.assess({"ip": "9.9.9.9"}, 5, [BF])
    tr2.observe({"ip": "8.8.8.8", "status": "FAILED"}, DAY + 5)
    assert tr2.assess({"ip": "8.8.8.8"}, DAY + 5, [OFF])["tier"] == "queue"


def test_admission_is_capped_per_day_first_come():
    """Amendment 7: at most k incidents enter a tier per day, in arrival
    order; an incident in a higher tier takes no lower slot; a queue
    incident can still move up; slots are not returned; caps reset daily."""
    tr = tracker("T1", {"block": 0, "step_up": 1, "queue": 2})
    ev = lambda ip: {"ip": ip, "user": "u", "status": "FAILED", "asn": 1}   # noqa: E731
    for k in range(5):                      # day 0: five 1-detector incidents
        tr.observe(ev(f"10.0.0.{k}"), 10 + k)
        tr.assess(ev(f"10.0.0.{k}"), 10 + k, [BF])
    # Day 1: every incident reaches both cutoffs (1 detector).
    tiers = []
    for k in range(5):
        tr.observe(ev(f"10.1.0.{k}"), DAY + k)
        tiers.append(tr.assess(ev(f"10.1.0.{k}"), DAY + k, [BF])["tier"])
    # First to step-up (slot 1/1); the next two to the queue (2/2); the rest stay at log.
    assert tiers == ["step_up", "queue", "queue", "log", "log"]
    assert tr.admitted == {"block": 0, "step_up": 1, "queue": 2}
    # Re-alerting does not re-admit or take a slot.
    assert tr.assess(ev("10.1.0.3"), DAY + 9, [BF])["tier"] == "log"
    # Queue -> step-up when a step-up slot is free (fresh tracker, step-up cap 2).
    tr2 = tracker("T1", {"block": 0, "step_up": 2, "queue": 5})
    for k in range(3):
        tr2.observe(ev(f"10.0.0.{k}"), 10 + k)
        tr2.assess(ev(f"10.0.0.{k}"), 10 + k, [BF, CS][:k % 2 + 1])
    # Day-0 finals (T1): (2, 1.0), (1, 1.0), (1, 0.0): step-up cutoff (1, 1.0), queue all.
    tr2.observe(ev("1.1.1.1"), DAY + 1)
    assert tr2.assess(ev("1.1.1.1"), DAY + 1, [BF])["tier"] == "step_up"
    tr2.observe(ev("1.1.1.2"), DAY + 2)
    assert tr2.assess(ev("1.1.1.2"), DAY + 2, [BF])["tier"] == "step_up"
    tr2.observe(ev("1.1.1.3"), DAY + 3)
    assert tr2.assess(ev("1.1.1.3"), DAY + 3, [BF])["tier"] == "queue"
    assert tr2.admitted["step_up"] == 2 and tr2.admitted["queue"] == 1
    # Next day the caps reset.
    tr2.observe(ev("1.1.1.9"), 2 * DAY + 1)
    tr2.assess(ev("1.1.1.9"), 2 * DAY + 1, [BF, CS])
    assert tr2.admitted == {"block": 0, "step_up": 1, "queue": 0}


def test_queue_incident_moves_up_when_a_step_up_slot_opens_later():
    tr = tracker("T1", {"block": 0, "step_up": 1, "queue": 3})
    ev = lambda ip: {"ip": ip, "user": "u", "status": "FAILED", "asn": 1}   # noqa: E731
    # Day 0: finals 2 detectors and 1 detector, 1 detector.
    for k, dets in enumerate([[BF, CS], [BF], [BF]]):
        tr.observe(ev(f"10.0.0.{k}"), 10 + k)
        tr.assess(ev(f"10.0.0.{k}"), 10 + k, dets)
    # Day 1: step-up cutoff = 2 detectors, queue cutoff = 1 detector.
    tr.observe(ev("2.2.2.2"), DAY + 1)
    assert tr.assess(ev("2.2.2.2"), DAY + 1, [BF])["tier"] == "queue"
    out = tr.assess(ev("2.2.2.2"), DAY + 2, [CS])          # now 2 detectors
    assert (out["tier"], out["previous_tier"]) == ("step_up", "queue")
    assert tr.admitted == {"block": 0, "step_up": 1, "queue": 1}   # the queue slot stays used


def test_floor_keeps_incidents_without_a_surviving_detector_at_log():
    """Amendment 8: an incident is admitted only at an event where it carries
    an alert of a floor detector; below the floor it uses no slot."""
    tr = tracker("T1", {"block": 0, "step_up": 1, "queue": 5}, floor=(CS,))
    ev = lambda ip: {"ip": ip, "user": "u", "status": "FAILED", "asn": 1}   # noqa: E731
    tr.observe(ev("9.9.9.9"), 5)
    tr.assess(ev("9.9.9.9"), 5, [CS])            # day 0: one incident -> every one qualifies
    tr.observe(ev("1.1.1.1"), DAY + 1)
    a = tr.assess(ev("1.1.1.1"), DAY + 1, [OFF, BF])
    assert a["tier"] == "log" and tr.admitted == {"block": 0, "step_up": 0, "queue": 0}
    tr.observe(ev("2.2.2.2"), DAY + 2)
    assert tr.assess(ev("2.2.2.2"), DAY + 2, [CS])["tier"] == "step_up"
    # A below-floor incident enters once a floor detector alerts in it.
    out = tr.assess(ev("1.1.1.1"), DAY + 3, [CS])
    assert (out["tier"], out["previous_tier"]) == ("queue", "log")


def test_deployed_floor_is_the_phase3b_survivors():
    assert TR.IncidentTriage().floor != 0
    p = os.path.join(BACKEND, "results", "phase3b_confirm.json")
    if not os.path.exists(p):
        pytest.skip("Phase 3b results not present")
    conf = json.load(open(p))["detectors"]
    assert list(config.RESPONSE_FLOOR_DETECTORS) == [
        d for d in TR.RULE_DETECTORS if conf[d]["val_a_meets"] and conf[d]["val_b_holds"]]
    assert set(TR.RULE_DETECTORS) - set(config.RESPONSE_FLOOR_DETECTORS) == {
        BF, "Multiple IP Login", OFF}


def test_asn_reputation_matches_features_v4():
    from ml import features_v4 as F
    rng = np.random.default_rng(3)
    fx, rep = F.FeatureExtractorV4(), TR.AsnReputation()
    col = F.FEATURE_NAMES.index("d_asn_fail_ratio")
    for i in range(500):
        e = {"timestamp": (T + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
             "user": "u", "ip": "1.1.1.1", "asn": int(rng.integers(4)),
             "status": "FAILED" if rng.random() < 0.3 else "SUCCESS"}
        assert rep.observe(e) == fx.update_and_extract(e)[col]


# ── Response tiers in the agents ─────────────────────────────────────────────

def _monitor(v3, rates, mail=None):
    from agents.monitoring_agent import MonitoringAgent
    v3.setattr(config, "TRIAGE_SCORE", "T0")
    v3.setattr(config, "RESPONSE_TIER_RATES", rates)
    store = Store()
    mon = MonitoringAgent(alert_manager=store, responder=ResponseAgent(email_alerter=mail or Mail()))
    return mon, store


def test_step_up_is_recorded_and_exposed_but_not_enforced(v3):
    mon, store = _monitor(v3, {"block": 0, "step_up": 1, "queue": 0})
    for i in range(5):
        mon._process_event(ev(T - timedelta(days=1) + timedelta(seconds=i), "amy", "6.6.6.9", "FAILED"))
    for i in range(5):
        mon._process_event(ev(T + timedelta(seconds=i), "zoe", "6.6.6.1", "FAILED"))
    a = [x for x in store.saved if x["ip"] == "6.6.6.1"][-1]
    assert a["response"]["tier"] == "step_up" and a["response"]["step_up"]
    assert not a["response"]["simulated_block"] and a["severity"] == "HIGH"
    mon._process_event(ev(T + timedelta(seconds=60), "zoe", "6.6.6.1", "SUCCESS"))
    assert mon.challenged_source_events == 1 and mon.blocked_source_events == 0
    assert not mon.responder.is_blocked("6.6.6.1", (T + timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S"))


def test_queue_and_log_tiers_send_no_email(v3):
    mail = Mail()
    mon, store = _monitor(v3, {"block": 0, "step_up": 0, "queue": 1}, mail)
    for d in (1, 0):
        for i in range(5):
            mon._process_event(ev(T - timedelta(days=d) + timedelta(seconds=i), "zoe", f"6.6.6.{d}", "FAILED"))
    tiers = {a["response"]["tier"] for a in store.saved}
    assert tiers == {"log", "queue"}
    assert mail.incidents == [] and mail.digests == []
    assert {a["severity"] for a in store.saved if a["response"]["tier"] == "queue"} == {"MEDIUM"}
    assert {a["response"]["email"] for a in store.saved} == {"not_required"}


def test_one_email_per_incident(v3):
    v3.setattr(config, "TRIAGE_SCORE", "T0")
    v3.setattr(config, "RESPONSE_TIER_RATES", {"block": 1, "step_up": 0, "queue": 0})
    mail = Mail()
    r = ResponseAgent(email_alerter=mail)
    stamp = lambda s: (T + timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S")   # noqa: E731
    e0 = {"timestamp": stamp(-DAY), "ip": "6.6.6.9", "user": "a", "status": "FAILED"}
    r.observe(e0)
    r.assess(e0, [{"type": BF}])
    outs = []
    for k in range(3):
        e = {"timestamp": stamp(60 * k), "ip": "6.6.6.1", "user": "a", "status": "FAILED"}
        r.observe(e)
        outs.append(r.assess(e, [{"type": BF}, {"type": OFF}]))
    assert [o["tier"] for o in outs] == ["block"] * 3
    assert [o["email"] for o in outs] == ["sent", "not_required", "not_required"]
    assert mail.incidents == [f"6.6.6.1|{outs[0]['day']}"]


def test_email_cooldown_per_ip():
    mail = Mail()
    n = TR.IncidentNotifier(mail, max_per_hour=20, cooldown=3600, tiers=("block", "step_up"))
    assert n.notify(inc("1.1.1.1", "block"), 0) == "sent"
    assert n.notify(inc("1.1.1.1", "block"), 3599) == "cooldown"
    assert n.notify(inc("2.2.2.2", "step_up"), 3599) == "sent"
    assert n.notify(inc("1.1.1.1", "block"), 3600) == "sent"
    assert len(mail.incidents) == 3


def test_email_rate_limit_and_digest_content():
    mail = Mail()
    n = TR.IncidentNotifier(mail, max_per_hour=3, cooldown=0, tiers=("block", "step_up"))
    out = [n.notify(inc(f"1.1.1.{k}", "step_up"), 7200 + k) for k in range(5)]
    assert out == ["sent"] * 3 + ["digest"] * 2
    assert mail.digests == []                          # the hour has not closed
    assert n.notify(inc("2.2.2.2", "block"), 7200 + 3600) == "sent"   # next hour: new budget
    assert mail.digests == [(2, ["1.1.1.3|1", "1.1.1.4|1"])]
    html = __import__("utils.email_alerter", fromlist=["EmailAlerter"]).EmailAlerter.digest_html(
        2, [dict(inc("<b>", "block"), detectors=["<script>"])])
    assert "<script>" not in html and "&lt;script&gt;" in html and "1 incident(s)" in html


def test_wants_only_the_first_entry_into_an_email_tier():
    n = TR.IncidentNotifier(Mail(), tiers=("block", "step_up"))
    assert n.wants(inc("1", "step_up", "queue")) and n.wants(inc("1", "block", "log"))
    assert not n.wants(inc("1", "block", "step_up")) and not n.wants(inc("1", "queue"))
    assert not n.wants(inc("1", "log")) and not n.wants(None)


# ── Config: policy table and derived severities ──────────────────────────────

def test_severity_map_is_derived_from_the_tiers():
    assert config.V3_SEVERITY_MAP == {t: ("HIGH" if t in config.EMAIL_TIERS else
                                          "MEDIUM" if t == "queue" else "LOW") for t in TR.TIERS}
    table = config.public_config()["response"]["v3_policy"]["table"]
    assert [r["tier"] for r in table] == list(TR.TIERS)


def test_config_holds_the_val_a_choice_and_measured_tiers():
    sel_p = os.path.join(BACKEND, "results", "phase5b_selection.json")
    resp_p = os.path.join(BACKEND, "results", "phase5b_response.json")
    if not (os.path.exists(sel_p) and os.path.exists(resp_p)):
        pytest.skip("Phase 5b results not present")
    sel, resp = json.load(open(sel_p)), json.load(open(resp_p))
    p5 = os.path.join(BACKEND, "results", "phase5_selection.json")
    if os.path.exists(p5):
        assert config.TRIAGE_SCORE == json.load(open(p5))["chosen"] == sel["chosen"]
    t = sel["tiers"]
    assert config.RESPONSE_TIER_RATES == {"block": t["block_rate"], "step_up": t["step_up_rate"],
                                          "queue": t["queue_rate"]}
    floor_p = os.path.join(BACKEND, "results", "phase5c_floor.json")
    if os.path.exists(floor_p):     # amendment 8: the table shows the floored run
        fl = json.load(open(floor_p))
        assert fl["floor"] == list(config.RESPONSE_FLOOR_DETECTORS) and fl["rates"] == config.RESPONSE_TIER_RATES
        resp = {"tiers_per_half": {"val_a": fl["halves"]["val_a"]["with_floor"]["tiers"]}}
    for tier, r in resp["tiers_per_half"]["val_a"].items():
        c = config.RESPONSE_TIER_VAL_A[tier]
        assert c["incidents"] == r["incidents"]
        if r["incidents"]:
            assert (c["precision"], c["ci_low"], c["ci_high"]) == (r["precision"], r["ci_low"], r["ci_high"])


# ── SQLite alert store and the API ───────────────────────────────────────────

def _alert(k, tier="step_up", ip="1.2.3.4", ts="2020-04-01 10:00:00"):
    return {"alert_id": f"A{k}", "detected_at": ts, "ip": ip, "user": "u", "type": CS,
            "severity": config.V3_SEVERITY_MAP[tier],
            "incident": {"incident_id": f"{ip}|18353", "ip": ip, "tier": tier, "score": [0.27, 0.5],
                         "detectors": [CS], "alerts": k + 1, "email": "sent" if k == 0 else "not_required"},
            "response": {"tier": tier, "step_up": tier == "step_up", "simulated_block": tier == "block"}}


def test_sqlite_store_is_indexed_and_round_trips(tmp_path):
    from utils.alert_store_sqlite import SqliteAlertStore
    s = SqliteAlertStore(str(tmp_path / "alerts.db"))
    idx = {r[1] for r in s._con.execute("PRAGMA index_list('alerts')")}
    assert {"ix_alerts_ts", "ix_alerts_ip", "ix_alerts_incident", "ix_alerts_tier",
            "ix_alerts_tier_id"} <= idx
    s.save_alerts([_alert(0), _alert(1), _alert(2, tier="queue", ip="5.5.5.5")])
    assert s.count() == 3 and [a["alert_id"] for a in s.load_alerts()] == ["A0", "A1", "A2"]
    assert [a["alert_id"] for a in s.query(tier="step_up")] == ["A1", "A0"]
    assert [a["alert_id"] for a in s.query(ip="5.5.5.5")] == ["A2"]
    i = {d["incident_id"]: d for d in s.incidents()}["1.2.3.4|18353"]
    assert i["alerts"] == 2 and i["email"] == "sent" and i["tier"] == "step_up"
    assert s.update_explanation("A0", "text") and s.query(ip="1.2.3.4")[-1]["enriched"]
    assert s.mark_enrichment_failed("A1", "x", final_after=1) == 1
    assert s.enrichment_counts() == {"total": 3, "enriched": 1, "failed": 1}
    assert s.clear(backup=True) == 3 and s.count() == 0
    assert s.restore() == 3 and len(s.load_cached()) == 3


def test_tier_filter_uses_the_tier_id_index(tmp_path):
    from utils.alert_store_sqlite import SqliteAlertStore
    s = SqliteAlertStore(str(tmp_path / "alerts.db"))
    plan = " ".join(r[3] for r in s._con.execute(
        "EXPLAIN QUERY PLAN SELECT body FROM alerts WHERE tier = ? ORDER BY id DESC LIMIT ?",
        ("step_up", 500)))
    assert "ix_alerts_tier_id" in plan and "TEMP B-TREE" not in plan


def _saved(alert, stamp):
    return dict(alert, saved_at=stamp)


def test_retention_prunes_old_alerts_and_orphan_incidents(tmp_path):
    from datetime import datetime
    from utils.alert_store_sqlite import SqliteAlertStore
    path = str(tmp_path / "alerts.db")
    s = SqliteAlertStore(path, retention_days=30)
    now = datetime(2026, 10, 14, 12, 0, 0).timestamp()
    s.save_alerts([_saved(_alert(0), "2026-09-01 00:00:00"),                  # old
                   _saved(_alert(1, ip="5.5.5.5"), "2026-09-01 00:00:00"),    # old, own incident
                   _saved(_alert(2), "2026-10-13 00:00:00")])                 # recent
    assert len(s.incidents()) == 2
    assert s.prune(now=now) == (2, 1)
    assert [a["alert_id"] for a in s.load_alerts()] == ["A2"]
    assert [i["ip"] for i in s.incidents()] == ["1.2.3.4"]     # still has A2
    assert s.prune(now=now) == (0, 0)
    # 0 keeps everything.
    k = SqliteAlertStore(str(tmp_path / "keep.db"), retention_days=0)
    k.save_alerts([_saved(_alert(0), "2000-01-01 00:00:00")])
    assert k.prune(now=now) == (0, 0) and k.count() == 1


def test_retention_runs_on_open_and_at_most_daily(tmp_path, monkeypatch):
    from utils import alert_store_sqlite as M
    path = str(tmp_path / "alerts.db")
    M.SqliteAlertStore(path, retention_days=0).save_alerts([_saved(_alert(0), "2000-01-01 00:00:00")])
    monkeypatch.setattr(config, "ALERT_RETENTION_DAYS", 30)
    s = M.SqliteAlertStore(path)                   # default from config; prunes on open
    assert s.retention_days == 30 and s.count() == 0
    clock = [1000.0]
    monkeypatch.setattr(M.time, "monotonic", lambda: clock[0])
    s._last_prune = None
    s._maybe_prune()                              # at t=1000
    s.save_alerts([_saved(_alert(1), "2000-01-01 00:00:00")])   # same day: not pruned yet
    assert s.count() == 1
    clock[0] += 86400
    s.load_cached()                               # a day later: pruned
    assert s.count() == 0


def test_api_reads_the_v3_store(tmp_path, monkeypatch):
    import api
    from utils.alert_store_sqlite import SqliteAlertStore
    monkeypatch.setattr(config, "RULES_MODE", "v3")
    monkeypatch.setattr(api, "ALERTS_DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setattr(api, "_store", None)
    SqliteAlertStore(api.ALERTS_DB_PATH).save_alerts(
        [_alert(0), _alert(1), _alert(2, tier="block", ip="9.9.9.9")])
    c = api.app.test_client()
    assert [a["alert_id"] for a in c.get("/api/alerts").get_json()] == ["A0", "A1", "A2"]
    assert [a["alert_id"] for a in c.get("/api/alerts?tier=block").get_json()] == ["A2"]
    incs = c.get("/api/incidents?tier=step_up").get_json()
    assert [i["ip"] for i in incs] == ["1.2.3.4"]
    st = c.get("/api/stats").get_json()
    assert st["step_up_ips"] == ["1.2.3.4"] and st["blocked_ips"] == ["9.9.9.9"]
    assert st["total_alerts"] == 3 and st["email"]["sent"] == 1
    assert c.get("/api/status").get_json()["alert_count"] == 3
    assert sum(h["total"] for h in c.get("/api/timeline").get_json()) == 3
    cfg = c.get("/api/config").get_json()
    assert cfg["response"]["v3_policy"]["table"][1]["tier"] == "step_up"
    assert c.get("/api/enrichment-status").get_json()["total"] == 3


# ── Ingest schema (5.5) ──────────────────────────────────────────────────────

def test_normalize_event_keeps_the_v4_fields_and_validates_them():
    from utils.event_schema import normalize_event
    base = {"user": "u", "ip": "1.2.3.4", "status": "FAILED", "timestamp": "2020-04-01 10:00:00"}
    e, err = normalize_event(dict(base, asn="29695", region="Oslo", user_agent="UA", browser="B 1",
                                  os="O 2", device_type="mobile", country="NO", rtt=12.5, junk=1))
    assert err is None and e["asn"] == 29695 and e["rtt"] == 12.5 and "junk" not in e
    assert {e[k] for k in ("region", "user_agent", "browser", "os")} == {"Oslo", "UA", "B 1", "O 2"}
    e, err = normalize_event(dict(base, rtt=None, region=None))
    assert err is None and "rtt" not in e and "region" not in e
    for bad in ({"asn": -1}, {"asn": "AS1"}, {"asn": True}, {"rtt": -1}, {"rtt": "5"},
                {"user_agent": 5}, {"region": "x" * 200}):
        assert normalize_event(dict(base, **bad))[1] is not None, bad


PARQUET = os.path.join(BACKEND, "data", "rba_parquet", "month=2020-02", "part-0.parquet")


@pytest.mark.skipif(not os.path.exists(PARQUET), reason="RBA Parquet files missing")
def test_full_rba_rows_through_api_ingest_give_the_replay_features(tmp_path, monkeypatch):
    """A full RBA row posted to /api/ingest and read back by the live queue
    consumer produces the same features_v4 vector as the offline replay."""
    monkeypatch.setenv("PHASE3_LIMIT", "4000")
    from eval import phase3b, phase4
    from ml import features_v4 as F
    from utils.event_schema import normalize_event
    import api
    S = phase3b.stream()
    replay = list(phase4.events(S))
    monkeypatch.setenv("INGEST_TOKEN", "t")
    monkeypatch.setattr(api, "QUEUE_PATH", str(tmp_path / "q.jsonl"))
    c = api.app.test_client()
    for e in replay:
        r = c.post("/api/ingest", json=e, headers={"X-Ingest-Token": "t"})
        assert r.status_code == 200, r.get_json()
    live = [normalize_event(json.loads(line))[0] for line in open(tmp_path / "q.jsonl", encoding="utf-8")]
    assert len(live) == len(replay)
    fx_a, fx_b = F.FeatureExtractorV4(), F.FeatureExtractorV4()
    a = np.array([fx_a.update_and_extract(e) for e in replay])
    b = np.array([fx_b.update_and_extract(e) for e in live])
    assert np.array_equal(a, b)
    rep_a, rep_b = TR.AsnReputation(), TR.AsnReputation()
    assert [rep_a.observe(e) for e in replay] == [rep_b.observe(e) for e in live]


# ── main.py: model.pkl only in legacy ML mode (5.5) ──────────────────────────

def test_main_loads_model_pkl_only_in_legacy_ml_mode(monkeypatch):
    import main
    calls = []
    monkeypatch.setattr(main, "get_or_train_model", lambda base: calls.append(base) or "model")
    monkeypatch.setattr(config, "ML_MODE", "v4")
    assert main.load_ml(BACKEND) is None and calls == []
    monkeypatch.setattr(config, "ML_MODE", "legacy")
    assert main.load_ml(BACKEND) == "model" and calls == [BACKEND]


def test_v4_with_the_forest_retired_runs_no_ml_step(monkeypatch):
    from agents.detection_agent import DetectionAgent
    monkeypatch.setattr(config, "RULES_MODE", "v3")
    monkeypatch.setattr(config, "ML_MODE", "v4")
    monkeypatch.setattr(config, "ML_V4_IFOREST", "retired")
    assert DetectionAgent().anomaly_detector is None
    assert "ML Anomaly Detected" not in config.active_detectors()
