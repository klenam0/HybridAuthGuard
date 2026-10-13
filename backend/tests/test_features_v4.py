# backend/tests/test_features_v4.py
"""
Phase 4 causal features (ml/features_v4.py) and the v4 ML step
(ml/model_v4.py): causality, sliding-window expiry at the 1 h and 24 h
boundaries, placeholder handling, the first event of a user, the fast
Isolation Forest scorer, and live/offline equivalence on the first 300,000
development rows (skipped when the RBA Parquet files are missing).

Run from backend/:  python -m pytest tests/test_features_v4.py -v
"""

import os
import sys
from datetime import datetime, timedelta

import numpy as np
import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from ml import features_v4 as F  # noqa: E402
from ml.model_v4 import FastIForest, V4Scorer  # noqa: E402

PLACEHOLDER = "-4324475583306591935"
T0 = datetime(2020, 2, 3, 10, 0, 0)
col = F.FEATURE_NAMES.index


def ev(sec, user="u1", ip="1.2.3.4", status="FAILED", **kw):
    e = {"timestamp": (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S"),
         "user": user, "ip": ip, "status": status, "country": "NO", "region": "Oslo",
         "asn": 29695, "device_type": "mobile", "user_agent": "UA/1",
         "browser": "Chrome Mobile 81.0.4044", "os": "Android 4.1", "rtt": None}
    e.update(kw)
    return e


def run(events):
    fx = F.FeatureExtractorV4()
    X = np.array([fx.update_and_extract(e) for e in events])
    return X, fx


def synthetic(n=400, seed=0):
    rng = np.random.default_rng(seed)
    t = np.cumsum(rng.integers(0, 900, n))
    users = [PLACEHOLDER, "u1", "u2", "u3", "u4", "u5"]
    out = []
    for i in range(n):
        out.append(ev(int(t[i]), user=users[rng.integers(len(users))],
                      ip=f"10.0.{rng.integers(3)}.{rng.integers(4)}",
                      status="SUCCESS" if rng.random() < 0.4 else "FAILED",
                      country=["NO", "US", "SE"][rng.integers(3)], asn=int(rng.integers(3)),
                      user_agent=f"UA/{rng.integers(4)}", rtt=float(rng.integers(1, 900))
                      if rng.random() < 0.1 else None))
    return out


def test_vector_shape_and_groups():
    X, _ = run([ev(0)])
    assert X.shape == (1, F.N_FEATURES) == (1, 32)
    assert sum(len(v) for v in F.FEATURE_GROUPS.values()) == F.N_FEATURES
    assert F.columns("D") == [col(f) for f in F.FEATURE_GROUPS["D"]]


def test_causality_later_events_do_not_change_earlier_vectors():
    evs = synthetic()
    k = 200
    X_prefix, fx_p = run(evs[:k])
    X_full, _ = run(evs)
    rng = np.random.default_rng(1)
    later = [evs[k + j] for j in rng.permutation(len(evs) - k)]
    X_perm, _ = run(evs[:k] + later)
    X_more, _ = run(evs[:k] + later + evs[k:])
    for other in (X_full, X_perm, X_more):
        assert np.array_equal(X_prefix, other[:k])
    # Freeman risk too
    fr = []
    fx = F.FeatureExtractorV4()
    for e in evs:
        fx.update_and_extract(e)
        fr.append(fx.last_freeman)
    fx2 = F.FeatureExtractorV4()
    for j, e in enumerate(evs[:k]):
        fx2.update_and_extract(e)
        assert fx2.last_freeman == fr[j]


def test_ip_windows_expire_at_1h_and_24h():
    for gap, f1, f24 in ((3600, 1, 1), (3601, 0, 1), (86400, 0, 1), (86401, 0, 0)):
        X, _ = run([ev(0, user="a"), ev(gap, user="b", status="SUCCESS")])
        assert X[1, col("b_ip_fail_1h")] == f1, gap
        assert X[1, col("b_ip_fail_24h")] == f24, gap
        assert X[1, col("b_ip_accounts_24h")] == f24, gap
        assert X[1, col("b_ip_fail_ratio_24h")] == (1.0 if f24 else 0.0), gap


def test_account_windows_expire_at_1h_and_24h():
    for gap, f1, f24 in ((3600, 1, 1), (3601, 0, 1), (86400, 0, 1), (86401, 0, 0)):
        X, _ = run([ev(0, user="a", ip="9.9.9.9", country="US"),
                    ev(gap, user="a", ip="8.8.8.8", status="SUCCESS")])
        assert X[1, col("c_acct_fail_1h")] == f1, gap
        assert X[1, col("c_acct_fail_24h")] == f24, gap
        assert X[1, col("c_acct_ips_24h")] == f24, gap
        assert X[1, col("c_acct_countries_24h")] == f24, gap


def test_current_event_is_not_counted():
    X, _ = run([ev(0)])
    for f in ("b_ip_fail_1h", "b_ip_fail_24h", "b_ip_accounts_24h", "c_acct_fail_1h",
              "c_acct_ips_24h", "d_ip_log_count", "d_asn_log_count"):
        assert X[0, col(f)] == 0, f


def test_placeholder_is_neutral_per_account_and_counted_per_ip():
    X, _ = run([ev(0, user=PLACEHOLDER), ev(10, user=PLACEHOLDER), ev(20, user="real")])
    for i in (0, 1):
        assert X[i, col("c_is_unknown_account")] == 1
        assert all(X[i, col(f)] == 0 for f in F.FEATURE_GROUPS["C"][:4])
    assert X[1, col("b_ip_placeholder_24h")] == 1
    assert X[2, col("b_ip_placeholder_24h")] == 2
    assert X[2, col("b_ip_accounts_24h")] == 0          # the placeholder is not an account
    assert X[2, col("c_is_unknown_account")] == 0
    assert X[2, col("b_ip_fail_24h")] == 2              # but its failures are failures


def test_first_event_of_a_user():
    X, fx = run([ev(0, user="a"), ev(60, user="a"), ev(120, user="a", ip="5.6.7.8")])
    assert X[0, col("a_first_event")] == 1
    assert all(X[0, col(f)] == 1 for f in F.FEATURE_GROUPS["A"][1:10])
    assert X[0, col("a_log_prior_events")] == 0
    assert X[0, col("a_log_secs_since_last")] == -1
    assert X[0, col("a_hour_deviation")] == 0
    assert X[1, col("a_first_event")] == 0 and X[1, col("a_new_ip")] == 0
    assert X[1, col("a_log_prior_events")] == np.log1p(1)
    assert X[1, col("a_log_secs_since_last")] == np.log1p(60)
    assert X[2, col("a_new_ip")] == 1 and X[2, col("a_new_prefix")] == 1
    assert X[2, col("a_new_asn")] == 0
    assert fx.users["a"].n == 3


def test_freeman_prior_for_users_without_history_and_risk_for_new_values():
    fx = F.FeatureExtractorV4()
    for i in range(20):
        fx.update_and_extract(ev(i, user=f"bg{i}", ip=f"7.7.{i}.1", country="US", user_agent="UA/x"))
    fx.update_and_extract(ev(100, user="new"))
    assert fx.last_freeman == (0.0,) * len(F.FREEMAN_BETAS)
    for i in range(5):
        fx.update_and_extract(ev(200 + i, user="habit"))
    fx.update_and_extract(ev(300, user="habit"))
    same = fx.last_freeman
    fx.update_and_extract(ev(400, user="habit", ip="7.7.3.1", country="US", asn=1, user_agent="UA/x"))
    moved = fx.last_freeman
    assert all(m > s for m, s in zip(moved, same))


def test_fast_iforest_is_bit_identical_to_sklearn():
    from sklearn.ensemble import IsolationForest
    rng = np.random.default_rng(0)
    X = rng.normal(size=(3000, 6))
    X[:, 2] = rng.integers(0, 3, len(X))
    for ne, ms in ((50, 64), (20, 1024)):
        m = IsolationForest(n_estimators=ne, max_samples=ms, random_state=42).fit(X[:2000])
        ref = -m.decision_function(X)
        fast = FastIForest(m)
        assert np.array_equal(ref, [fast.score(x) for x in X])


def _bundle(alerting, threshold=0.5):
    return {"name": "new_ip", "kind": "new_ip", "feature_names": F.FEATURE_NAMES,
            "threshold": threshold, "alerting": alerting, "columns": []}


def test_v4_fallback_scores_but_never_alerts():
    sc = V4Scorer(_bundle(alerting=False))
    r = sc.score_event(ev(0))
    assert r["score"] == 1.0 and r["is_anomaly"] is False
    sc = V4Scorer(_bundle(alerting=True))
    assert sc.score_event(ev(0))["is_anomaly"] is True
    assert sc.score_event(ev(1))["is_anomaly"] is False      # known IP now


def test_v4_requires_v3_rules(monkeypatch):
    from agents.detection_agent import DetectionAgent
    monkeypatch.setattr(config, "ML_MODE", "v4")
    with pytest.raises(ValueError):
        DetectionAgent(mode="legacy")
    agent = DetectionAgent(mode="v3", anomaly_detector=V4Scorer(_bundle(alerting=True)))
    alerts = agent.analyze_all(ev(0, status="SUCCESS"))
    assert [a["type"] for a in alerts] == ["ML Anomaly Detected"]


PARQUET = os.path.join(BACKEND, "data", "rba_parquet", "month=2020-02", "part-0.parquet")


@pytest.mark.skipif(not os.path.exists(PARQUET), reason="RBA Parquet files missing")
def test_live_and_offline_vectors_are_bit_identical_on_300k_rows(monkeypatch):
    """The offline extraction (eval.phase4.events + the extractor) and the
    real v3 DetectionAgent in ML_MODE v4 produce the same vectors."""
    monkeypatch.setenv("PHASE3_LIMIT", "300000")
    from agents.detection_agent import DetectionAgent
    from eval import phase3b, phase4
    S = phase3b.stream()
    assert S.n == 300_000
    fx = F.FeatureExtractorV4()
    offline = np.array([fx.update_and_extract(e) for e in phase4.events(S)])
    monkeypatch.setattr(config, "RULES_MODE", "v3")
    monkeypatch.setattr(config, "ML_MODE", "v4")
    scorer = V4Scorer(_bundle(alerting=False))
    agent = DetectionAgent(anomaly_detector=scorer)
    live = np.empty_like(offline)
    for i, e in enumerate(phase4.events(S, with_id=True)):
        agent.analyze(e)
        live[i] = scorer.last_vector
    assert np.array_equal(offline, live)
