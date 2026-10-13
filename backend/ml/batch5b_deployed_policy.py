# backend/ml/batch5b_deployed_policy.py
"""
Batch 5b: the blocking cost under the policy the code actually deploys.

Why this exists
  Batch 5 counted a "block" whenever DetectionAgent stops alerting on an
  address (rule_blocked_ips / ml_blocked_ips). The live system differs in two
  ways that the paper must reflect:
    1. AnomalyDetector.score_event() flags an event only if predict() == -1
       AND decision_function < -0.02 (confidence Medium or High). Batch 5 used
       predict() == -1 alone (decision_function < 0).
    2. ResponseAgent blocks an address (simulated) only for HIGH-severity
       alerts: Brute Force Attack, Slow Brute Force, Credential Stuffing,
       Multiple IP Login, and ML Anomaly Detected with decision_function
       < -0.10 (High confidence). MEDIUM alerts (Suspicious Login Time, ML at
       Medium confidence) only notify an administrator.

What it reports, for both ML thresholds (evaluated: score < 0; deployed:
score < -0.02), over 10 seeds
  - hybrid campaign coverage, benign IPs flagged, event recall and FPR;
  - cost of DETECTOR-LEVEL suppression (what Batch 5 measured);
  - cost of RESPONSE-LEVEL blocks (HIGH alerts only), i.e. what an enforced
    version of the shipped response policy would do;
  - alert counts by type and severity.
Block duration is not specified in the code ("temporarily"), so response
blocks are treated as lasting to the end of the test stream: an upper bound.

Check: the "evaluated" threshold, suppression cost, seed 42 must reproduce
Batch 5 (10,071 benign users affected; campaign recall 0.5998).

HOW TO RUN (from backend/; needs batch5_hybrid_ci_and_blocking.py in ml/
and the Batch 4 cache)
    python ml/batch5b_deployed_policy.py
About 10-15 minutes. Writes backend/data/batch5b_results.json and
backend/data/batch5b_summary.txt.
"""

import json
import os
import sys
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from batch5_hybrid_ci_and_blocking import (Stream, arm_metrics, blocking_harm,  # noqa: E402
                                           fit_if, load_pools)
from train_from_dataset_v2 import RESULTS_DIR, SEED_BASE, user_disjoint_split  # noqa: E402
from train_from_dataset_v3 import fit_frequency_maps, extract_features_freq  # noqa: E402
from evaluate_hybrid_and_baselines import DEFAULT_THRESHOLD  # noqa: E402
from evaluate_hybrid_batch37 import ReplayDetectorV4  # noqa: E402

HIGH_RULES = {"Brute Force Attack", "Slow Brute Force", "Credential Stuffing", "Multiple IP Login"}
ML_HIGH_CUTOFF = -0.10          # anomaly_model.py: High confidence
THRESHOLDS = {"evaluated_score_lt_0": 0.0, "deployed_score_lt_-0.02": -0.02}


def replay_typed(stream, ml_flag, ml_high):
    det = ReplayDetectorV4(threshold=DEFAULT_THRESHOLD, use_ml=True,
                           ml_cooldown_seconds=0, internal_ip_guard=False)
    n = len(stream.events)
    flagged = np.zeros(n, bool)
    types, sev = [None] * n, [None] * n
    suppress_idx, suppress_by, enforced_idx = {}, {}, {}
    for i, e in enumerate(stream.events):
        ip = e["ip"]
        r = det.analyze_event(e, bool(ml_flag[i]))
        if r:
            flagged[i] = True
            types[i] = r
            s = "HIGH" if (r in HIGH_RULES or (r == "ML Anomaly Detected" and ml_high[i])) else "MEDIUM"
            sev[i] = s
            if s == "HIGH" and ip not in enforced_idx:
                enforced_idx[ip] = i
        if ip not in suppress_idx:
            if ip in det.rule_blocked_ips:
                suppress_idx[ip], suppress_by[ip] = i, "rule"
            elif ip in det.ml_blocked_ips:
                suppress_idx[ip], suppress_by[ip] = i, "ml"
    return {"flagged": flagged, "types": types, "sev": sev,
            "suppression": {"block_idx": suppress_idx, "block_by": suppress_by},
            "enforced": {"block_idx": enforced_idx,
                         "block_by": {ip: "response_high" for ip in enforced_idx}}}


def alert_breakdown(stream, rep):
    rows = Counter()
    for t, s, a in zip(rep["types"], rep["sev"], stream.true):
        if t:
            rows[(t, s, "attack" if a else "benign")] += 1
    out = {}
    for (t, s, lab), c in sorted(rows.items()):
        out.setdefault(f"{t} | {s}", {"attack": 0, "benign": 0})[lab] = c
    return out


def main():
    start = datetime.now()
    seeds = [SEED_BASE + i for i in range(10)]
    normal_df, attack_df = load_pools()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips, known_countries = fit_frequency_maps(train_df)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(extract_features_freq(train_df, freq_maps, known_ips, known_countries))
    test = Stream(test_df, freq_maps, known_ips, known_countries)
    X_test_s = scaler.transform(test.X)

    per_seed = []
    for seed in seeds:
        t0 = datetime.now()
        iso, thr = fit_if(X_train_s, seed)
        decision = iso.score_samples(X_test_s) - thr      # = decision_function
        high = decision < ML_HIGH_CUTOFF
        row = {"seed": seed}
        for name, cut in THRESHOLDS.items():
            ml = decision < cut
            rep = replay_typed(test, ml, high)
            row[name] = {
                "ml_only": arm_metrics(test, ml),
                "hybrid": arm_metrics(test, rep["flagged"]),
                "detector_suppression_cost": blocking_harm(test, rep["suppression"]),
                "response_block_cost": blocking_harm(test, rep["enforced"]),
                "ml_alerts_high_share": round(float(high[ml].mean()), 4) if ml.any() else 0.0,
            }
            if seed == SEED_BASE:
                row[name]["alert_breakdown"] = alert_breakdown(test, rep)
        per_seed.append(row)
        d = row["deployed_score_lt_-0.02"]
        print(f"   seed {seed}: deployed hybrid campaign {d['hybrid']['campaign_recall']:.4f}, "
              f"users affected by response blocks {d['response_block_cost']['share_benign_users_affected']:.4f} "
              f"({(datetime.now() - t0).seconds}s)")

    def stat(f):
        v = np.array([f(r) for r in per_seed], float)
        return {"mean": round(float(v.mean()), 4), "min": round(float(v.min()), 4), "max": round(float(v.max()), 4)}

    summary = {}
    for name in THRESHOLDS:
        g = lambda r, k1, k2, n=name: r[n][k1][k2]
        summary[name] = {
            "ml_only_campaign_recall": stat(lambda r: g(r, "ml_only", "campaign_recall")),
            "ml_only_fpr": stat(lambda r: g(r, "ml_only", "fpr")),
            "ml_only_recall": stat(lambda r: g(r, "ml_only", "recall")),
            "hybrid_campaign_recall": stat(lambda r: g(r, "hybrid", "campaign_recall")),
            "hybrid_benign_ips_flagged": stat(lambda r: g(r, "hybrid", "benign_ips_flagged")),
            "hybrid_recall": stat(lambda r: g(r, "hybrid", "recall")),
            "hybrid_fpr": stat(lambda r: g(r, "hybrid", "fpr")),
            "suppression_users_affected_share": stat(lambda r: g(r, "detector_suppression_cost", "share_benign_users_affected")),
            "suppression_benign_ips_blocked": stat(lambda r: g(r, "detector_suppression_cost", "benign_ips_blocked")),
            "response_users_affected_share": stat(lambda r: g(r, "response_block_cost", "share_benign_users_affected")),
            "response_benign_ips_blocked": stat(lambda r: g(r, "response_block_cost", "benign_ips_blocked")),
            "response_attack_ips_blocked": stat(lambda r: g(r, "response_block_cost", "attack_ips_blocked")),
            "response_benign_successful_logins_after_block": stat(lambda r: g(r, "response_block_cost", "benign_successful_logins_after_block")),
            "ml_alerts_high_share": stat(lambda r: r[name]["ml_alerts_high_share"]),
        }
    s42 = per_seed[0]["evaluated_score_lt_0"]
    check = {"users_affected": s42["detector_suppression_cost"]["benign_users_affected_any"],
             "campaign_recall": s42["hybrid"]["campaign_recall"]}
    check["match_batch5"] = check["users_affected"] == 10071 and abs(check["campaign_recall"] - 0.5998) < 1e-4
    results = {"per_seed": per_seed, "summary": summary, "batch5_reproduction_seed42": check,
               "elapsed_minutes": round((datetime.now() - start).total_seconds() / 60, 1)}

    os.makedirs(RESULTS_DIR, exist_ok=True)
    jpath = os.path.join(RESULTS_DIR, "batch5b_results.json")
    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    L = [f"Batch 5b summary, {results['elapsed_minutes']} min",
         f"Batch 5 reproduction (evaluated threshold, seed 42): {'MATCH' if check['match_batch5'] else 'DIFFERENT ' + str(check)}",
         "", "10-seed means (min-max). Users affected = share of 46,279 legitimate users; IPs blocked out of 42,162 benign."]
    for name, s in summary.items():
        f = lambda d: f"{d['mean']:.4f} ({d['min']:.4f}-{d['max']:.4f})"
        L += ["", f"[{name}]",
              f"   IF-only campaign recall {f(s['ml_only_campaign_recall'])}, event recall {f(s['ml_only_recall'])}, FPR {f(s['ml_only_fpr'])}",
              f"   hybrid campaign recall {f(s['hybrid_campaign_recall'])}, benign IPs flagged {s['hybrid_benign_ips_flagged']['mean']:.0f}, "
              f"event recall {f(s['hybrid_recall'])}, FPR {f(s['hybrid_fpr'])}",
              f"   share of ML alerts at HIGH severity: {f(s['ml_alerts_high_share'])}",
              f"   detector suppression: users affected {f(s['suppression_users_affected_share'])}, "
              f"benign IPs {s['suppression_benign_ips_blocked']['mean']:.0f}",
              f"   response blocks (HIGH only): users affected {f(s['response_users_affected_share'])}, "
              f"benign IPs {s['response_benign_ips_blocked']['mean']:.0f}, attack IPs {s['response_attack_ips_blocked']['mean']:.0f}, "
              f"benign successful logins after block {s['response_benign_successful_logins_after_block']['mean']:.0f}"]
    L += ["", "Alert breakdown, deployed threshold, seed 42 (type | severity: attack / benign alerts):"]
    for k, v in per_seed[0]["deployed_score_lt_-0.02"]["alert_breakdown"].items():
        L.append(f"   {k:<40} {v['attack']:>7} / {v['benign']:<7}")
    text = "\n".join(L)
    spath = os.path.join(RESULTS_DIR, "batch5b_summary.txt")
    with open(spath, "w") as f:
        f.write(text)
    print("\n" + text + f"\n\nSaved -> {jpath}\nSaved -> {spath}")


if __name__ == "__main__":
    main()
