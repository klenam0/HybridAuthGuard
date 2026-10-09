# backend/ml/evaluate_hybrid_batch38.py
"""
Batch 3.8 - one focused test following directly from Batch 3.7's finding.

Batch 3.7 found that every one of the 457 attacking IPs ML-only catches
but hybrid misses has a private-range address (192.168.x, 10.0.x,
172.16.x), the exact ranges hybrid's internal_ip_guard skips scoring for.
That guard was built for the live system's actual office network, where
those prefixes mean "trusted." In the RBA dataset, they may not mean
anything of the kind. This script re-runs the settled hybrid configuration
(contamination=0.4, cooldown=0, ML state fixed) with that guard switched
off, and compares campaign recall, event recall, and false-positive rate
against Batch 3.7's guard-on result, to see whether removing an assumption
built for a different context recovers those 457 campaigns.

Nothing here is new machinery: run_hybrid() already accepted an
internal_ip_guard parameter in Batch 3.7 for exactly this test. This
script reuses the same fitted model, same vectorized ML scores, same
test set, so it is a same-run, directly comparable rerun, not a fresh
evaluation with its own drift.

HOW TO RUN
==========
Save in backend/ml/, alongside evaluate_hybrid_batch37.py (this script
imports from it). From backend/:

    python ml/evaluate_hybrid_batch38.py

Should take well under a minute, same as Batch 3.7's main comparison,
since no retraining happens, only two replay passes over the test set.
Writes backend/results/batch3_8_results.json.
"""

import os
import sys
import json
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import stream_dataset, user_disjoint_split, RESULTS_DIR, SEED_BASE
from train_from_dataset_v3 import fit_frequency_maps
from evaluate_hybrid_and_baselines import extract_matrix, SETTLED_CONTAMINATION
from evaluate_hybrid_batch37 import (
    sort_stream_df, events_from_sorted_df, features_presorted,
    run_hybrid, summarize,
)

if __name__ == "__main__":
    print("\nStarting Batch 3.8: internal-IP guard on vs. off...\n")
    started = datetime.now()

    normal_df, attack_df = stream_dataset()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    X_train = extract_matrix(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    iso = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                          random_state=SEED_BASE, n_jobs=-1, max_samples=100000,
                          max_features=1.0)
    iso.fit(X_train_scaled)
    train_scores = iso.score_samples(X_train_scaled)

    test_sorted = sort_stream_df(test_df)
    test_events, test_true = events_from_sorted_df(test_sorted)
    X_test_scaled = scaler.transform(
        features_presorted(test_sorted, freq_maps, known_ips_set, known_countries_set))
    test_scores = iso.score_samples(X_test_scaled)

    threshold = np.percentile(train_scores, 100.0 * SETTLED_CONTAMINATION)
    ml_flags = test_scores < threshold

    print("--- Guard ON (Batch 3.7's setting, private-range IPs excluded from ML) ---")
    flagged_on, _ = run_hybrid(test_events, ml_flags, cooldown=0, internal_ip_guard=True)
    guard_on = summarize(test_events, flagged_on, test_true)
    print(f"   event-recall={guard_on['recall']:.4f}  campaign-recall={guard_on['campaign_level_recall']:.4f}  "
          f"F1={guard_on['f1']:.4f}  FPR={guard_on['fpr']:.4f}  IPs caught={guard_on['campaign_ips_caught']}")

    print("\n--- Guard OFF (every IP scored, regardless of address range) ---")
    flagged_off, _ = run_hybrid(test_events, ml_flags, cooldown=0, internal_ip_guard=False)
    guard_off = summarize(test_events, flagged_off, test_true)
    print(f"   event-recall={guard_off['recall']:.4f}  campaign-recall={guard_off['campaign_level_recall']:.4f}  "
          f"F1={guard_off['f1']:.4f}  FPR={guard_off['fpr']:.4f}  IPs caught={guard_off['campaign_ips_caught']}")

    ip_gain = guard_off["campaign_ips_caught"] - guard_on["campaign_ips_caught"]
    print(f"\nCampaigns recovered by removing the guard: {ip_gain}")
    print(f"FPR change: {guard_on['fpr']:.4f} -> {guard_off['fpr']:.4f} "
          f"({'+' if guard_off['fpr'] >= guard_on['fpr'] else ''}{(guard_off['fpr']-guard_on['fpr'])*100:.2f} points)")

    results = {"guard_on": guard_on, "guard_off": guard_off, "campaigns_recovered": ip_gain}
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_8_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    elapsed = (datetime.now() - started).seconds
    print(f"\nDone in {elapsed}s. Saved -> {out_path}")
