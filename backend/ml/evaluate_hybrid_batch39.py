# backend/ml/evaluate_hybrid_batch39.py
"""
Batch 3.9 - final sweep with the settled configuration, plus two checklist
items from the reviewer's Part D table: the full prevalence table (D3)
and ROC/precision-recall/score-histogram curve data (D4).

WHY THIS RERUN, NOT JUST BATCH 3.8's NUMBERS
================================================
Batch 3.7's frontier and three policies (max F1, campaign recall at
FPR<=10%, campaign recall at FPR<=20%) were computed with the internal-IP
guard ON. Batch 3.8 showed the guard should be OFF: it recovers all 457
missing campaigns at a modest FPR cost. That means every number on
Batch 3.7's frontier, and all three policies chosen from it, belong to a
configuration you are no longer using. This script reruns the same
sweep with the guard off throughout, so the frontier and the policies
chosen from it actually describe the system going into the paper.

WHAT'S NEW, MAPPED TO THE REVIEWER'S PART D CHECKLIST
=========================================================
D3 (precision at 50%, 10%, 5%, 1% prevalence, FPR, alerts/1,000 events):
  earlier batches only computed 5% and 1%. summarize() below adds 50%
  and 10%, so all four required points are reported together.
D4 (ROC curve, precision-recall curve, score histogram, confidence
  intervals over seeds): confidence intervals over seeds were already
  done in Batches 1, 2, and 2.5. This script adds the other three. ROC
  and PR curves come straight from the Isolation Forest's continuous
  test-set scores, already computed as part of the sweep, via sklearn's
  roc_curve and precision_recall_curve, no new model fits needed. The
  score histogram is two arrays of per-event anomaly scores, one for
  genuine events and one for attacks, binned the same way, meant to be
  plotted as an overlaid histogram in the paper.

HOW TO RUN
==========
Save in backend/ml/, alongside evaluate_hybrid_batch37.py (this script
imports from it). From backend/:

    python ml/evaluate_hybrid_batch39.py

Should take well under two minutes, same order of speed as Batch 3.7,
no retraining, only replay passes and curve computation.

Writes backend/results/batch3_9_final_sweep_results.json. Send it back, or
paste the printed tables.
"""

import os
import sys
import json
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_curve, precision_recall_curve

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import stream_dataset, user_disjoint_split, RESULTS_DIR, SEED_BASE
from train_from_dataset_v3 import fit_frequency_maps
from evaluate_hybrid_and_baselines import extract_matrix, SETTLED_CONTAMINATION
from evaluate_hybrid_batch37 import (
    sort_stream_df, events_from_sorted_df, features_presorted,
    run_hybrid, compute_metrics, campaign_metrics, SWEEP_GRID, FPR_BUDGETS,
)

PREVALENCE_GRID = [0.50, 0.10, 0.05, 0.01]
HISTOGRAM_BINS = 40


def precision_at_prevalence(tpr, fpr, prevalence):
    denom = prevalence * tpr + (1 - prevalence) * fpr
    return round(prevalence * tpr / denom, 4) if denom > 0 else 0.0


def summarize(events, flagged, true_attack):
    """Same as evaluate_hybrid_batch37.summarize(), extended with the full
    D3 prevalence table (50/10/5/1%) instead of just 5% and 1%."""
    m = compute_metrics(flagged, true_attack)
    m.update(campaign_metrics(events, flagged, true_attack))
    m["precision_at_prevalence"] = {
        f"{int(p * 100)}pct": precision_at_prevalence(m["recall"], m["fpr"], p)
        for p in PREVALENCE_GRID
    }
    m["false_alerts_per_1000_logins_at_1pct_prevalence"] = round(m["fpr"] * 990, 1)
    return m


def sweep_guard_off(scores, train_scores, events, true_attack, grid):
    rows = []
    for c in grid:
        threshold = np.percentile(train_scores, 100.0 * c)
        ml_flags = scores < threshold
        flagged, _ = run_hybrid(events, ml_flags, cooldown=0, internal_ip_guard=False)
        row = summarize(events, flagged, true_attack)
        row["contamination"] = c
        rows.append(row)
    return rows


def choose_policies(val_rows):
    policies = {"A_max_f1": max(val_rows, key=lambda r: r["f1"])["contamination"]}
    for budget in FPR_BUDGETS:
        feasible = [r for r in val_rows if r["fpr"] <= budget]
        if feasible:
            best = max(feasible, key=lambda r: (r["campaign_level_recall"], -r["fpr"]))
            policies[f"campaign_recall_at_fpr_le_{int(budget * 100)}pct"] = best["contamination"]
        else:
            policies[f"campaign_recall_at_fpr_le_{int(budget * 100)}pct"] = None
    return policies


def print_frontier(title, rows):
    print(f"\n   {title}")
    print(f"   {'contam':<8}{'evt-recall':<12}{'camp-recall':<13}{'F1':<8}{'FPR':<8}"
          f"{'P@50%':<8}{'P@10%':<8}{'P@5%':<8}{'P@1%':<8}")
    for r in rows:
        p = r["precision_at_prevalence"]
        print(f"   {r['contamination']:<8}{r['recall']:<12.4f}{r['campaign_level_recall']:<13.4f}"
              f"{r['f1']:<8.4f}{r['fpr']:<8.4f}{p['50pct']:<8.4f}{p['10pct']:<8.4f}"
              f"{p['5pct']:<8.4f}{p['1pct']:<8.4f}")


if __name__ == "__main__":
    print("\nStarting Batch 3.9: final sweep (guard off) + D3/D4 curve data...\n")
    started = datetime.now()

    normal_df, attack_df = stream_dataset()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("Fitting the settled Isolation Forest (contamination=0.4) once...")
    X_train = extract_matrix(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    iso = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                          random_state=SEED_BASE, n_jobs=-1, max_samples=100000,
                          max_features=1.0)
    iso.fit(X_train_scaled)
    train_scores = iso.score_samples(X_train_scaled)

    val_sorted, test_sorted = sort_stream_df(val_df), sort_stream_df(test_df)
    val_events, val_true = events_from_sorted_df(val_sorted)
    test_events, test_true = events_from_sorted_df(test_sorted)
    X_val_scaled = scaler.transform(features_presorted(val_sorted, freq_maps, known_ips_set, known_countries_set))
    X_test_scaled = scaler.transform(features_presorted(test_sorted, freq_maps, known_ips_set, known_countries_set))
    val_scores = iso.score_samples(X_val_scaled)
    test_scores = iso.score_samples(X_test_scaled)
    print(f"Test events: {len(test_events):,} (attacks: {int(test_true.sum()):,})\n")

    results = {}

    # ── Settled configuration, guard off, confirmed fresh in this run ──────
    settled_threshold = np.percentile(train_scores, 100.0 * SETTLED_CONTAMINATION)
    ml_flags_test = test_scores < settled_threshold
    rules_flags, _ = run_hybrid(test_events, None)
    hybrid_flags, hybrid_counts = run_hybrid(test_events, ml_flags_test, cooldown=0,
                                             internal_ip_guard=False)
    ml_only_flags = ml_flags_test

    results["rules_only"] = summarize(test_events, rules_flags, test_true)
    results["ml_only"] = summarize(test_events, ml_only_flags, test_true)
    results["hybrid_settled_guard_off"] = summarize(test_events, hybrid_flags, test_true)
    results["hybrid_settled_guard_off"]["alert_type_counts"] = hybrid_counts

    print("=" * 90)
    print("  SETTLED CONFIGURATION ON TEST (contamination=0.4, cooldown=0, guard OFF)")
    print("=" * 90)
    for name in ["rules_only", "ml_only", "hybrid_settled_guard_off"]:
        r = results[name]
        p = r["precision_at_prevalence"]
        print(f"   {name:<28} recall={r['recall']:.4f}  campaign={r['campaign_level_recall']:.4f}  "
              f"F1={r['f1']:.4f}  FPR={r['fpr']:.4f}  P@50/10/5/1%="
              f"{p['50pct']:.3f}/{p['10pct']:.3f}/{p['5pct']:.3f}/{p['1pct']:.3f}")

    # ── Full sweep, guard off, on validation and test ──────────────────────
    print("\nSweeping operating points (guard off, cooldown=0)...")
    val_rows = sweep_guard_off(val_scores, train_scores, val_events, val_true, SWEEP_GRID)
    test_rows = sweep_guard_off(test_scores, train_scores, test_events, test_true, SWEEP_GRID)
    policies = choose_policies(val_rows)
    results["frontier_validation"] = val_rows
    results["frontier_test"] = test_rows
    results["policies_chosen_on_validation"] = policies

    print_frontier("VALIDATION", val_rows)
    print_frontier("TEST", test_rows)

    print("\n" + "=" * 90)
    print("  FINAL POLICIES (guard off): chosen on validation, reported once on test")
    print("=" * 90)
    by_c_test = {r["contamination"]: r for r in test_rows}
    policy_results = {}
    for name, c in policies.items():
        if c is None:
            print(f"   {name}: no setting met the FPR budget on validation")
            continue
        t = by_c_test[c]
        policy_results[name] = {"contamination": c, "test": t}
        p = t["precision_at_prevalence"]
        print(f"   {name}: c={c}  recall={t['recall']:.4f}  campaign={t['campaign_level_recall']:.4f}  "
              f"F1={t['f1']:.4f}  FPR={t['fpr']:.4f}  P@5%={p['5pct']:.4f}  P@1%={p['1pct']:.4f}")
    results["policy_results_on_test"] = policy_results

    # ── D4: ROC curve, PR curve, score histogram (test set, ML scores) ─────
    print("\nComputing ROC / precision-recall / score-histogram data for D4...")
    anomaly_scores = -test_scores  # higher = more anomalous, matches earlier batches' convention
    fpr_arr, tpr_arr, roc_thresholds = roc_curve(test_true, anomaly_scores)
    prec_arr, rec_arr, pr_thresholds = precision_recall_curve(test_true, anomaly_scores)

    normal_scores = anomaly_scores[~test_true]
    attack_scores = anomaly_scores[test_true]
    lo, hi = float(anomaly_scores.min()), float(anomaly_scores.max())
    bin_edges = np.linspace(lo, hi, HISTOGRAM_BINS + 1)
    normal_hist, _ = np.histogram(normal_scores, bins=bin_edges)
    attack_hist, _ = np.histogram(attack_scores, bins=bin_edges)

    results["curve_data"] = {
        "roc_curve": {"fpr": fpr_arr.tolist(), "tpr": tpr_arr.tolist()},
        "precision_recall_curve": {"precision": prec_arr.tolist(), "recall": rec_arr.tolist()},
        "score_histogram": {
            "bin_edges": bin_edges.tolist(),
            "normal_counts": normal_hist.tolist(),
            "attack_counts": attack_hist.tolist(),
            "note": "higher score = more anomalous (negated decision_function, "
                    "matches every earlier batch's convention)",
        },
    }
    print(f"   ROC points: {len(fpr_arr)}, PR points: {len(prec_arr)}, "
          f"histogram bins: {HISTOGRAM_BINS} (score range {lo:.3f} to {hi:.3f})")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_9_final_sweep_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    elapsed = (datetime.now() - started).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print(f"Saved -> {out_path}")
    print("Send the file back, or paste the printed tables.")
