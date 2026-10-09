# backend/ml/train_from_dataset_v3.py
"""
RBA Dataset training — feature-encoding fix (Batch 2 of the reviewer revision).

WHAT THIS TESTS
================
Batch 1 showed ROC-AUC collapsing from 0.802 (original, leaky) to 0.648
(temporal split) to 0.511, barely above chance, under the user-disjoint
split. That staircase is consistent with the model substantially
memorising specific IP/user identities via the raw LabelEncoder integer
codes (reviewer M6), rather than learning generalisable behavioural
patterns.

This script tests that directly, not by assuming it, by re-encoding
IP address, user ID, country, and device type as their FREQUENCY in the
training set (how common is this exact value, a number no model can use
to memorise a specific identity) instead of an arbitrary raw ID, and
reruns the exact same leakage-safe methodology from Batch 1: tune
contamination on validation only, evaluate the final model exactly once
on an untouched test set, across 10 seeds, for both split strategies.

It ALSO runs a second variant per split: a "behavioral_only" ablation
that drops all four identity-derived features entirely (frequency or
otherwise) and keeps only hour, login outcome, per-IP failure rate, and
the two new/unseen flags. This directly answers the second half of M6:
what does the detector contribute with no identity signal, of any kind,
at all.

Two things to watch for when the results come back:
  - If frequency-encoded performance recovers meaningfully under
    user_disjoint relative to Batch 1's 0.511 ROC-AUC, that is real
    evidence the behavioural features carry genuine signal once identity
    memorisation is no longer available as a shortcut.
  - If it does not recover, that is equally real evidence, and a
    different, more honest conclusion for the paper: the current feature
    set may not carry much generalisable signal for previously unseen
    users at all, independent of how identity is encoded.

Nothing here is tuned to produce a better number. The validation set
picks the contamination value, once, per split and per feature variant.
The test set is touched exactly once. Same discipline as Batch 1.

WHAT ELSE CHANGED FROM BATCH 1
================================
  - The contamination grid is extended downward (0.005, 0.01, 0.03 added)
    because Batch 1's temporal-split tuning curve was still rising toward
    the lower edge of the old grid, meaning the true optimum may sit
    below what was searched.
  - Splitting logic (stream_dataset, temporal_split, user_disjoint_split,
    label composition) is imported unchanged from train_from_dataset_v2,
    not reimplemented, so this batch isolates the effect of the encoding
    change alone.

HOW TO RUN
==========
Save this file in backend/ml/, alongside train_from_dataset.py and
train_from_dataset_v2.py (it imports from both). From backend/:

    python ml/train_from_dataset_v3.py

This runs 2 split strategies x 2 feature variants x 20 model fits each
(10 for the tuning grid, 10 for the final seed sweep) = 80 fits total.
Based on Batch 1's timing, expect roughly 1.5 to 2 hours. It streams the
same 8GB CSV Batch 1 did.

It writes four JSON files to backend/results/:
    leakage_fix_results_temporal_frequency.json
    leakage_fix_results_temporal_behavioral_only.json
    leakage_fix_results_user_disjoint_frequency.json
    leakage_fix_results_user_disjoint_behavioral_only.json

If backend/results/leakage_fix_results_temporal.json and
leakage_fix_results_user_disjoint.json (Batch 1's output) are still
present, this script also loads them and prints a combined comparison
table across all three feature variants (raw-ID, frequency, behavioral-
only) for both splits, so you can see the full picture in one place
before sending everything back.

Send all four new JSON files back, plus a copy of whatever the combined
comparison table printed at the end. I will not write a specific number
into the paper until I have this real output.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse Batch 1's streaming, splitting, and label-composition logic
# unchanged — this batch isolates the effect of the encoding change alone.
from train_from_dataset_v2 import (
    stream_dataset, temporal_split, user_disjoint_split,
    report_label_composition, parse_bool_col,
    RESULTS_DIR, N_SEEDS, SEED_BASE,
)

# ── Configuration ──────────────────────────────────────────────────────────
CONTAMINATION_GRID = [0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10, 0.12, 0.15, 0.20]

FEATURE_VARIANTS = ["frequency", "behavioral_only"]
# Column order produced by extract_features_freq():
#   0=hour_sin 1=hour_cos 2=is_failed 3=ip_freq 4=user_freq 5=failed_rate
#   6=country_freq 7=device_freq 8=is_new_ip 9=is_new_country
BEHAVIORAL_ONLY_COLUMNS = [0, 1, 2, 5, 8, 9]


# ── Frequency-encoded feature extraction ─────────────────────────────────────

def fit_frequency_maps(train_df):
    """Build training-set-only frequency tables. Never touches val/test."""
    n = len(train_df)
    ip_counts      = train_df["IP Address"].astype(str).str.strip().value_counts()
    user_counts    = train_df["User ID"].astype(str).str.strip().value_counts()
    country_counts = train_df["Country"].fillna("XX").astype(str).str.strip().value_counts()
    device_counts  = train_df["Device Type"].fillna("Unknown").astype(str).str.strip().value_counts()

    freq_maps = {
        "ip":      (ip_counts / n).to_dict(),
        "user":    (user_counts / n).to_dict(),
        "country": (country_counts / n).to_dict(),
        "device":  (device_counts / n).to_dict(),
    }
    known_ips_set       = set(train_df["IP Address"].astype(str))
    known_countries_set = set(train_df["Country"].fillna("XX").astype(str))
    return freq_maps, known_ips_set, known_countries_set


def extract_features_freq(df, freq_maps, known_ips_set=None, known_countries_set=None):
    """
    Same 10-feature layout and same causal, time-ordered failed_rate
    calculation as the original extract_features(), with IP/user/country/
    device replaced by their training-set frequency instead of a raw
    LabelEncoder integer. An entity absent from training gets frequency
    0.0, which is the correct, non-leaking behaviour, not a special case.
    """
    df = df.copy().reset_index(drop=True)

    dt_parsed = pd.to_datetime(df["Login Timestamp"], errors="coerce")
    hour = dt_parsed.dt.hour.fillna(12)
    df["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    df["hour_cos"] = np.cos(2 * np.pi * hour / 24)

    if "login_success" in df.columns:
        df["is_failed"] = (~df["login_success"].astype(bool)).astype(int)
    else:
        df["is_failed"] = (~parse_bool_col(df["Login Successful"])).astype(int)

    df["_orig_idx"] = df.index
    df = df.sort_values("Login Timestamp").reset_index(drop=True)
    df["fail_cumsum"]  = df.groupby("IP Address")["is_failed"].cumsum()
    df["total_cumsum"] = df.groupby("IP Address").cumcount() + 1
    df["failed_rate"]  = df["fail_cumsum"] / df["total_cumsum"]

    df["ip_freq"]      = df["IP Address"].astype(str).str.strip().map(freq_maps["ip"]).fillna(0.0)
    df["user_freq"]    = df["User ID"].astype(str).str.strip().map(freq_maps["user"]).fillna(0.0)
    df["country_freq"] = df["Country"].fillna("XX").astype(str).str.strip().map(freq_maps["country"]).fillna(0.0)
    df["device_freq"]  = df["Device Type"].fillna("Unknown").astype(str).str.strip().map(freq_maps["device"]).fillna(0.0)

    if known_ips_set is not None:
        df["is_new_ip"] = (~df["IP Address"].astype(str).isin(known_ips_set)).astype(int)
    else:
        df["is_new_ip"] = (df["ip_freq"] == 0.0).astype(int)

    if known_countries_set is not None:
        df["is_new_country"] = (~df["Country"].fillna("XX").astype(str).isin(known_countries_set)).astype(int)
    else:
        df["is_new_country"] = (df["country_freq"] == 0.0).astype(int)

    df = df.sort_values("_orig_idx").reset_index(drop=True)
    feature_cols = ["hour_sin", "hour_cos", "is_failed", "ip_freq", "user_freq",
                    "failed_rate", "country_freq", "device_freq", "is_new_ip", "is_new_country"]
    return df[feature_cols].values.astype(float)


# ── Fit + evaluate, per feature variant ──────────────────────────────────────

def fit_and_score(train_df, eval_df, freq_maps, known_ips_set, known_countries_set,
                   contamination, seed, feature_variant):
    X_train_full = extract_features_freq(train_df, freq_maps, known_ips_set, known_countries_set)
    X_train = X_train_full if feature_variant == "frequency" else X_train_full[:, BEHAVIORAL_ONLY_COLUMNS]

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        contamination=contamination, n_estimators=200, random_state=seed,
        n_jobs=-1, max_samples=100000, max_features=1.0,
    )
    model.fit(X_train_scaled)

    eval_df = eval_df.copy()
    eval_df["login_success"] = parse_bool_col(eval_df["Login Successful"])
    eval_df["is_any_attack"] = (
        parse_bool_col(eval_df["Is Attack IP"]) | parse_bool_col(eval_df["Is Account Takeover"])
    )

    X_eval_full = extract_features_freq(eval_df, freq_maps, known_ips_set, known_countries_set)
    X_eval = X_eval_full if feature_variant == "frequency" else X_eval_full[:, BEHAVIORAL_ONLY_COLUMNS]
    X_eval_scaled = scaler.transform(X_eval)

    preds  = model.predict(X_eval_scaled)
    scores = model.decision_function(X_eval_scaled)
    true_attack = eval_df["is_any_attack"].astype(int).values
    pred_attack = (preds == -1).astype(int)

    TP = int(((pred_attack == 1) & (true_attack == 1)).sum())
    FP = int(((pred_attack == 1) & (true_attack == 0)).sum())
    TN = int(((pred_attack == 0) & (true_attack == 0)).sum())
    FN = int(((pred_attack == 0) & (true_attack == 1)).sum())

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (TP + TN) / len(true_attack) if len(true_attack) else 0.0

    anomaly_scores = -scores
    try:
        roc_auc = roc_auc_score(true_attack, anomaly_scores)
        pr_auc  = average_precision_score(true_attack, anomaly_scores)
    except Exception:
        roc_auc = pr_auc = 0.0

    return {
        "contamination": contamination, "seed": seed, "feature_variant": feature_variant,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "accuracy": round(accuracy, 4),
        "roc_auc": round(roc_auc, 4), "pr_auc": round(pr_auc, 4),
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
    }


# ── Run one full (split strategy, feature variant) combination ──────────────

def run_strategy(name, train_df, val_df, test_df, feature_variant):
    print("\n" + "=" * 60)
    print(f"  STRATEGY: {name}  |  FEATURES: {feature_variant}")
    print("=" * 60)

    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("\n--- Tuning contamination on VALIDATION set only ---")
    tuning_results = []
    for c in CONTAMINATION_GRID:
        t0 = datetime.now()
        r = fit_and_score(train_df, val_df, freq_maps, known_ips_set, known_countries_set,
                           contamination=c, seed=SEED_BASE, feature_variant=feature_variant)
        elapsed = (datetime.now() - t0).seconds
        print(f"   contamination={c:<6} -> P={r['precision']:.3f} R={r['recall']:.3f} "
              f"F1={r['f1']:.3f} ROC-AUC={r['roc_auc']:.3f}  ({elapsed}s)")
        tuning_results.append(r)

    best = max(tuning_results, key=lambda r: r["f1"])
    best_contamination = best["contamination"]
    print(f"\n   Best on validation: contamination={best_contamination} (F1={best['f1']:.3f})")

    print(f"\n--- Refitting at contamination={best_contamination} across {N_SEEDS} seeds, "
          f"evaluated ONCE on the untouched TEST set ---")
    seed_results = []
    for i in range(N_SEEDS):
        seed = SEED_BASE + i
        t0 = datetime.now()
        r = fit_and_score(train_df, test_df, freq_maps, known_ips_set, known_countries_set,
                           contamination=best_contamination, seed=seed, feature_variant=feature_variant)
        elapsed = (datetime.now() - t0).seconds
        print(f"   seed={seed} -> P={r['precision']:.3f} R={r['recall']:.3f} "
              f"F1={r['f1']:.3f} ROC-AUC={r['roc_auc']:.3f}  ({elapsed}s)")
        seed_results.append(r)

    metrics_arr = {k: np.array([r[k] for r in seed_results])
                   for k in ["precision", "recall", "f1", "accuracy", "roc_auc", "pr_auc"]}
    summary = {
        k: {"mean": round(float(v.mean()), 4), "std": round(float(v.std()), 4),
            "min": round(float(v.min()), 4), "max": round(float(v.max()), 4)}
        for k, v in metrics_arr.items()
    }

    print(f"\n   FINAL TEST-SET RESULT ({N_SEEDS} seeds, contamination={best_contamination}):")
    for k, s in summary.items():
        print(f"      {k:10s}: mean={s['mean']:.4f}  std={s['std']:.4f}  "
              f"min={s['min']:.4f}  max={s['max']:.4f}")

    return {
        "strategy": name, "feature_variant": feature_variant,
        "train_size": len(train_df), "val_size": len(val_df), "test_size": len(test_df),
        "tuning_grid_results": tuning_results,
        "best_contamination": best_contamination,
        "seed_results": seed_results,
        "summary": summary,
    }


# ── Comparison table against Batch 1's raw-ID results, if present ───────────

def print_comparison(strategy_name, freq_result, ablation_result):
    print("\n" + "=" * 70)
    print(f"  COMPARISON ACROSS FEATURE VARIANTS — {strategy_name}")
    print("=" * 70)

    batch1_path = os.path.join(RESULTS_DIR, f"leakage_fix_results_{strategy_name}.json")
    rows = []
    if os.path.exists(batch1_path):
        with open(batch1_path) as f:
            batch1 = json.load(f)
        rows.append(("raw_id (Batch 1)", batch1["summary"]))
    else:
        print(f"   (Batch 1 file not found at {batch1_path} — skipping raw-ID row)")

    rows.append(("frequency (Batch 2)", freq_result["summary"]))
    rows.append(("behavioral_only (Batch 2)", ablation_result["summary"]))

    print(f"\n   {'variant':<28}{'precision':<12}{'recall':<12}{'f1':<12}{'roc_auc':<12}")
    for label, s in rows:
        print(f"   {label:<28}{s['precision']['mean']:<12.4f}{s['recall']['mean']:<12.4f}"
              f"{s['f1']['mean']:<12.4f}{s['roc_auc']['mean']:<12.4f}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nStarting feature-encoding evaluation pipeline (Batch 2)...\n")
    overall_start = datetime.now()

    normal_df, attack_df = stream_dataset()
    report_label_composition(attack_df)

    os.makedirs(RESULTS_DIR, exist_ok=True)

    for strategy_name, split_fn in [
        ("temporal", temporal_split),
        ("user_disjoint", user_disjoint_split),
    ]:
        train_df, val_df, test_df = split_fn(normal_df, attack_df)

        variant_results = {}
        for feature_variant in FEATURE_VARIANTS:
            result = run_strategy(f"{strategy_name}_{feature_variant}",
                                   train_df, val_df, test_df, feature_variant)
            variant_results[feature_variant] = result

            out_path = os.path.join(RESULTS_DIR,
                                     f"leakage_fix_results_{strategy_name}_{feature_variant}.json")
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)
            print(f"\nSaved -> {out_path}")

        print_comparison(strategy_name, variant_results["frequency"], variant_results["behavioral_only"])

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print("Send all four leakage_fix_results_*_{frequency,behavioral_only}.json files")
    print("back, along with the comparison tables printed above, for the paper rewrite.")
