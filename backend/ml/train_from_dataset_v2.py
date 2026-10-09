# backend/ml/train_from_dataset_v2.py
"""
RBA Dataset training — leakage-corrected version (Batch 1 of the reviewer revision).

WHAT THIS FIXES, RELATIVE TO train_from_dataset.py
====================================================
The original script tuned CONTAMINATION by re-running the whole script with
different values, each time checking the result against the same eval_df
that was later reported as the held-out test set. That is test-set leakage:
the reported numbers reflect a model selected using knowledge of the test
set, not a model evaluated on data it never touched during development.

The original split was also a random row-level split of a single pool
(`eval_normal = normal_df.sample(...)`), which does not stop the same user,
IP, or device from appearing in both train and eval. Since ip_enc and
user_enc are raw identity codes, entities seen at training time are
literally memorised, which inflates apparent performance for exactly the
event-level split used before.

This script fixes both problems by:
  1. Splitting into three disjoint sets — train / validation / test —
     rather than two. Contamination is tuned ONLY against validation.
     The test set is evaluated exactly once, after the contamination
     value is already fixed.
  2. Offering two split STRATEGIES, run one after another, so both get
     reported in the paper rather than picking whichever looks better:
       - temporal:      train < validation < test in time, mirroring how
                         the model would actually be deployed (train on
                         the past, evaluate on the future).
       - user_disjoint:  no user's login history appears in both train
                         and test, so the model cannot have memorised a
                         specific user's or IP's identity in advance.
  3. Running the FINAL, already-chosen contamination value across 10
     different random seeds (IsolationForest is stochastic) and reporting
     mean, standard deviation, min, and max, not a single point estimate.
  4. Printing the exact composition of the "attack" label (M5) — how many
     of the positives are Is Attack IP only, Is Account Takeover only, or
     both, plus distinct attacking IPs, targeted users, and IP-day
     "campaigns" — so the mimicry narrative in the paper can be corrected
     to match what the label actually represents.

WHAT THIS DOES NOT CHANGE (on purpose, scoped to this batch only)
====================================================================
  - Feature extraction itself (extract_features, imported unchanged from
    train_from_dataset.py) — the raw-ID-encoding problem (reviewer M6) is
    a separate batch.
  - Sample sizes (NORMAL_TARGET, ATTACK_TARGET) — left the same as the
    original so this batch isolates the effect of fixing the split alone.
  - n_estimators, max_samples — left the same as the original.

HOW TO RUN
==========
Save this file in the same folder as train_from_dataset.py
(backend/ml/), then from the backend/ directory:

    python ml/train_from_dataset_v2.py

It will take a while — expect roughly 30-45 minutes total, since it fits
17 Isolation Forest models per split strategy (7 for the tuning grid,
10 for the final seed sweep) and does this for both split strategies.
It streams the same 8GB CSV the original script does, so make sure
DATASET_PATH below still points at the right file.

It writes two JSON result files to backend/results/:
    leakage_fix_results_temporal.json
    leakage_fix_results_user_disjoint.json

Send both files back once this finishes. I will not write any specific
number into the paper until I have real output from this script, per how
we've been doing this throughout.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import roc_auc_score, average_precision_score
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the original script's feature extraction and boolean parsing
# unchanged — this batch fixes the split and tuning methodology only.
from train_from_dataset import parse_bool_col
from legacy_features import extract_features

# ── Configuration ──────────────────────────────────────────────────────────
DATASET_PATH   = os.environ.get(
    "RBA_DATASET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "rba-dataset.csv"),
)
RESULTS_DIR    = os.path.join(os.path.dirname(__file__), "..", "results")

CHUNK_SIZE     = 100_000
NORMAL_TARGET  = 700_000   # unchanged from the original script, on purpose
ATTACK_TARGET  = 70_000    # unchanged from the original script, on purpose

CONTAMINATION_GRID = [0.02, 0.05, 0.08, 0.10, 0.12, 0.15, 0.20]
N_SEEDS = 10                # final model refit across this many random seeds
SEED_BASE = 42

USECOLS = [
    "Login Timestamp",
    "User ID",
    "IP Address",
    "Country",
    "Device Type",
    "Login Successful",
    "Is Attack IP",
    "Is Account Takeover",
]


# ── Step 1: stream the dataset into a normal pool and an attack pool ────────
# Same streaming approach as the original script. This part was never the
# problem — the leakage is downstream, in how these pools get split.

def stream_dataset():
    print("=" * 60)
    print("  RBA DATASET STREAMER (leakage-corrected pipeline)")
    print("=" * 60)
    print(f"\nReading: {DATASET_PATH}")

    normal_chunks, attack_chunks = [], []
    normal_count = attack_count = total_read = 0

    try:
        reader = pd.read_csv(DATASET_PATH, usecols=USECOLS,
                              chunksize=CHUNK_SIZE, low_memory=True)
    except FileNotFoundError:
        print(f"Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    for chunk in reader:
        total_read += len(chunk)
        chunk.columns = chunk.columns.str.strip()

        def col_to_bool(col):
            if chunk[col].dtype == bool:
                return chunk[col]
            return chunk[col].astype(str).str.strip().str.lower().isin(["true", "1", "yes"])

        chunk["is_attack"]     = col_to_bool("Is Attack IP")
        chunk["is_takeover"]   = col_to_bool("Is Account Takeover")
        chunk["is_any_attack"] = chunk["is_attack"] | chunk["is_takeover"]

        if normal_count < NORMAL_TARGET:
            normal = chunk[~chunk["is_any_attack"]].copy()
            normal = normal.head(NORMAL_TARGET - normal_count)
            normal_chunks.append(normal)
            normal_count += len(normal)

        if attack_count < ATTACK_TARGET:
            attacks = chunk[chunk["is_any_attack"]].copy()
            attacks = attacks.head(ATTACK_TARGET - attack_count)
            attack_chunks.append(attacks)
            attack_count += len(attacks)

        print(f"   Read {total_read:>8,} | Normal: {normal_count:>6,}/{NORMAL_TARGET:,} "
              f"| Attack: {attack_count:>5,}/{ATTACK_TARGET:,}", end="\r")

        if normal_count >= NORMAL_TARGET and attack_count >= ATTACK_TARGET:
            break

    print(f"\n\nStreaming complete — {total_read:,} rows read")
    normal_df = pd.concat(normal_chunks, ignore_index=True)
    attack_df = pd.concat(attack_chunks, ignore_index=True) if attack_chunks else pd.DataFrame()

    normal_df["Login Timestamp"] = pd.to_datetime(normal_df["Login Timestamp"], errors="coerce")
    attack_df["Login Timestamp"] = pd.to_datetime(attack_df["Login Timestamp"], errors="coerce")

    return normal_df, attack_df


# ── Step 2: label diagnostics (reviewer M5) ──────────────────────────────────

def report_label_composition(attack_df):
    print("\n" + "=" * 60)
    print("  LABEL COMPOSITION (reviewer M5)")
    print("=" * 60)

    n_total     = len(attack_df)
    n_ip_only   = int((attack_df["is_attack"] & ~attack_df["is_takeover"]).sum())
    n_to_only   = int((~attack_df["is_attack"] & attack_df["is_takeover"]).sum())
    n_both      = int((attack_df["is_attack"] & attack_df["is_takeover"]).sum())

    unique_ips   = attack_df["IP Address"].nunique()
    unique_users = attack_df["User ID"].nunique()

    campaign_key = (attack_df["IP Address"].astype(str) + "|" +
                     attack_df["Login Timestamp"].dt.date.astype(str))
    n_campaigns = campaign_key.nunique()

    result = {
        "total_positive_rows": n_total,
        "attack_ip_only":      n_ip_only,
        "account_takeover_only": n_to_only,
        "both_labels":         n_both,
        "pct_account_takeover_involved": round(100 * (n_to_only + n_both) / n_total, 2) if n_total else 0,
        "unique_attacking_ips": int(unique_ips),
        "unique_targeted_users": int(unique_users),
        "distinct_ip_day_campaigns": int(n_campaigns),
    }

    print(f"   Total positive rows:              {n_total:,}")
    print(f"   Attack IP only:                   {n_ip_only:,}")
    print(f"   Account takeover only:            {n_to_only:,}")
    print(f"   Both labels:                      {n_both:,}")
    print(f"   Pct involving account takeover:   {result['pct_account_takeover_involved']}%")
    print(f"   Unique attacking IPs:             {unique_ips:,}")
    print(f"   Unique targeted users:            {unique_users:,}")
    print(f"   Distinct IP-day campaigns:        {n_campaigns:,}")
    print("\n   This is the real basis for the paper's mimicry narrative.")
    print("   If pct_account_takeover_involved is low, the recall-ceiling")
    print("   explanation needs to be rewritten around attack-IP detection,")
    print("   not behavioural mimicry, or split into two separate findings.")

    return result


# ── Step 3: split strategies ─────────────────────────────────────────────────

def temporal_split(normal_df, attack_df):
    """
    train < validation < test, strictly in time. Attacks that occurred
    before the train/validation cutoff are dropped rather than placed
    in a bucket where they don't temporally belong.
    """
    combined_timestamps = pd.concat([
        normal_df["Login Timestamp"], attack_df["Login Timestamp"]
    ], ignore_index=True)

    t1 = combined_timestamps.quantile(0.70)
    t2 = combined_timestamps.quantile(0.85)

    train_df = normal_df[normal_df["Login Timestamp"] < t1].reset_index(drop=True)

    val_normal  = normal_df[(normal_df["Login Timestamp"] >= t1) & (normal_df["Login Timestamp"] < t2)]
    val_attack  = attack_df[(attack_df["Login Timestamp"] >= t1) & (attack_df["Login Timestamp"] < t2)]
    val_df      = pd.concat([val_normal, val_attack], ignore_index=True)

    test_normal = normal_df[normal_df["Login Timestamp"] >= t2]
    test_attack = attack_df[attack_df["Login Timestamp"] >= t2]
    test_df     = pd.concat([test_normal, test_attack], ignore_index=True)

    print(f"\n   Temporal split cutoffs: train < {t1} <= validation < {t2} <= test")
    print(f"   Train (normal only): {len(train_df):,}")
    print(f"   Validation: {len(val_df):,} ({len(val_attack):,} attacks, {len(val_normal):,} normal)")
    print(f"   Test:       {len(test_df):,} ({len(test_attack):,} attacks, {len(test_normal):,} normal)")

    return train_df, val_df, test_df


def user_disjoint_split(normal_df, attack_df, held_out_frac=0.30, seed=SEED_BASE):
    """
    No user's normal login history appears in both train and test.
    Attacks are split independently since attacker identities are not
    assumed to overlap meaningfully with the legitimate user population.
    """
    rng = np.random.RandomState(seed)
    unique_users = np.array(normal_df["User ID"].unique(), dtype=object)
    rng.shuffle(unique_users)

    n_held_out = int(len(unique_users) * held_out_frac)
    held_out_users = set(unique_users[:n_held_out])
    train_users    = set(unique_users[n_held_out:])

    train_df = normal_df[normal_df["User ID"].isin(train_users)].reset_index(drop=True)
    held_out_normal = normal_df[normal_df["User ID"].isin(held_out_users)].reset_index(drop=True)

    # Split held-out normal and all attacks 50/50 into validation/test by
    # random row assignment (fixed seed), since there is no temporal or
    # user-identity ordering constraint left to enforce at this stage.
    held_out_normal = held_out_normal.sample(frac=1.0, random_state=seed)
    val_normal  = held_out_normal.iloc[:len(held_out_normal) // 2]
    test_normal = held_out_normal.iloc[len(held_out_normal) // 2:]

    attack_shuffled = attack_df.sample(frac=1.0, random_state=seed)
    val_attack  = attack_shuffled.iloc[:len(attack_shuffled) // 2]
    test_attack = attack_shuffled.iloc[len(attack_shuffled) // 2:]

    val_df  = pd.concat([val_normal, val_attack], ignore_index=True)
    test_df = pd.concat([test_normal, test_attack], ignore_index=True)

    print(f"\n   User-disjoint split: {len(train_users):,} train users, "
          f"{len(held_out_users):,} held-out users")
    print(f"   Train (normal only): {len(train_df):,}")
    print(f"   Validation: {len(val_df):,} ({len(val_attack):,} attacks, {len(val_normal):,} normal)")
    print(f"   Test:       {len(test_df):,} ({len(test_attack):,} attacks, {len(test_normal):,} normal)")

    return train_df, val_df, test_df


# ── Step 4: fit + evaluate helpers ───────────────────────────────────────────

def fit_encoders(train_df):
    train_df = train_df.copy()
    train_df["login_success"] = parse_bool_col(train_df["Login Successful"])

    ip_enc, user_enc = LabelEncoder(), LabelEncoder()
    country_enc, device_enc = LabelEncoder(), LabelEncoder()

    ip_enc.fit(train_df["IP Address"].astype(str).str.strip())
    user_enc.fit(train_df["User ID"].astype(str).str.strip())
    country_enc.fit(train_df["Country"].fillna("XX").astype(str).str.strip())
    device_enc.fit(train_df["Device Type"].fillna("Unknown").astype(str).str.strip())

    known_ips_set       = set(train_df["IP Address"].astype(str))
    known_countries_set = set(train_df["Country"].fillna("XX").astype(str))

    return ip_enc, user_enc, country_enc, device_enc, known_ips_set, known_countries_set


def fit_and_score(train_df, eval_df, encoders, contamination, seed):
    ip_enc, user_enc, country_enc, device_enc, known_ips_set, known_countries_set = encoders

    X_train = extract_features(train_df, ip_enc, user_enc, country_enc, device_enc,
                                known_ips_set=known_ips_set, known_countries_set=known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = IsolationForest(
        contamination=contamination,
        n_estimators=200,
        random_state=seed,
        n_jobs=-1,
        max_samples=100000,
        max_features=1.0,
    )
    model.fit(X_train_scaled)

    eval_df = eval_df.copy()
    eval_df["login_success"] = parse_bool_col(eval_df["Login Successful"])
    # is_any_attack survives from stream_dataset()'s chunk-level labelling for
    # rows drawn from normal_df/attack_df directly, but is recomputed here
    # explicitly from the raw label columns so this function is correct
    # regardless of what the caller passed in.
    eval_df["is_any_attack"] = (
        parse_bool_col(eval_df["Is Attack IP"]) | parse_bool_col(eval_df["Is Account Takeover"])
    )

    X_eval = extract_features(eval_df, ip_enc, user_enc, country_enc, device_enc,
                               known_ips_set=known_ips_set, known_countries_set=known_countries_set)
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
        "contamination": contamination, "seed": seed,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "accuracy": round(accuracy, 4),
        "roc_auc": round(roc_auc, 4), "pr_auc": round(pr_auc, 4),
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
    }


# ── Step 5: run one full split strategy end to end ───────────────────────────

def run_strategy(name, train_df, val_df, test_df):
    print("\n" + "=" * 60)
    print(f"  STRATEGY: {name}")
    print("=" * 60)

    encoders = fit_encoders(train_df)

    print("\n--- Tuning contamination on VALIDATION set only ---")
    tuning_results = []
    for c in CONTAMINATION_GRID:
        t0 = datetime.now()
        r = fit_and_score(train_df, val_df, encoders, contamination=c, seed=SEED_BASE)
        elapsed = (datetime.now() - t0).seconds
        print(f"   contamination={c:<5} -> P={r['precision']:.3f} R={r['recall']:.3f} "
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
        r = fit_and_score(train_df, test_df, encoders, contamination=best_contamination, seed=seed)
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
        "strategy": name,
        "train_size": len(train_df), "val_size": len(val_df), "test_size": len(test_df),
        "tuning_grid_results": tuning_results,
        "best_contamination": best_contamination,
        "seed_results": seed_results,
        "summary": summary,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nStarting leakage-corrected evaluation pipeline...\n")
    overall_start = datetime.now()

    normal_df, attack_df = stream_dataset()
    label_composition = report_label_composition(attack_df)

    os.makedirs(RESULTS_DIR, exist_ok=True)

    for strategy_name, split_fn in [
        ("temporal", temporal_split),
        ("user_disjoint", user_disjoint_split),
    ]:
        train_df, val_df, test_df = split_fn(normal_df, attack_df)
        result = run_strategy(strategy_name, train_df, val_df, test_df)
        result["label_composition"] = label_composition

        out_path = os.path.join(RESULTS_DIR, f"leakage_fix_results_{strategy_name}.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nSaved -> {out_path}")

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print("Send both leakage_fix_results_*.json files back for the paper rewrite.")
