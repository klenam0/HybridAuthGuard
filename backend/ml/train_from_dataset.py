# backend/ml/train_from_dataset.py
"""
RBA Dataset training — reviewer-revision corrected version.

WHAT CHANGED FROM THE ORIGINAL, AND WHY (see docs/DECISIONS.md, ADR-13 on
contamination, ADR-14 on the user-disjoint split and ADR-15 on frequency
encoding; this is the short version):

  - CONTAMINATION was 0.15, selected by repeatedly evaluating against the
    same data later reported as held-out, genuine test-set leakage. A
    validation-only sweep (train/validation/test actually separated)
    found 0.4 instead.
  - IP/user/country/device were raw LabelEncoder integer IDs, which let
    the model substantially memorise specific identities rather than
    learn generalisable behaviour (confirmed: ROC-AUC collapsed to
    chance level, 0.511, under a strict held-out-user test). Replaced
    with training-set FREQUENCY (how common a value is, not which one
    it is), which recovered ROC-AUC to 0.755.
  - The split was a single random train/eval division with no user
    separation, allowing the same users and IPs to appear on both
    sides. Replaced with a genuine user-disjoint split: a held-out
    fraction of users never appears in training at all.

This produces a payload tagged "encoding_scheme": "frequency", which the
corrected anomaly_model.py (also updated as part of this revision) uses
to route to the new frequency-based scoring path. Older model.pkl files
without that tag still load and score exactly as before, through the
untouched legacy path.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # noqa: E402

# ── Configuration ──────────────────────────────────────────────────────────
DATASET_PATH  = os.environ.get(
    "RBA_DATASET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "data", "rba-dataset.csv"),
)
MODEL_PATH    = os.path.join(os.path.dirname(__file__), "..", "data", "model.pkl")

CHUNK_SIZE      = 100_000
NORMAL_TARGET   = 700_000
ATTACK_TARGET   = 70_000
CONTAMINATION   = config.ML_CONTAMINATION  # settled after a validation-only sweep; was 0.15
USER_HELD_OUT_FRACTION = 0.30  # user-disjoint split
RANDOM_SEED     = 42

USECOLS = [
    "Login Timestamp", "User ID", "IP Address", "Country", "Device Type",
    "Login Successful", "Is Attack IP", "Is Account Takeover",
]


def parse_bool_col(series):
    if series.dtype == bool:
        return series
    return series.astype(str).str.strip().str.lower().isin(["true", "1", "yes"])


# ── Step 1: stream the dataset into a normal pool and an attack pool ────────

def stream_dataset():
    print("=" * 60)
    print("  RBA DATASET STREAMER (reviewer-revision corrected pipeline)")
    print("=" * 60)
    print(f"\nReading: {DATASET_PATH}")

    normal_chunks, attack_chunks = [], []
    normal_count = attack_count = total_read = 0

    try:
        reader = pd.read_csv(DATASET_PATH, usecols=USECOLS, chunksize=CHUNK_SIZE, low_memory=True)
    except FileNotFoundError:
        print(f"Dataset not found: {DATASET_PATH}")
        sys.exit(1)

    for chunk in reader:
        total_read += len(chunk)
        chunk.columns = chunk.columns.str.strip()

        chunk["is_attack"]     = parse_bool_col(chunk["Is Attack IP"])
        chunk["is_takeover"]   = parse_bool_col(chunk["Is Account Takeover"])
        chunk["is_any_attack"] = chunk["is_attack"] | chunk["is_takeover"]

        if normal_count < NORMAL_TARGET:
            normal = chunk[~chunk["is_any_attack"]].head(NORMAL_TARGET - normal_count)
            normal_chunks.append(normal)
            normal_count += len(normal)

        if attack_count < ATTACK_TARGET:
            attacks = chunk[chunk["is_any_attack"]].head(ATTACK_TARGET - attack_count)
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


# ── Step 2: user-disjoint split ──────────────────────────────────────────────

def user_disjoint_split(normal_df, attack_df, held_out_frac=USER_HELD_OUT_FRACTION, seed=RANDOM_SEED):
    """No user's normal login history appears in both train and eval.
    Attacks are split independently (attacker identities are not assumed
    to overlap meaningfully with the legitimate user population)."""
    rng = np.random.RandomState(seed)
    unique_users = np.array(normal_df["User ID"].unique(), dtype=object)
    rng.shuffle(unique_users)

    n_held_out = int(len(unique_users) * held_out_frac)
    held_out_users = set(unique_users[:n_held_out])
    train_users = set(unique_users[n_held_out:])

    train_df = normal_df[normal_df["User ID"].isin(train_users)].reset_index(drop=True)
    held_out_normal = normal_df[normal_df["User ID"].isin(held_out_users)].reset_index(drop=True)
    held_out_normal = held_out_normal.sample(frac=1.0, random_state=seed)

    val_normal  = held_out_normal.iloc[:len(held_out_normal) // 2]
    eval_normal = held_out_normal.iloc[len(held_out_normal) // 2:]

    attack_shuffled = attack_df.sample(frac=1.0, random_state=seed)
    val_attack  = attack_shuffled.iloc[:len(attack_shuffled) // 2]
    eval_attack = attack_shuffled.iloc[len(attack_shuffled) // 2:]

    val_df  = pd.concat([val_normal, val_attack], ignore_index=True)
    eval_df = pd.concat([eval_normal, eval_attack], ignore_index=True)

    print(f"\n   User-disjoint split: {len(train_users):,} train users, "
          f"{len(held_out_users):,} held-out users")
    print(f"   Train (normal only): {len(train_df):,}")
    print(f"   Validation: {len(val_df):,}  |  Eval: {len(eval_df):,}")
    return train_df, val_df, eval_df


# ── Step 3: frequency encoding ──────────────────────────────────────────────

def fit_frequency_maps(train_df):
    n = len(train_df)
    ip_counts      = train_df["IP Address"].astype(str).str.strip().value_counts()
    user_counts    = train_df["User ID"].astype(str).str.strip().value_counts()
    country_counts = train_df["Country"].fillna("XX").astype(str).str.strip().value_counts()
    device_counts  = train_df["Device Type"].fillna("Unknown").astype(str).str.strip().value_counts()
    freq_maps = {
        "ip": (ip_counts / n).to_dict(),
        "user": (user_counts / n).to_dict(),
        "country": (country_counts / n).to_dict(),
        "device": (device_counts / n).to_dict(),
    }
    known_ips_set = set(train_df["IP Address"].astype(str))
    known_countries_set = set(train_df["Country"].fillna("XX").astype(str))
    return freq_maps, known_ips_set, known_countries_set


def extract_features_freq(df, freq_maps, known_ips_set, known_countries_set):
    """10 features, frequency-encoded. See anomaly_model.py's
    _extract_features_v2_frequency() for the matching single-event
    runtime version; keep both in sync if either changes."""
    df = df.copy().reset_index(drop=True)
    hour = pd.to_datetime(df["Login Timestamp"], errors="coerce").dt.hour.fillna(12)
    df["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    df["hour_cos"] = np.cos(2 * np.pi * hour / 24)
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
    df["is_new_ip"]      = (~df["IP Address"].astype(str).isin(known_ips_set)).astype(int)
    df["is_new_country"] = (~df["Country"].fillna("XX").astype(str).isin(known_countries_set)).astype(int)

    df = df.sort_values("_orig_idx").reset_index(drop=True)
    cols = ["hour_sin", "hour_cos", "is_failed", "ip_freq", "user_freq",
            "failed_rate", "country_freq", "device_freq", "is_new_ip", "is_new_country"]
    return df[cols].values.astype(float)


# ── Step 4: train, evaluate once, save ──────────────────────────────────────

def train_and_save():
    normal_df, attack_df = stream_dataset()
    train_df, val_df, eval_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("\nFitting Isolation Forest (contamination=0.4)...")
    X_train = extract_features_freq(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    model = IsolationForest(contamination=CONTAMINATION, n_estimators=200,
                             random_state=RANDOM_SEED, n_jobs=-1,
                             max_samples=100000, max_features=1.0)
    model.fit(X_train_scaled)

    print("Evaluating once on the eval set...")
    eval_df = eval_df.copy()
    eval_df["is_any_attack"] = (
        parse_bool_col(eval_df["Is Attack IP"]) | parse_bool_col(eval_df["Is Account Takeover"])
    )
    X_eval = extract_features_freq(eval_df, freq_maps, known_ips_set, known_countries_set)
    X_eval_scaled = scaler.transform(X_eval)
    preds = model.predict(X_eval_scaled)
    scores = model.decision_function(X_eval_scaled)
    true_attack = eval_df["is_any_attack"].astype(int).values
    pred_attack = (preds == -1).astype(int)

    TP = int(((pred_attack == 1) & (true_attack == 1)).sum())
    FP = int(((pred_attack == 1) & (true_attack == 0)).sum())
    TN = int(((pred_attack == 0) & (true_attack == 0)).sum())
    FN = int(((pred_attack == 0) & (true_attack == 1)).sum())
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    recall = TP / (TP + FN) if (TP + FN) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    try:
        roc_auc = roc_auc_score(true_attack, -scores)
        pr_auc = average_precision_score(true_attack, -scores)
    except Exception:
        roc_auc = pr_auc = 0.0
    metrics = {"precision": round(precision, 4), "recall": round(recall, 4),
               "f1": round(f1, 4), "roc_auc": round(roc_auc, 4), "pr_auc": round(pr_auc, 4)}
    print(f"   Precision={metrics['precision']:.4f} Recall={metrics['recall']:.4f} "
          f"F1={metrics['f1']:.4f} ROC-AUC={metrics['roc_auc']:.4f}")

    payload = {
        "model": model, "scaler": scaler,
        "encoding_scheme": "frequency",
        "ip_freq_map": freq_maps["ip"], "user_freq_map": freq_maps["user"],
        "country_freq_map": freq_maps["country"], "device_freq_map": freq_maps["device"],
        "known_ips_set": known_ips_set, "known_countries_set": known_countries_set,
        "known_ips": list(freq_maps["ip"].keys()), "known_users": list(freq_maps["user"].keys()),
        "known_countries": list(freq_maps["country"].keys()), "known_devices": list(freq_maps["device"].keys()),
        "contamination": CONTAMINATION, "feature_count": 10,
        "feature_names": ["hour_sin", "hour_cos", "is_failed", "ip_freq", "user_freq",
                           "failed_rate", "country_freq", "device_freq", "is_new_ip", "is_new_country"],
        "trained_on": "RBA Dataset (Kaggle), user-disjoint split, frequency encoding",
        "training_size": f"{len(train_df):,} normal login events, {len(train_df['User ID'].unique()):,} users",
        "metrics": metrics,
        "trained_at": datetime.now().isoformat(),
    }

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(payload, MODEL_PATH)
    print(f"\nModel saved -> {MODEL_PATH}")

    metrics_path = os.path.join(os.path.dirname(MODEL_PATH), "model_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump({**metrics, "trained_on": payload["trained_on"],
                    "training_size": payload["training_size"],
                    "trained_at": payload["trained_at"],
                    "feature_count": payload["feature_count"],
                    "contamination": CONTAMINATION,
                    "n_estimators": model.n_estimators}, f, indent=2)
    print(f"Metrics saved -> {metrics_path}")


if __name__ == "__main__":
    train_and_save()
