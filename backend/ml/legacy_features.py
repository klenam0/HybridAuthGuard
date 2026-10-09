# backend/ml/legacy_features.py
"""
Raw label-encoder feature extraction from the original (pre-revision) pipeline.
Kept only so the Batch 1 leakage experiments in train_from_dataset_v2.py
reproduce exactly. Not used by the deployed model.

Copied verbatim from backend/ml/train_from_dataset.py at commit 48c66c0.
"""

import numpy as np
import pandas as pd


# ── Step 2: Parse boolean columns ─────────────────────────────────────────────

def parse_bool_col(series):
    if series.dtype == bool:
        return series
    return series.astype(str).str.strip().str.lower().isin(["true","1","yes"])


# ── Step 3: Feature extraction ────────────────────────────────────────────────

def extract_features(df, ip_enc, user_enc, country_enc, device_enc,
                     known_ips_set=None, known_countries_set=None):
    """
    9-feature extraction - proven 7 features + 2 targeted additions.

    Features:
      [0]  hour_sin       - cyclic hour encoding (sine)
      [1]  hour_cos       - cyclic hour encoding (cosine)
      [2]  is_failed      - 1 if login failed, 0 if success
      [3]  ip_encoded     - LabelEncoder ID for IP (proven effective)
      [4]  user_encoded   - LabelEncoder ID for user
      [5]  failed_rate    - rolling cumulative failure rate per IP
      [6]  country_encoded - LabelEncoder ID for country
      [7]  device_encoded - LabelEncoder ID for device type
      [8]  is_new_ip      - 1 if IP never seen in training data (NEW)
      [9]  is_new_country - 1 if country never seen in training (NEW)

    Changes from best working model:
      - raw hour replaced with hour_sin + hour_cos (fixes 23/0 boundary)
      - is_new_ip added (direct unknown external IP signal)
      - is_new_country added (direct unknown country signal)
      Total: 7 → 9 features (+2 targeted additions)
    """
    df = df.copy().reset_index(drop=True)

    # ── Parse timestamp ────────────────────────────────────────────────────
    dt_parsed = pd.to_datetime(df["Login Timestamp"], errors="coerce")
    hour      = dt_parsed.dt.hour.fillna(12)

    # ── Cyclic hour encoding ───────────────────────────────────────────────
    df["hour_sin"] = np.sin(2 * np.pi * hour / 24)
    df["hour_cos"] = np.cos(2 * np.pi * hour / 24)

    # ── Is failed ─────────────────────────────────────────────────────────
    if "login_success" in df.columns:
        df["is_failed"] = (~df["login_success"].astype(bool)).astype(int)
    else:
        df["is_failed"] = (~parse_bool_col(df["Login Successful"])).astype(int)

    # ── Sort chronologically for rolling failure rate ──────────────────────
    df["_orig_idx"] = df.index
    df = df.sort_values("Login Timestamp").reset_index(drop=True)

    df["fail_cumsum"]  = df.groupby("IP Address")["is_failed"].cumsum()
    df["total_cumsum"] = df.groupby("IP Address").cumcount() + 1
    df["failed_rate"]  = df["fail_cumsum"] / df["total_cumsum"]

    # ── LabelEncoder mappings (same as best working model) ─────────────────
    def encode_col(series, encoder):
        mapping = {cls: idx for idx, cls in enumerate(encoder.classes_)}
        return series.astype(str).str.strip().map(mapping).fillna(-1).astype(int)

    df["ip_enc"]      = encode_col(df["IP Address"],             ip_enc)
    df["user_enc"]    = encode_col(df["User ID"],                user_enc)
    df["country_enc"] = encode_col(df["Country"].fillna("XX"),   country_enc)
    df["device_enc"]  = encode_col(
        df["Device Type"].fillna("Unknown"), device_enc
    )

    # ── NEW: is_new_ip flag ────────────────────────────────────────────────
    # 1 if IP was never seen in training data - strong anomaly signal
    if known_ips_set is not None:
        df["is_new_ip"] = (~df["IP Address"].astype(str)
                            .isin(known_ips_set)).astype(int)
    else:
        # At training time: ip_enc == -1 means unseen
        df["is_new_ip"] = (df["ip_enc"] == -1).astype(int)

   # ── NEW: is_new_country flag ───────────────────────────────────────────
    # Use known_countries_set if provided (inference path)
    # Fall back to country_enc == -1 (training path - same result)
    if known_countries_set is not None:
        df["is_new_country"] = (~df["Country"].fillna("XX").astype(str)
                                .isin(known_countries_set)).astype(int)
    else:
        df["is_new_country"] = (df["country_enc"] == -1).astype(int)

    # ── Restore original order ─────────────────────────────────────────────
    df = df.sort_values("_orig_idx").reset_index(drop=True)

    feature_cols = [
        "hour_sin", "hour_cos",
        "is_failed",
        "ip_enc",
        "user_enc",
        "failed_rate",
        "country_enc",
        "device_enc",
        "is_new_ip",
        "is_new_country",
    ]
    return df[feature_cols].values.astype(float)

