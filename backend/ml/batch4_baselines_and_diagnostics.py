# backend/ml/batch4_baselines_and_diagnostics.py
"""
Batch 4: answers reviewer report 2 (Eng Osei, 8 Oct 2026), the items that
need real numbers before the manuscript can be rewritten.

  Item 2   Baselines at chance. Reruns LOF, autoencoder and a supervised
           Random Forest with ROC-AUC, PR-AUC and TPR at fixed FPR from
           continuous scores, thresholds tuned on validation only. Also
           replicates the OLD Random Forest design (train-normal + labelled
           validation) so the paper can say why it failed.
  Item 4   is_new_ip single-feature baseline (plus the other single
           features), attacking-IP overlap between validation and test,
           targeted-user overlap with training users.
  Item 8   TPR at 1%, 2%, 5% and 10% FPR for the Isolation Forest, and the
           attack share among the highest-scored events.
  Item 9   Single-event Isolation Forest scoring latency (scaler + predict),
           the stage the 0.023 ms/event figure most likely excluded.
  Item 13  Whether Login Timestamp hours behave like local time or UTC.

Diagnostic hypothesis being tested (state it in the paper only if the
numbers confirm it): under the user-disjoint split every held-out NORMAL
event has user_freq = 0 by construction, while every training event has
user_freq > 0. Any model that measures distance from the training
distribution can then treat "held-out user" as "anomalous". Each model is
therefore run twice: the 10-feature set used in the paper, and the same
set without user_freq.

Two test sets are evaluated:
  A  the paper's existing user-disjoint test set (identical rows to Table 1)
  B  the same held-out normals, with attacks regrouped so that no attacking
     IP appears in both validation and test (row-random splitting in
     user_disjoint_split puts most attacking IPs on both sides)

Nothing is tuned on test. Validation chooses every threshold.

HOW TO RUN (from backend/, same place as the earlier batches)
    python ml/batch4_baselines_and_diagnostics.py --quick    # smoke test, ~5-10 min
    python ml/batch4_baselines_and_diagnostics.py            # full run

The first run streams the CSV once and caches the sampled pools to
backend/data/rba_sample_cache.pkl, so every later run (and Batch 5) skips
the 8 GB read. Delete that file to force a fresh read.

Writes backend/data/batch4_results.json and backend/data/batch4_summary.txt
(quick mode writes *_QUICK versions, which are not for the paper).
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv():
    """Load KEY=VALUE lines from .env in backend/ or the repo root into the
    environment (without overriding variables already set). Python does not
    read .env files on its own."""
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (os.path.dirname(here), os.path.dirname(os.path.dirname(here)), here):
        p = os.path.join(d, ".env")
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip().removeprefix("export ").strip()
                v = v.strip().strip('"').strip("'")
                if k and v:
                    os.environ.setdefault(k, v)


_load_dotenv()

import train_from_dataset_v2 as _v2  # noqa: E402
from train_from_dataset_v2 import (RESULTS_DIR, SEED_BASE, parse_bool_col,  # noqa: E402
                                   stream_dataset, user_disjoint_split)
from train_from_dataset_v3 import extract_features_freq, fit_frequency_maps

FEATURES = ["hour_sin", "hour_cos", "is_failed", "ip_freq", "user_freq",
            "failed_rate", "country_freq", "device_freq", "is_new_ip", "is_new_country"]
FEATURE_SETS = {
    "full10": list(range(10)),
    "no_user_freq": [i for i in range(10) if FEATURES[i] != "user_freq"],
}
SETTLED_CONTAMINATION = 0.4
FPR_TARGETS = (0.01, 0.02, 0.05, 0.10)
CACHE_PATH = os.path.join(RESULTS_DIR, "rba_sample_cache.pkl")


# ── Data ─────────────────────────────────────────────────────────────────────

def load_pools():
    if os.path.exists(CACHE_PATH):
        print(f"Loading cached sample pools from {CACHE_PATH}")
        return pd.read_pickle(CACHE_PATH)
    normal_df, attack_df = stream_dataset()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    pd.to_pickle((normal_df, attack_df), CACHE_PATH)
    print(f"Cached sample pools to {CACHE_PATH}")
    return normal_df, attack_df


def labels(df):
    return (np.asarray(parse_bool_col(df["Is Attack IP"]), dtype=bool) |
            np.asarray(parse_bool_col(df["Is Account Takeover"]), dtype=bool)).astype(int)


def ip_grouped_split(val_df, test_df, seed):
    """Split B: same held-out normals as split A; attacks regrouped by IP."""
    y_val, y_test = labels(val_df), labels(test_df)
    attacks = pd.concat([val_df[y_val == 1], test_df[y_test == 1]], ignore_index=True)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed)
    a_idx, b_idx = next(gss.split(attacks, groups=attacks["IP Address"].astype(str)))
    val_b = pd.concat([val_df[y_val == 0], attacks.iloc[a_idx]], ignore_index=True)
    test_b = pd.concat([test_df[y_test == 0], attacks.iloc[b_idx]], ignore_index=True)
    return val_b, test_b


# ── Metrics ──────────────────────────────────────────────────────────────────

def thresholded(y, flagged):
    y = np.asarray(y, bool)
    f = np.asarray(flagged, bool)
    tp, fp = int((f & y).sum()), int((f & ~y).sum())
    fn, tn = int((~f & y).sum()), int((~f & ~y).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "alerts_per_1000": round(1000 * f.mean(), 2)}


def ranking(y, s):
    """Threshold-free metrics. s: higher = more anomalous / more attack-like."""
    y = np.asarray(y, int)
    s = np.asarray(s, float)
    out = {"roc_auc": round(float(roc_auc_score(y, s)), 4),
           "pr_auc": round(float(average_precision_score(y, s)), 4),
           "base_rate": round(float(y.mean()), 4)}
    fpr, tpr, _ = roc_curve(y, s)
    for t in FPR_TARGETS:
        ok = fpr <= t
        out[f"tpr_at_fpr_{t}"] = round(float(tpr[ok].max()), 4) if ok.any() else 0.0
    order = np.argsort(-s, kind="stable")
    for frac in (0.001, 0.01, 0.05):
        k = max(1, int(len(s) * frac))
        out[f"attack_share_top_{frac}"] = round(float(y[order[:k]].mean()), 4)
    return out


def best_f1_threshold(y_val, s_val, n_grid=400):
    """Choose the flagging threshold (flag if s >= thr) by max F1 on validation."""
    y_val = np.asarray(y_val, bool)
    cands = np.unique(np.quantile(s_val, np.linspace(0.0, 0.999, n_grid)))
    best_thr, best_f1 = cands[0], -1.0
    for thr in cands:
        f = s_val >= thr
        tp = (f & y_val).sum()
        denom = f.sum() + y_val.sum()
        f1 = 2 * tp / denom if denom else 0.0
        if f1 > best_f1:
            best_thr, best_f1 = thr, f1
    return float(best_thr), round(float(best_f1), 4)


def evaluate_scores(name, y_val, s_val, y_test, s_test, fixed_flags_test=None):
    thr, val_f1 = best_f1_threshold(y_val, s_val)
    res = {"model": name, "val_best_f1": val_f1,
           "val_flag_rate": round(float((s_val >= thr).mean()), 4),
           "ranking": ranking(y_test, s_test),
           "at_val_threshold": thresholded(y_test, s_test >= thr)}
    if fixed_flags_test is not None:
        res["at_settled_contamination_0.4"] = thresholded(y_test, fixed_flags_test)
    return res


def agg(dicts):
    """Mean/std across seeds for every numeric leaf."""
    out = {}
    for k in dicts[0]:
        v = dicts[0][k]
        if isinstance(v, dict):
            out[k] = agg([d[k] for d in dicts])
        elif isinstance(v, (int, float)):
            arr = np.array([d[k] for d in dicts], float)
            out[k] = {"mean": round(float(arr.mean()), 4), "std": round(float(arr.std()), 4)}
    return out


# ── Diagnostics ──────────────────────────────────────────────────────────────

def diagnostics(normal_df, attack_df, train_df, val_df, test_df, X):
    d = {}
    d["pool_time_span"] = {
        "normal": [str(normal_df["Login Timestamp"].min()), str(normal_df["Login Timestamp"].max())],
        "attack": [str(attack_df["Login Timestamp"].min()), str(attack_df["Login Timestamp"].max())],
    }
    y_val, y_test = labels(val_df), labels(test_df)
    val_ips = set(val_df.loc[y_val == 1, "IP Address"].astype(str))
    test_att = test_df.loc[y_test == 1]
    test_ips = set(test_att["IP Address"].astype(str))
    d["attack_ip_overlap_val_test"] = {
        "val_attack_ips": len(val_ips), "test_attack_ips": len(test_ips),
        "ips_in_both": len(val_ips & test_ips),
        "share_test_attack_events_with_ip_in_val":
            round(float(test_att["IP Address"].astype(str).isin(val_ips).mean()), 4),
    }
    train_users = set(train_df["User ID"].astype(str))
    train_ips = set(train_df["IP Address"].astype(str))
    d["share_test_attack_events_targeting_training_users"] = round(
        float(test_att["User ID"].astype(str).isin(train_users).mean()), 4)
    d["share_test_attack_events_from_training_ips"] = round(
        float(test_att["IP Address"].astype(str).isin(train_ips).mean()), 4)
    per_ip_test = test_att.groupby("IP Address").size()
    per_ip_pool = attack_df.groupby("IP Address").size()
    d["attack_events_per_ip"] = {"test_median": float(per_ip_test.median()),
                                 "pool_median": float(per_ip_pool.median())}

    groups = {"train": (X["train"], None),
              "test_normal": (X["test"], y_test == 0),
              "test_attack": (X["test"], y_test == 1)}
    fstats = {}
    for g, (M, mask) in groups.items():
        M = M if mask is None else M[mask]
        fstats[g] = {
            "n": int(len(M)),
            "share_user_freq_gt0": round(float((M[:, 4] > 0).mean()), 4),
            "share_ip_freq_gt0": round(float((M[:, 3] > 0).mean()), 4),
            "mean_is_new_ip": round(float(M[:, 8].mean()), 4),
            "mean_is_new_country": round(float(M[:, 9].mean()), 4),
            "mean_is_failed": round(float(M[:, 2].mean()), 4),
            "mean_failed_rate": round(float(M[:, 5].mean()), 4),
        }
    d["feature_profile"] = fstats

    # Item 13: if timestamps were UTC, the daily trough would move with each
    # country's UTC offset; if local, troughs line up across countries.
    tz = {}
    top = normal_df["Country"].value_counts().head(6).index
    for c in top:
        h = normal_df.loc[normal_df["Country"] == c, "Login Timestamp"].dt.hour.value_counts()
        h = h.reindex(range(24), fill_value=0)
        tz[str(c)] = {"n": int(h.sum()), "peak_hour": int(h.idxmax()),
                      "trough_hour": int(h.idxmin()),
                      "share_00_05": round(float(h.loc[0:5].sum() / h.sum()), 4)}
    d["hour_profile_by_country"] = tz
    return d


# ── Models ───────────────────────────────────────────────────────────────────

def run_isolation_forest(Xtr, Xv, Xt, y_val, y_test, seeds, cols):
    scaler = StandardScaler().fit(Xtr[:, cols])
    per_seed, kept = [], None
    for seed in seeds:
        m = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                            random_state=seed, n_jobs=-1,
                            max_samples=min(100_000, len(Xtr)), max_features=1.0)
        m.fit(scaler.transform(Xtr[:, cols]))
        sv = -m.decision_function(scaler.transform(Xv[:, cols]))
        Xt_s = scaler.transform(Xt[:, cols])
        st = -m.decision_function(Xt_s)
        fixed = m.predict(Xt_s) == -1
        r = evaluate_scores("isolation_forest", y_val, sv, y_test, st, fixed)
        r["seed"] = seed
        per_seed.append(r)
        if kept is None:
            kept = (m, scaler)
        print(f"      seed {seed}: ROC-AUC {r['ranking']['roc_auc']:.4f}  "
              f"TPR@1%FPR {r['ranking']['tpr_at_fpr_0.01']:.4f}")
    clean = [{k: v for k, v in r.items() if k not in ("model", "seed")} for r in per_seed]
    return {"per_seed": per_seed, "mean_std": agg(clean)}, kept


def run_lof(Xtr, Xv, Xt, y_val, y_test, cols, fit_n, seed):
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(Xtr), size=min(fit_n, len(Xtr)), replace=False)
    scaler = StandardScaler().fit(Xtr[:, cols])
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1)
    lof.fit(scaler.transform(Xtr[idx][:, cols]))
    sv = -lof.score_samples(scaler.transform(Xv[:, cols]))
    st = -lof.score_samples(scaler.transform(Xt[:, cols]))
    r = evaluate_scores("lof", y_val, sv, y_test, st)
    r["fit_rows"] = int(len(idx))
    return r


def run_autoencoder(Xtr, Xv, Xt, y_val, y_test, cols, fit_n, seed):
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(Xtr), size=min(fit_n, len(Xtr)), replace=False)
    scaler = StandardScaler().fit(Xtr[:, cols])
    A = scaler.transform(Xtr[idx][:, cols])
    ae = MLPRegressor(hidden_layer_sizes=(6, 3, 6), activation="relu", max_iter=200,
                      early_stopping=True, random_state=seed)
    ae.fit(A, A)

    def err(M):
        Ms = scaler.transform(M[:, cols])
        return ((ae.predict(Ms) - Ms) ** 2).mean(axis=1)

    r = evaluate_scores("autoencoder", y_val, err(Xv), y_test, err(Xt))
    r["fit_rows"] = int(len(idx))
    r["n_iter"] = int(ae.n_iter_)
    return r


def run_rf_supervised(Xv, Xt, y_val, y_test, groups_val, cols, seed):
    """Correct design: trained ONLY on the labelled validation pool; the
    flagging threshold comes from out-of-fold predictions grouped by IP, so
    no IP contributes to both fitting and threshold choice."""
    params = dict(n_estimators=200, min_samples_leaf=5, class_weight="balanced",
                  n_jobs=-1, random_state=seed)
    oof = np.zeros(len(Xv))
    for tr, te in GroupKFold(n_splits=5).split(Xv, y_val, groups_val):
        rf = RandomForestClassifier(**params).fit(Xv[tr][:, cols], y_val[tr])
        oof[te] = rf.predict_proba(Xv[te][:, cols])[:, 1]
    rf = RandomForestClassifier(**params).fit(Xv[:, cols], y_val)
    st = rf.predict_proba(Xt[:, cols])[:, 1]
    r = evaluate_scores("rf_supervised", y_val, oof, y_test, st)
    r["feature_importance"] = {FEATURES[c]: round(float(w), 4)
                               for c, w in zip(cols, rf.feature_importances_)}
    return r


def run_rf_old_design(Xtr, Xv, Xt, y_val, y_test, cols, seed):
    """Replicates Batch 3: training normals (all label 0) stacked with the
    labelled validation set, default 0.5 threshold."""
    Xfit = np.vstack([Xtr[:, cols], Xv[:, cols]])
    yfit = np.concatenate([np.zeros(len(Xtr), int), y_val])
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                n_jobs=-1, random_state=seed).fit(Xfit, yfit)
    st = rf.predict_proba(Xt[:, cols])[:, 1]
    return {"model": "rf_old_design_replication", "ranking": ranking(y_test, st),
            "at_0.5": thresholded(y_test, st >= 0.5),
            "feature_importance": {FEATURES[c]: round(float(w), 4)
                                   for c, w in zip(cols, rf.feature_importances_)}}


def single_feature_baselines(Xt, y_test):
    signs = {"is_new_ip": 1, "ip_freq": -1, "user_freq": -1, "failed_rate": 1,
             "is_failed": 1, "is_new_country": 1, "country_freq": -1, "device_freq": -1}
    out = {}
    for f, sign in signs.items():
        out[f] = ranking(y_test, sign * Xt[:, FEATURES.index(f)])
        out[f]["direction"] = "higher=attack" if sign > 0 else "lower=attack"
    return out


def scoring_latency(model, scaler, Xt, cols, n):
    rows = Xt[:n][:, cols]
    for r in rows[:20]:
        model.predict(scaler.transform(r.reshape(1, -1)))   # warm-up
    times = []
    for r in rows:
        t0 = time.perf_counter()
        model.predict(scaler.transform(r.reshape(1, -1)))
        times.append((time.perf_counter() - t0) * 1000)
    t = np.array(times)
    big = Xt[: min(len(Xt), 20_000)][:, cols]
    t0 = time.perf_counter()
    model.predict(scaler.transform(big))
    batch_ms = (time.perf_counter() - t0) * 1000 / len(big)
    return {"single_event_ms_mean": round(float(t.mean()), 3),
            "single_event_ms_median": round(float(np.median(t)), 3),
            "single_event_ms_p95": round(float(np.percentile(t, 95)), 3),
            "batched_ms_per_event": round(batch_ms, 4), "n_single": int(n)}


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="small smoke test, not for the paper")
    ap.add_argument("--data", help="path to rba-dataset.csv (overrides RBA_DATASET_PATH)")
    args = ap.parse_args()
    data_path = args.data or os.environ.get("RBA_DATASET_PATH")
    if data_path:
        _v2.DATASET_PATH = data_path   # stream_dataset() reads this module global
    if not os.path.exists(CACHE_PATH):
        print(f"Dataset path: {_v2.DATASET_PATH}")
        if not os.path.exists(_v2.DATASET_PATH):
            sys.exit("Dataset not found. Pass --data \"C:\\path\\to\\rba-dataset.csv\" "
                     "or set RBA_DATASET_PATH=... in backend/.env")
    q = args.quick
    seeds = [SEED_BASE] if q else [SEED_BASE + i for i in range(10)]
    lof_n, ae_n, lat_n = (10_000, 30_000, 200) if q else (100_000, 200_000, 2_000)
    tag = "_QUICK" if q else ""
    start = datetime.now()

    normal_df, attack_df = load_pools()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    if q:
        train_df = train_df.sample(n=min(60_000, len(train_df)), random_state=SEED_BASE)
        val_df = val_df.sample(n=min(20_000, len(val_df)), random_state=SEED_BASE)
        test_df = test_df.sample(n=min(20_000, len(test_df)), random_state=SEED_BASE)
    val_b, test_b = ip_grouped_split(val_df, test_df, SEED_BASE)

    freq_maps, known_ips, known_countries = fit_frequency_maps(train_df)

    def feats(df):
        return extract_features_freq(df, freq_maps, known_ips, known_countries)

    X = {"train": feats(train_df), "val": feats(val_df), "test": feats(test_df),
         "val_b": feats(val_b), "test_b": feats(test_b)}
    y = {"val": labels(val_df), "test": labels(test_df),
         "val_b": labels(val_b), "test_b": labels(test_b)}
    groups = {"val": val_df["IP Address"].astype(str).values,
              "val_b": val_b["IP Address"].astype(str).values}

    results = {"mode": "quick" if q else "full", "seeds": seeds,
               "sizes": {k: int(len(v)) for k, v in X.items()},
               "attacks": {k: int(v.sum()) for k, v in y.items()}}
    print(f"\nSizes: {results['sizes']}\nAttacks: {results['attacks']}")

    print("\n[1/6] Diagnostics")
    results["diagnostics"] = diagnostics(normal_df, attack_df, train_df, val_df, test_df, X)
    print(json.dumps(results["diagnostics"], indent=2))

    print("\n[2/6] Single-feature baselines")
    results["single_feature"] = {"A": single_feature_baselines(X["test"], y["test"]),
                                 "B": single_feature_baselines(X["test_b"], y["test_b"])}

    splits = {"A": ("val", "test"), "B": ("val_b", "test_b")}
    results["models"] = {}
    kept = None
    for fs_name, cols in FEATURE_SETS.items():
        for sp, (vk, tk) in splits.items():
            key = f"{fs_name}|split_{sp}"
            print(f"\n=== {key} ===")
            block = {}
            print("   [3/6] Isolation Forest")
            block["isolation_forest"], k = run_isolation_forest(
                X["train"], X[vk], X[tk], y[vk], y[tk], seeds, cols)
            if fs_name == "full10" and sp == "A":
                kept = k
            print("   [4/6] LOF")
            block["lof"] = run_lof(X["train"], X[vk], X[tk], y[vk], y[tk], cols, lof_n, SEED_BASE)
            print("   [4/6] Autoencoder")
            block["autoencoder"] = run_autoencoder(X["train"], X[vk], X[tk], y[vk], y[tk],
                                                   cols, ae_n, SEED_BASE)
            print("   [5/6] Random Forest (supervised, validation-trained)")
            block["rf_supervised"] = run_rf_supervised(X[vk], X[tk], y[vk], y[tk],
                                                       groups[vk], cols, SEED_BASE)
            if sp == "A":
                print("   [5/6] Random Forest (old Batch 3 design, replication)")
                block["rf_old_design"] = run_rf_old_design(X["train"], X[vk], X[tk],
                                                           y[vk], y[tk], cols, SEED_BASE)
            results["models"][key] = block

    print("\n[6/6] Scoring latency (full10 model, seed 42)")
    m, sc = kept
    results["latency"] = scoring_latency(m, sc, X["test"], FEATURE_SETS["full10"], lat_n)
    print(results["latency"])

    results["elapsed_minutes"] = round((datetime.now() - start).total_seconds() / 60, 1)

    # ── Save ──
    os.makedirs(RESULTS_DIR, exist_ok=True)
    jpath = os.path.join(RESULTS_DIR, f"batch4_results{tag}.json")
    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    lines = [f"Batch 4 summary ({results['mode']}), {results['elapsed_minutes']} min", ""]
    hdr = f"{'feature set | split':<24}{'model':<18}{'ROC-AUC':>9}{'PR-AUC':>8}{'TPR@1%':>8}" \
          f"{'TPR@5%':>8}{'P':>8}{'R':>8}{'F1':>8}{'FPR':>8}"
    lines.append(hdr)
    for key, block in results["models"].items():
        for name, r in block.items():
            if name == "isolation_forest":
                rk = {k: v["mean"] for k, v in r["mean_std"]["ranking"].items()}
                th = {k: v["mean"] for k, v in r["mean_std"]["at_settled_contamination_0.4"].items()}
                name = "IF (10-seed, c=0.4)" if not q else "IF (c=0.4)"
            elif name == "rf_old_design":
                rk, th = r["ranking"], r["at_0.5"]
            else:
                rk, th = r["ranking"], r["at_val_threshold"]
            lines.append(f"{key:<24}{name:<18}{rk['roc_auc']:>9.3f}{rk['pr_auc']:>8.3f}"
                         f"{rk['tpr_at_fpr_0.01']:>8.3f}{rk['tpr_at_fpr_0.05']:>8.3f}"
                         f"{th['precision']:>8.3f}{th['recall']:>8.3f}{th['f1']:>8.3f}{th['fpr']:>8.3f}")
    lines += ["", "Single-feature ROC-AUC (split A test):"]
    for f, r in results["single_feature"]["A"].items():
        lines.append(f"   {f:<16}{r['roc_auc']:.3f}  TPR@1%FPR {r['tpr_at_fpr_0.01']:.3f}  ({r['direction']})")
    lines += ["", "Sanity check: full10|split_A IF ROC-AUC should be about 0.755 (Batch 2.5) in full mode."]
    summary = "\n".join(lines)
    spath = os.path.join(RESULTS_DIR, f"batch4_summary{tag}.txt")
    with open(spath, "w") as f:
        f.write(summary)
    print("\n" + summary)
    print(f"\nSaved -> {jpath}\nSaved -> {spath}")


if __name__ == "__main__":
    main()
