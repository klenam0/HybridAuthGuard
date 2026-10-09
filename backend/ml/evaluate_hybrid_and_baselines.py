# backend/ml/evaluate_hybrid_and_baselines.py
"""
Batch 3 of the reviewer revision — answers M1 and M2 directly.

WHAT THE REVIEWER ASKED FOR (M1, quoted from the report)
============================================================
"Please replay the held-out RBA events in timestamp order through the
actual pipeline and report rules-only, Isolation-Forest-only and hybrid
results (precision, recall, F1, false-positive rate and alerts per 1,000
events), plus an ablation of detector ordering."

"Please add at least two standard baselines on identical features and
split (for example Local Outlier Factor or One-Class SVM, and an
autoencoder) and a supervised reference (Random Forest or gradient
boosting on the RBA labels)."

WHY "REPLAY THROUGH THE ACTUAL PIPELINE" MEANS SOMETHING SPECIFIC
====================================================================
The rule detectors in backend/agents/detection_agent.py are stateful —
they remember failed-attempt counts, blocked IPs, and per-user last-login
times across events. You cannot fairly test "rules-only" or "hybrid" by
scoring events independently the way the earlier batches scored the
Isolation Forest alone; the order events arrive in, and whether an
earlier event caused an IP to be blocked, changes what happens to a
later event. So this script is not a bulk scikit-learn evaluation, it is
a faithful, line-for-line port of DetectionAgent.analyze_event() (kept
deliberately close to backend/agents/detection_agent.py so it can be
diffed against it), replayed one event at a time, in timestamp order,
over the same user-disjoint test set Batches 1-2.5 already established.

Three passes are run over the identical sorted event list, each with its
own fresh, independent state, so none of them contaminate each other:
  - rules-only:  the ported analyze_event() with anomaly_detector=None
  - hybrid:      the SAME ported analyze_event(), with our settled
                 Batch 2.5 model (user-disjoint split, frequency
                 encoding, contamination=0.4) attached
  - ML-only:     a separate, simple loop that scores every event with
                 only the ML model, no rule logic and no rule-driven
                 blocking, at all

WHAT COUNTS AS "SUPPORTED BY THE REST OF THIS PROJECT"
=========================================================
The ML side of both "hybrid" and "ML-only" uses a from-scratch streaming
scorer (StreamingFrequencyMLScorer below) built on the exact settled
configuration from Batch 2.5, not the original repository's
AnomalyDetector class, which still uses the old raw-ID encoding this
whole revision moved away from. The streaming scorer updates its causal
per-IP failure counters BEFORE scoring each event, matching the same
inclusive semantics your thesis's Decision 13 already established as
correct for the original pipeline.

THE DETECTOR-ORDERING ABLATION
================================
detection_agent.py's own comments state that Slow Brute Force and
Credential Stuffing must be checked BEFORE Fast Brute Force, warning:
"Changing this order will cause misclassification: Credential stuffing
will be caught as brute force." That claim is about Fast Brute Force's
position relative to the other two, not the relative order of Slow
Brute Force and Credential Stuffing between themselves, those two are
mutually exclusive by construction (one requires fewer than 3 unique
usernames on the IP, the other requires 5 or more), so swapping just
those two can never change an outcome, confirmed directly in this
script's smoke test before it was ever pointed at real data. The actual
ablation implemented here checks Fast Brute Force first instead, which
is what the source comment's claim is really about: a credential-
stuffing event also satisfies the failed-attempt threshold Fast Brute
Force checks for, so if Fast Brute Force runs first, it wins, and the
event gets misclassified as generic "Brute Force Attack" instead of
"Credential Stuffing," exactly as the comment predicts.

BASELINES
==========
All three fit on the identical frequency-encoded features and the
identical user-disjoint train/validation/test split already established:
  - Local Outlier Factor (novelty=True), contamination tuned on
    validation the same way the Isolation Forest was.
  - A lightweight autoencoder built from sklearn's MLPRegressor (trained
    to reconstruct its own input; reconstruction error is the anomaly
    score), with its flagging threshold likewise tuned on validation.
  - A supervised Random Forest reference, trained on the union of the
    unsupervised model's normal-only training data plus the labelled
    validation set. This is the one place a label is used for training
    on purpose, since the point of this baseline is "how well could you
    do if you actually had labels." Reusing validation for this training
    set is safe against the same identity-memorisation leak fixed in
    Batch 2, because the Random Forest only ever sees the same
    frequency-encoded features as everything else, never a raw identity
    it could memorise; the test set itself is never touched by this
    baseline's training.

HOW TO RUN
==========
Save in backend/ml/, alongside the other four scripts. From backend/:

    python ml/evaluate_hybrid_and_baselines.py

Expect roughly 15-25 minutes: the rule replays are a single Python loop
over ~100,000 events (a few minutes each), the baselines each need a
small validation-only tuning grid before their one-shot test evaluation.

Writes one file, backend/results/batch3_hybrid_and_baselines_results.json,
containing every arm's precision/recall/F1/FPR/alerts-per-1000, plus the
ordering ablation. Send it back, along with whatever prints at the end.
"""

import os
import sys
import json
import numpy as np
from collections import defaultdict
from datetime import datetime
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import stream_dataset, user_disjoint_split, RESULTS_DIR, SEED_BASE
from train_from_dataset_v3 import fit_frequency_maps, extract_features_freq

# Settled configuration from Batches 1-2.5
SETTLED_CONTAMINATION = 0.4
DEFAULT_THRESHOLD = 5  # matches DetectionAgent's default and main.py's default

LOF_CONTAMINATION_GRID = [0.1, 0.2, 0.3, 0.4]
AE_PERCENTILE_GRID = [70, 80, 90, 95]


# ── Streaming ML scorer, mirrors AnomalyDetector.score_event()'s causal update ──

class StreamingFrequencyMLScorer:
    """One-event-at-a-time scorer using the settled Batch 2.5 configuration.
    Maintains its own running per-IP failure counters exactly as the real
    AnomalyDetector.score_event() does, updating them BEFORE scoring each
    event so failed_rate is inclusive of the current event."""

    def __init__(self, model, scaler, freq_maps, known_ips_set, known_countries_set):
        self.model = model
        self.scaler = scaler
        self.freq_maps = freq_maps
        self.known_ips_set = known_ips_set
        self.known_countries_set = known_countries_set
        self.ip_total_counts = defaultdict(int)
        self.ip_failure_counts = defaultdict(int)

    def score_event(self, log_event):
        ip = log_event["ip"]
        is_failed = 1 if log_event.get("status", "SUCCESS") == "FAILED" else 0

        self.ip_total_counts[ip] += 1
        if is_failed:
            self.ip_failure_counts[ip] += 1
        failed_rate = self.ip_failure_counts[ip] / self.ip_total_counts[ip]

        try:
            ts = datetime.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour = ts.hour
        except Exception:
            hour = 12
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)

        user    = log_event.get("user", "unknown")
        country = log_event.get("country", "XX")
        device  = log_event.get("device_type", "Unknown")

        ip_freq      = self.freq_maps["ip"].get(ip, 0.0)
        user_freq    = self.freq_maps["user"].get(user, 0.0)
        country_freq = self.freq_maps["country"].get(country, 0.0)
        device_freq  = self.freq_maps["device"].get(device, 0.0)
        is_new_ip      = int(ip not in self.known_ips_set)
        is_new_country = int(country not in self.known_countries_set)

        features = np.array([[hour_sin, hour_cos, is_failed, ip_freq, user_freq,
                               failed_rate, country_freq, device_freq,
                               is_new_ip, is_new_country]], dtype=float)
        features_scaled = self.scaler.transform(features)
        pred = self.model.predict(features_scaled)[0]
        return {"is_anomaly": bool(pred == -1)}


# ── Faithful port of DetectionAgent.analyze_event() ──────────────────────────

class ReplayDetector:
    """
    Line-for-line port of backend/agents/detection_agent.py's
    DetectionAgent, kept close enough to diff against the original.
    Two differences only: (1) the internal-IP guard is kept for fidelity
    but is a near no-op on RBA data, since RBA IPs are not private-range
    addresses; (2) anomaly_detector, when supplied, is a
    StreamingFrequencyMLScorer instead of the original AnomalyDetector.

    Pass credential_before_slow=True to run the ordering ablation: swaps
    the Credential Stuffing and Slow Brute Force checks, exactly the
    reordering detection_agent.py's own comments warn against.
    """

    def __init__(self, threshold=5, anomaly_detector=None, fast_brute_force_first=False):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.blocked_ips = set()
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.anomaly_detector = anomaly_detector
        self.ip_users_tried = defaultdict(set)
        self.internal_ip_prefixes = ("192.168.", "10.0.", "172.16.")
        self.suspicious_last_fired = {}
        self.ml_alerted_ips = set()
        # detection_agent.py's own comment: "Slow Brute Force / Credential
        # Stuffing checked BEFORE Fast Brute Force... Changing this order
        # will cause misclassification: Credential stuffing will be caught
        # as brute force." That claim is about Fast Brute Force's position
        # relative to the other two, not the relative order of Slow Brute
        # Force and Credential Stuffing between themselves, those two are
        # mutually exclusive by construction (unique_users < 3 vs >= 5), so
        # swapping just those two can never change an outcome. This flag
        # tests the claim the comment actually makes.
        self.fast_brute_force_first = fast_brute_force_first
        self.alert_type_counts = defaultdict(int)

    def _slow_brute_force_check(self, ip, timestamp):
        recent_failures = [t for t in self.ip_attempt_times[ip]
                            if abs((timestamp - t).total_seconds()) <= 3600]
        unique_users_for_ip = len(self.ip_users_tried[ip])
        time_spread_minutes = ((timestamp - recent_failures[0]).total_seconds() / 60
                                if recent_failures else 0)
        if (len(recent_failures) >= 4 and self.failed_attempts[ip] < self.threshold
                and time_spread_minutes >= 5 and unique_users_for_ip < 3):
            self.blocked_ips.add(ip)
            return "Slow Brute Force"
        return None

    def _credential_stuffing_check(self, ip, unique_users):
        if unique_users >= 5 and self.failed_attempts[ip] >= 5:
            self.blocked_ips.add(ip)
            return "Credential Stuffing"
        return None

    def _fast_brute_force_check(self, ip):
        if self.failed_attempts[ip] >= self.threshold:
            self.blocked_ips.add(ip)
            return "Brute Force Attack"
        return None

    def analyze_event(self, log_event):
        ip = log_event["ip"]
        user = log_event["user"]
        timestamp = datetime.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour = timestamp.hour

        self.ip_users_tried[ip].add(user)

        # 1. Suspicious Login Time
        if log_event["status"] == "SUCCESS" and 0 <= hour <= 5:
            last_fired = self.suspicious_last_fired.get(ip)
            if last_fired is None or (timestamp - last_fired).total_seconds() > 600:
                self.suspicious_last_fired[ip] = timestamp
                self.alert_type_counts["Suspicious Login Time"] += 1
                return "Suspicious Login Time"

        # 2. Multiple IP Login
        if log_event["status"] == "SUCCESS":
            prev = self.user_last_login.get(user)
            self.user_last_login[user] = (ip, timestamp)
            if prev is not None:
                last_ip, last_time = prev
                time_diff = abs((timestamp - last_time).total_seconds())
                if ip != last_ip and time_diff < 120:
                    self.alert_type_counts["Multiple IP Login"] += 1
                    return "Multiple IP Login"

        # 3, 4, 5: FAILED block, order matters
        if log_event["status"] == "FAILED":
            if ip in self.blocked_ips:
                return None

            self.ip_attempt_times[ip].append(timestamp)
            self.failed_attempts[ip] += 1
            unique_users = len(self.ip_users_tried[ip])

            if self.fast_brute_force_first:
                result = self._fast_brute_force_check(ip)
                if result:
                    self.alert_type_counts[result] += 1
                    return result

            result = self._slow_brute_force_check(ip, timestamp)
            if result:
                self.alert_type_counts[result] += 1
                return result

            result = self._credential_stuffing_check(ip, unique_users)
            if result:
                self.alert_type_counts[result] += 1
                return result

            if not self.fast_brute_force_first:
                result = self._fast_brute_force_check(ip)
                if result:
                    self.alert_type_counts[result] += 1
                    return result

        # 6. ML Anomaly
        if self.anomaly_detector:
            is_internal = ip.startswith(self.internal_ip_prefixes)
            if not is_internal:
                result = self.anomaly_detector.score_event(log_event)
                if result and result["is_anomaly"]:
                    is_failed_event = log_event.get("status") == "FAILED"
                    if is_failed_event:
                        if ip in self.ml_alerted_ips:
                            return None
                        self.ml_alerted_ips.add(ip)
                    else:
                        if ip in self.blocked_ips:
                            return None
                        self.blocked_ips.add(ip)
                    self.alert_type_counts["ML Anomaly Detected"] += 1
                    return "ML Anomaly Detected"

        return None


# ── Data preparation: convert the sorted test set into replayable events ────

def build_event_stream(test_df):
    """Sort by time, convert to the log_event dict shape analyze_event()
    expects, and return alongside the parallel ground-truth attack labels.

    Uses direct column access via zip(), not itertuples(): pandas
    itertuples() silently renames columns containing spaces (every
    column in this dataset) to positional fields, which would have made
    every getattr() fallback below quietly return a wrong default
    instead of raising an error. Caught this in the smoke test before
    it reached real data.
    """
    df = test_df.sort_values("Login Timestamp").reset_index(drop=True)

    ips        = df["IP Address"].astype(str).tolist()
    users      = df["User ID"].astype(str).tolist()
    timestamps = df["Login Timestamp"].tolist()
    is_success = (df["Login Successful"].astype(str).str.strip().str.lower()
                  .isin(["true", "1", "yes"]).tolist())
    countries  = df["Country"].fillna("XX").astype(str).tolist()
    devices    = df["Device Type"].fillna("Unknown").astype(str).tolist()

    events = []
    for ip, user, ts, success, country, device in zip(ips, users, timestamps,
                                                        is_success, countries, devices):
        events.append({
            "ip": ip, "user": user,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "SUCCESS" if success else "FAILED",
            "country": country, "device_type": device,
        })

    true_attack = (
        df["Is Attack IP"].astype(str).str.strip().str.lower().isin(["true", "1", "yes"]) |
        df["Is Account Takeover"].astype(str).str.strip().str.lower().isin(["true", "1", "yes"])
    ).values
    return events, true_attack


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(flagged, true_attack):
    flagged = np.asarray(flagged, dtype=bool)
    true_attack = np.asarray(true_attack, dtype=bool)
    TP = int((flagged & true_attack).sum())
    FP = int((flagged & ~true_attack).sum())
    TN = int((~flagged & ~true_attack).sum())
    FN = int((~flagged & true_attack).sum())
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
    alerts_per_1000 = flagged.sum() / len(flagged) * 1000
    return {
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
        "alerts_per_1000_events": round(alerts_per_1000, 2),
    }


# ── Replay passes ─────────────────────────────────────────────────────────────

def run_rules_only(events, fast_brute_force_first=False):
    detector = ReplayDetector(threshold=DEFAULT_THRESHOLD, anomaly_detector=None,
                               fast_brute_force_first=fast_brute_force_first)
    flagged = [detector.analyze_event(e) is not None for e in events]
    return flagged, dict(detector.alert_type_counts)


def run_hybrid(events, ml_scorer):
    detector = ReplayDetector(threshold=DEFAULT_THRESHOLD, anomaly_detector=ml_scorer)
    flagged = [detector.analyze_event(e) is not None for e in events]
    return flagged, dict(detector.alert_type_counts)


def run_ml_only(events, ml_scorer):
    flagged = [ml_scorer.score_event(e)["is_anomaly"] for e in events]
    return flagged


# ── Baselines ──────────────────────────────────────────────────────────────────

def extract_matrix(df, freq_maps, known_ips_set, known_countries_set):
    return extract_features_freq(df, freq_maps, known_ips_set, known_countries_set)


def tune_and_eval_lof(X_train_scaled, X_val_scaled, X_test_scaled, val_true, test_true):
    best = None
    print("   Tuning LOF contamination on VALIDATION only:")
    for c in LOF_CONTAMINATION_GRID:
        lof = LocalOutlierFactor(novelty=True, contamination=c, n_jobs=-1)
        lof.fit(X_train_scaled)
        pred = lof.predict(X_val_scaled)
        flagged = (pred == -1)
        m = compute_metrics(flagged, val_true)
        print(f"      contamination={c} -> P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
        if best is None or m["f1"] > best[1]["f1"]:
            best = (c, m, lof)
    best_c, _, _ = best
    print(f"   Best on validation: contamination={best_c}")
    lof_final = LocalOutlierFactor(novelty=True, contamination=best_c, n_jobs=-1)
    lof_final.fit(X_train_scaled)
    pred_test = lof_final.predict(X_test_scaled)
    return compute_metrics(pred_test == -1, test_true), best_c


def tune_and_eval_autoencoder(X_train_scaled, X_val_scaled, X_test_scaled, val_true, test_true):
    print("   Training lightweight autoencoder (MLPRegressor)...")
    ae = MLPRegressor(hidden_layer_sizes=(6, 3, 6), activation="relu",
                       max_iter=200, random_state=SEED_BASE)
    ae.fit(X_train_scaled, X_train_scaled)

    train_recon = ((ae.predict(X_train_scaled) - X_train_scaled) ** 2).mean(axis=1)
    val_recon   = ((ae.predict(X_val_scaled) - X_val_scaled) ** 2).mean(axis=1)
    test_recon  = ((ae.predict(X_test_scaled) - X_test_scaled) ** 2).mean(axis=1)

    best = None
    print("   Tuning reconstruction-error threshold on VALIDATION only:")
    for pct in AE_PERCENTILE_GRID:
        threshold = np.percentile(train_recon, pct)
        flagged = val_recon > threshold
        m = compute_metrics(flagged, val_true)
        print(f"      train percentile={pct} -> P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f}")
        if best is None or m["f1"] > best[1]["f1"]:
            best = (pct, m, threshold)
    best_pct, _, best_threshold = best
    print(f"   Best on validation: percentile={best_pct}")
    flagged_test = test_recon > best_threshold
    return compute_metrics(flagged_test, test_true), best_pct


def eval_supervised_rf(X_train_scaled, y_train, X_test_scaled, test_true):
    print("   Training supervised Random Forest reference "
          "(train-normal + validation labels)...")
    rf = RandomForestClassifier(n_estimators=200, random_state=SEED_BASE, n_jobs=-1,
                                 class_weight="balanced")
    rf.fit(X_train_scaled, y_train)
    pred_test = rf.predict(X_test_scaled)
    return compute_metrics(pred_test == 1, test_true)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nStarting Batch 3: hybrid vs. rules-only vs. ML-only, plus baselines...\n")
    overall_start = datetime.now()

    normal_df, attack_df = stream_dataset()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)

    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    # ── Fit the settled Isolation Forest (contamination=0.4) once ──────────
    print("\nFitting the settled Isolation Forest (contamination=0.4)...")
    X_train = extract_matrix(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    iso_model = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                                 random_state=SEED_BASE, n_jobs=-1, max_samples=100000,
                                 max_features=1.0)
    iso_model.fit(X_train_scaled)

    results = {}

    # ── Build the replayable event streams ──────────────────────────────────
    print("\nBuilding timestamp-ordered event streams...")
    test_events, test_true = build_event_stream(test_df)
    val_events, val_true = build_event_stream(val_df)
    print(f"   Test events: {len(test_events):,}  (attacks: {test_true.sum():,})")

    # ── Rules-only (default order) ──────────────────────────────────────────
    print("\n--- Rules-only (default detector order) ---")
    flagged, alert_counts = run_rules_only(test_events, fast_brute_force_first=False)
    results["rules_only_default_order"] = compute_metrics(flagged, test_true)
    results["rules_only_default_order"]["alert_type_counts"] = alert_counts
    print(f"   {results['rules_only_default_order']}")

    # ── Rules-only (ablation: fast brute force checked first) ───────────────
    print("\n--- Rules-only (ABLATION: fast-brute-force-checked-first order) ---")
    flagged_ablation, alert_counts_ablation = run_rules_only(test_events, fast_brute_force_first=True)
    results["rules_only_ablation_order"] = compute_metrics(flagged_ablation, test_true)
    results["rules_only_ablation_order"]["alert_type_counts"] = alert_counts_ablation
    print(f"   {results['rules_only_ablation_order']}")

    # ── ML-only ───────────────────────────────────────────────────────────────
    print("\n--- ML-only (settled frequency-encoded Isolation Forest) ---")
    ml_scorer_for_mlonly = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps,
                                                       known_ips_set, known_countries_set)
    flagged_ml = run_ml_only(test_events, ml_scorer_for_mlonly)
    results["ml_only"] = compute_metrics(flagged_ml, test_true)
    print(f"   {results['ml_only']}")

    # ── Hybrid (fresh ML scorer state, since ML-only already mutated one) ───
    print("\n--- Hybrid (rules + ML, faithful combined pipeline) ---")
    ml_scorer_for_hybrid = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps,
                                                       known_ips_set, known_countries_set)
    flagged_hybrid, alert_counts_hybrid = run_hybrid(test_events, ml_scorer_for_hybrid)
    results["hybrid"] = compute_metrics(flagged_hybrid, test_true)
    results["hybrid"]["alert_type_counts"] = alert_counts_hybrid
    print(f"   {results['hybrid']}")

    # ── Baselines ────────────────────────────────────────────────────────────
    print("\n--- Baseline: Local Outlier Factor ---")
    X_val = extract_matrix(val_df, freq_maps, known_ips_set, known_countries_set)
    X_test = extract_matrix(test_df, freq_maps, known_ips_set, known_countries_set)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    lof_metrics, lof_best_c = tune_and_eval_lof(X_train_scaled, X_val_scaled, X_test_scaled,
                                                 val_true, test_true)
    results["baseline_lof"] = lof_metrics
    results["baseline_lof"]["best_contamination"] = lof_best_c
    print(f"   {lof_metrics}")

    print("\n--- Baseline: Autoencoder (MLPRegressor) ---")
    ae_metrics, ae_best_pct = tune_and_eval_autoencoder(X_train_scaled, X_val_scaled, X_test_scaled,
                                                         val_true, test_true)
    results["baseline_autoencoder"] = ae_metrics
    results["baseline_autoencoder"]["best_train_percentile"] = ae_best_pct
    print(f"   {ae_metrics}")

    print("\n--- Baseline: Supervised Random Forest (train-normal + validation labels) ---")
    y_train = np.zeros(len(X_train))
    X_rf_train = np.vstack([X_train, X_val])
    y_rf_train = np.concatenate([y_train, val_true.astype(int)])
    X_rf_train_scaled = scaler.transform(X_rf_train)
    rf_metrics = eval_supervised_rf(X_rf_train_scaled, y_rf_train, X_test_scaled, test_true)
    results["baseline_supervised_rf"] = rf_metrics
    print(f"   {rf_metrics}")

    # ── Save ─────────────────────────────────────────────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_hybrid_and_baselines_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"   {'arm':<32}{'precision':<12}{'recall':<12}{'f1':<12}{'fpr':<12}{'alerts/1000':<12}")
    for name, m in results.items():
        print(f"   {name:<32}{m['precision']:<12.4f}{m['recall']:<12.4f}"
              f"{m['f1']:<12.4f}{m['fpr']:<12.4f}{m['alerts_per_1000_events']:<12.2f}")

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print(f"Saved -> {out_path}")
    print("Send this file back, plus the summary table above, for the paper rewrite.")
