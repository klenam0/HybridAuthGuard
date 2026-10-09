# backend/ml/evaluate_hybrid_fix.py
"""
Batch 3.5 - tests a specific fix for the hybrid collapse Batch 3 found.

WHAT BATCH 3 FOUND
====================
Hybrid's recall (14.3%) was dramatically lower than ML-only's recall
(77.9%) on the identical test set. Root cause, traced through the actual
detection_agent.py logic: when the ML detector flags a SUCCESS event as
anomalous, it adds that IP to self.blocked_ips. The FAILED-event block's
very first line is `if ip in self.blocked_ips: return None`, which
executes BEFORE failed_attempts[ip] is incremented. So one ML-flagged
SUCCESS event permanently stops the rule detectors from ever accumulating
further evidence against that IP again, even while a genuine, ongoing
brute-force or credential-stuffing campaign continues arriving from it.
Evidence for this: the two SUCCESS-checked rules (Suspicious Login Time,
Multiple IP Login) were byte-for-byte identical between rules-only and
hybrid; every FAILED-checked rule dropped substantially.

THE FIX
========
blocked_ips was doing two jobs at once: "a rule confirmed and blocked
this IP" (which should legitimately stop further rule processing for
that IP) and "ML flagged this IP once, don't alert on it again" (which
should NOT stop rule processing for that IP). This script splits them
into rule_blocked_ips and ml_blocked_ips, and changes the FAILED block's
gate to check only rule_blocked_ips. Everything else about the pipeline
is unchanged.

Pass separate_ml_blocking=False to ReplayDetectorV2 to reproduce Batch
3's original, buggy behaviour exactly (used here as a same-run reference
point rather than trusting numbers from a separate script execution).
Pass True to apply the fix.

WHAT THIS SCRIPT DOES, IN ORDER
=================================
  1. A deterministic unit test using a stub ML scorer with hardcoded
     outputs, not the real trained model, proving the fix mechanism
     works exactly as intended before it goes anywhere near real data.
  2. Refits the identical settled Isolation Forest (user-disjoint,
     frequency encoding, contamination=0.4) and reruns rules-only,
     hybrid-original (the Batch 3 bug, recomputed here for a clean,
     same-run comparison), and hybrid-fixed, on the same real test set,
     in the same replay.

HOW TO RUN
==========
Save in backend/ml/, alongside the other five scripts (it imports
build_event_stream, compute_metrics, and StreamingFrequencyMLScorer
directly from evaluate_hybrid_and_baselines.py, so that file must be
in the same folder). From backend/:

    python ml/evaluate_hybrid_fix.py

Baselines (LOF, autoencoder, supervised RF) are not rerun here, they
do not depend on this bug at all. Expect well under Batch 3's 41
minutes, likely 10-15, since only the model fit and three replay
passes over the test set are needed.

Writes backend/results/batch3_5_hybrid_fix_results.json. Send it back,
plus the printed unit-test result and the final comparison table.
"""

import os
import sys
import json
from collections import defaultdict
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import stream_dataset, user_disjoint_split, RESULTS_DIR, SEED_BASE
from train_from_dataset_v3 import fit_frequency_maps
from evaluate_hybrid_and_baselines import (
    build_event_stream, compute_metrics, extract_matrix, StreamingFrequencyMLScorer,
    SETTLED_CONTAMINATION, DEFAULT_THRESHOLD,
)


class ReplayDetectorV2:
    """
    Same as ReplayDetector in evaluate_hybrid_and_baselines.py, with one
    change: rule_blocked_ips and ml_blocked_ips are tracked separately.
    separate_ml_blocking=False reproduces Batch 3's original behaviour
    (kept as a same-run reference point); True applies the fix.
    """

    def __init__(self, threshold=5, anomaly_detector=None, separate_ml_blocking=False):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.rule_blocked_ips = set()
        self.ml_blocked_ips = set()
        self.separate_ml_blocking = separate_ml_blocking
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.anomaly_detector = anomaly_detector
        self.ip_users_tried = defaultdict(set)
        self.internal_ip_prefixes = ("192.168.", "10.0.", "172.16.")
        self.suspicious_last_fired = {}
        self.ml_alerted_ips = set()
        self.alert_type_counts = defaultdict(int)

    def _failed_block_gate(self, ip):
        """The exact line the fix changes. False mode (Batch 3's original
        behaviour): gated by anything either rules or ML has blocked.
        True mode (fixed): gated only by what rules themselves blocked."""
        if self.separate_ml_blocking:
            return ip in self.rule_blocked_ips
        return ip in self.rule_blocked_ips or ip in self.ml_blocked_ips

    def _slow_brute_force_check(self, ip, timestamp):
        recent_failures = [t for t in self.ip_attempt_times[ip]
                            if abs((timestamp - t).total_seconds()) <= 3600]
        unique_users_for_ip = len(self.ip_users_tried[ip])
        time_spread_minutes = ((timestamp - recent_failures[0]).total_seconds() / 60
                                if recent_failures else 0)
        if (len(recent_failures) >= 4 and self.failed_attempts[ip] < self.threshold
                and time_spread_minutes >= 5 and unique_users_for_ip < 3):
            self.rule_blocked_ips.add(ip)
            return "Slow Brute Force"
        return None

    def _credential_stuffing_check(self, ip, unique_users):
        if unique_users >= 5 and self.failed_attempts[ip] >= 5:
            self.rule_blocked_ips.add(ip)
            return "Credential Stuffing"
        return None

    def _fast_brute_force_check(self, ip):
        if self.failed_attempts[ip] >= self.threshold:
            self.rule_blocked_ips.add(ip)
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

        # 3, 4, 5: FAILED block. THE FIX: this gate now checks only
        # rule_blocked_ips when separate_ml_blocking=True, instead of
        # both rule- and ML-driven blocks together.
        if log_event["status"] == "FAILED":
            if self._failed_block_gate(ip):
                return None

            self.ip_attempt_times[ip].append(timestamp)
            self.failed_attempts[ip] += 1
            unique_users = len(self.ip_users_tried[ip])

            result = self._slow_brute_force_check(ip, timestamp)
            if result:
                self.alert_type_counts[result] += 1
                return result

            result = self._credential_stuffing_check(ip, unique_users)
            if result:
                self.alert_type_counts[result] += 1
                return result

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
                        if ip in self.rule_blocked_ips or ip in self.ml_blocked_ips:
                            return None
                        self.ml_blocked_ips.add(ip)
                    self.alert_type_counts["ML Anomaly Detected"] += 1
                    return "ML Anomaly Detected"

        return None


def run_pass(events, anomaly_detector, separate_ml_blocking):
    detector = ReplayDetectorV2(threshold=DEFAULT_THRESHOLD, anomaly_detector=anomaly_detector,
                                 separate_ml_blocking=separate_ml_blocking)
    flagged = [detector.analyze_event(e) is not None for e in events]
    return flagged, dict(detector.alert_type_counts)


# ── Deterministic unit test: proves the mechanism with a stub scorer ────────

class StubMLScorer:
    """Hardcoded: flags exactly one IP's SUCCESS event as anomalous,
    nothing else. Removes all dependence on the real trained model so
    this test proves the FIX mechanism, not the model's behaviour."""

    def __init__(self, flag_ip):
        self.flag_ip = flag_ip

    def score_event(self, log_event):
        is_anomaly = (log_event["ip"] == self.flag_ip and log_event["status"] == "SUCCESS")
        return {"is_anomaly": is_anomaly}


def unit_test_fix_mechanism():
    print("=" * 70)
    print("  UNIT TEST: does the fix actually stop ML from silencing rules?")
    print("=" * 70)
    attacker_ip = "203.0.113.99"
    events = [
        {"ip": attacker_ip, "user": "victim", "status": "SUCCESS",
         "timestamp": "2026-01-01 09:00:00", "country": "XX", "device_type": "bot"},
    ]
    for i in range(6):
        events.append({"ip": attacker_ip, "user": "admin", "status": "FAILED",
                       "timestamp": f"2026-01-01 09:0{i+1}:00",
                       "country": "XX", "device_type": "bot"})

    stub = StubMLScorer(flag_ip=attacker_ip)

    flagged_buggy, counts_buggy = run_pass(events, stub, separate_ml_blocking=False)
    print(f"\nOriginal behaviour (separate_ml_blocking=False):")
    print(f"   Alert types: {counts_buggy}")
    print(f"   Fast Brute Force ever fired?: {'Brute Force Attack' in counts_buggy}")

    flagged_fixed, counts_fixed = run_pass(events, stub, separate_ml_blocking=True)
    print(f"\nFixed behaviour (separate_ml_blocking=True):")
    print(f"   Alert types: {counts_fixed}")
    print(f"   Fast Brute Force ever fired?: {'Brute Force Attack' in counts_fixed}")

    assert "Brute Force Attack" not in counts_buggy, (
        "Expected the ORIGINAL behaviour to suppress Fast Brute Force here, "
        "since the SUCCESS event should have blocked the IP and silenced "
        "the six FAILED events that follow. If this assertion fails, the "
        "reproduction of Batch 3's bug is not faithful.")
    assert "Brute Force Attack" in counts_fixed, (
        "Expected the FIXED behaviour to let Fast Brute Force fire normally "
        "on the six FAILED events, since ML blocking a SUCCESS event should "
        "no longer silence rule-based counting for that IP. The fix did not "
        "work as intended.")
    print("\nPASS: the fix mechanism behaves exactly as intended, confirmed "
          "before running against real data.\n")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unit_test_fix_mechanism()

    print("Starting Batch 3.5: testing the fix against real data...\n")
    overall_start = datetime.now()

    normal_df, attack_df = stream_dataset()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("\nFitting the settled Isolation Forest (contamination=0.4)...")
    X_train = extract_matrix(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    iso_model = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                                 random_state=SEED_BASE, n_jobs=-1, max_samples=100000,
                                 max_features=1.0)
    iso_model.fit(X_train_scaled)

    print("\nBuilding timestamp-ordered event stream...")
    test_events, test_true = build_event_stream(test_df)
    print(f"   Test events: {len(test_events):,}  (attacks: {test_true.sum():,})")

    results = {}

    print("\n--- Rules-only (sanity check: should match Batch 3 exactly) ---")
    flagged, counts = run_pass(test_events, None, separate_ml_blocking=True)
    results["rules_only"] = compute_metrics(flagged, test_true)
    results["rules_only"]["alert_type_counts"] = counts
    print(f"   {results['rules_only']}")

    print("\n--- Hybrid, ORIGINAL behaviour (Batch 3's bug, recomputed here) ---")
    ml_scorer_a = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps,
                                              known_ips_set, known_countries_set)
    flagged_a, counts_a = run_pass(test_events, ml_scorer_a, separate_ml_blocking=False)
    results["hybrid_original"] = compute_metrics(flagged_a, test_true)
    results["hybrid_original"]["alert_type_counts"] = counts_a
    print(f"   {results['hybrid_original']}")

    print("\n--- Hybrid, FIXED behaviour ---")
    ml_scorer_b = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps,
                                              known_ips_set, known_countries_set)
    flagged_b, counts_b = run_pass(test_events, ml_scorer_b, separate_ml_blocking=True)
    results["hybrid_fixed"] = compute_metrics(flagged_b, test_true)
    results["hybrid_fixed"]["alert_type_counts"] = counts_b
    print(f"   {results['hybrid_fixed']}")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_5_hybrid_fix_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"   {'arm':<20}{'precision':<12}{'recall':<12}{'f1':<12}{'fpr':<12}{'alerts/1000':<12}")
    for name, m in results.items():
        print(f"   {name:<20}{m['precision']:<12.4f}{m['recall']:<12.4f}"
              f"{m['f1']:<12.4f}{m['fpr']:<12.4f}{m['alerts_per_1000_events']:<12.2f}")

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print(f"Saved -> {out_path}")
    print("Send this file back, plus the printed unit-test result and summary table.")
