# backend/ml/evaluate_hybrid_campaign_and_cooldown.py
"""
Batch 3.6 - two additions on top of Batch 3.5's fix.

ADDITION 1: CAMPAIGN-LEVEL RECALL
====================================
Every metric so far has been event-level: out of every individual login
event, how many got correctly flagged. That may be the wrong lens for
comparing hybrid against ML-only. A single attacking IP in this dataset
generates on average about 9-10 events (7,251 unique attacking IPs
across 70,000 positive rows). ML-only independently re-flags every one
of those events with no memory between them. Hybrid deliberately alerts
once per IP for FAILED events (the ml_alerted_ips throttle) precisely
to avoid re-announcing the same ongoing campaign 9 times. If the point
of an alert is "tell a human about this campaign," event-level recall
undercounts hybrid unfairly, campaign_level_recall() below instead asks:
of every distinct attacking IP in the test set, how many were flagged
by at least one event. This is computed for every arm in this script,
including a fresh rerun of rules-only, ML-only, and hybrid-fixed
(Batch 3.5's permanent-throttle version), since campaign-level tracking
needs the per-event flag array, which the earlier batches did not save.

ADDITION 2: COOLDOWN INSTEAD OF A PERMANENT THROTTLE
=======================================================
ml_alerted_ips currently means "this IP gets exactly one ML alert on a
FAILED event, ever, for the rest of the replay," no matter how long the
campaign continues afterward. The Suspicious Login Time rule already
uses a different, arguably better pattern elsewhere in this same
codebase: a 600-second cooldown, alert, then allow re-alerting once
enough time has passed rather than never again. This script tests
replacing the permanent ML throttle with the same kind of cooldown,
swept across several candidate windows on VALIDATION ONLY, then
evaluated exactly once on the untouched TEST set at whichever candidate
wins, same discipline as every batch before this one. A cooldown of 0
(always allowed to re-alert) and effectively-infinite (Batch 3.5's
original permanent-throttle behaviour) are both included in the sweep
as the two extremes bounding the search.

Selection is still done by event-level F1, consistent with every prior
batch's tuning criterion, not by campaign-level recall, to avoid
quietly changing what "best" means partway through this project.
Campaign-level recall is reported at every candidate for full
transparency, so if F1's chosen candidate and the best campaign-level
candidate disagree, that disagreement is visible rather than hidden.

HOW TO RUN
==========
Save in backend/ml/, alongside the other six scripts (it imports from
evaluate_hybrid_and_baselines.py and evaluate_hybrid_fix.py, both must
be in the same folder). From backend/:

    python ml/evaluate_hybrid_campaign_and_cooldown.py

Expect roughly 25-35 minutes: streaming and splitting happen once, the
model fits once, then eleven replay passes run in total (three baseline
reruns for campaign tracking, seven cooldown candidates on validation,
one final evaluation on test).

Writes backend/results/batch3_6_campaign_and_cooldown_results.json.
Send it back, plus the printed comparison tables, for the paper rewrite.
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

# None means the original, permanent, alert-once-ever throttle (Batch 3.5's
# hybrid_fixed exactly). 0 means always allowed to re-alert, no throttle at
# all. The rest are candidate cooldown windows, in seconds.
COOLDOWN_GRID_SECONDS = [0, 300, 600, 1800, 3600, 7200, None]


class ReplayDetectorV3:
    """
    Same fix as ReplayDetectorV2 in evaluate_hybrid_fix.py (rule_blocked_ips
    and ml_blocked_ips kept separate, so ML never silences rule counting),
    always applied here, that part is settled. What's new is
    ml_cooldown_seconds: replaces the permanent ml_alerted_ips throttle
    with a re-alert-after-cooldown policy. None reproduces the original
    permanent throttle exactly.
    """

    def __init__(self, threshold=5, anomaly_detector=None, ml_cooldown_seconds=None):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.rule_blocked_ips = set()
        self.ml_blocked_ips = set()
        self.ml_cooldown_seconds = ml_cooldown_seconds
        self.ml_last_alerted = {}
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.anomaly_detector = anomaly_detector
        self.ip_users_tried = defaultdict(set)
        self.internal_ip_prefixes = ("192.168.", "10.0.", "172.16.")
        self.suspicious_last_fired = {}
        self.alert_type_counts = defaultdict(int)

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

    def _ml_failed_event_gated(self, ip, timestamp):
        """True if this FAILED-event ML alert should be suppressed."""
        last = self.ml_last_alerted.get(ip)
        if last is None:
            return False
        if self.ml_cooldown_seconds is None:
            return True  # permanent throttle: already alerted once, ever
        return (timestamp - last).total_seconds() < self.ml_cooldown_seconds

    def analyze_event(self, log_event):
        ip = log_event["ip"]
        user = log_event["user"]
        timestamp = datetime.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour = timestamp.hour

        self.ip_users_tried[ip].add(user)

        if log_event["status"] == "SUCCESS" and 0 <= hour <= 5:
            last_fired = self.suspicious_last_fired.get(ip)
            if last_fired is None or (timestamp - last_fired).total_seconds() > 600:
                self.suspicious_last_fired[ip] = timestamp
                self.alert_type_counts["Suspicious Login Time"] += 1
                return "Suspicious Login Time"

        if log_event["status"] == "SUCCESS":
            prev = self.user_last_login.get(user)
            self.user_last_login[user] = (ip, timestamp)
            if prev is not None:
                last_ip, last_time = prev
                time_diff = abs((timestamp - last_time).total_seconds())
                if ip != last_ip and time_diff < 120:
                    self.alert_type_counts["Multiple IP Login"] += 1
                    return "Multiple IP Login"

        if log_event["status"] == "FAILED":
            if ip in self.rule_blocked_ips:
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

        if self.anomaly_detector:
            is_internal = ip.startswith(self.internal_ip_prefixes)
            if not is_internal:
                result = self.anomaly_detector.score_event(log_event)
                if result and result["is_anomaly"]:
                    is_failed_event = log_event.get("status") == "FAILED"
                    if is_failed_event:
                        if self._ml_failed_event_gated(ip, timestamp):
                            return None
                        self.ml_last_alerted[ip] = timestamp
                    else:
                        if ip in self.rule_blocked_ips or ip in self.ml_blocked_ips:
                            return None
                        self.ml_blocked_ips.add(ip)
                    self.alert_type_counts["ML Anomaly Detected"] += 1
                    return "ML Anomaly Detected"

        return None


def run_pass(events, anomaly_detector, ml_cooldown_seconds=None):
    detector = ReplayDetectorV3(threshold=DEFAULT_THRESHOLD, anomaly_detector=anomaly_detector,
                                 ml_cooldown_seconds=ml_cooldown_seconds)
    flagged = [detector.analyze_event(e) is not None for e in events]
    return flagged, dict(detector.alert_type_counts)


def run_ml_only(events, ml_scorer):
    return [ml_scorer.score_event(e)["is_anomaly"] for e in events]


def campaign_level_recall(events, flagged, true_attack):
    """Of every distinct attacking IP present, what fraction were flagged
    by at least one of their events. Returns (rate, n_ips_seen, n_ips_caught)."""
    seen, caught = set(), set()
    for e, f, t in zip(events, flagged, true_attack):
        if t:
            seen.add(e["ip"])
            if f:
                caught.add(e["ip"])
    rate = len(caught) / len(seen) if seen else 0.0
    return round(rate, 4), len(seen), len(caught)


def full_report(name, events, flagged, true_attack):
    metrics = compute_metrics(flagged, true_attack)
    camp_rate, n_seen, n_caught = campaign_level_recall(events, flagged, true_attack)
    metrics["campaign_level_recall"] = camp_rate
    metrics["campaign_ips_seen"] = n_seen
    metrics["campaign_ips_caught"] = n_caught
    print(f"   {name}: event-recall={metrics['recall']:.4f}  "
          f"campaign-recall={camp_rate:.4f} ({n_caught}/{n_seen} IPs)  "
          f"F1={metrics['f1']:.4f}  alerts/1000={metrics['alerts_per_1000_events']:.2f}")
    return metrics


if __name__ == "__main__":
    print("\nStarting Batch 3.6: campaign-level recall and cooldown tuning...\n")
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

    print("\nBuilding timestamp-ordered event streams...")
    test_events, test_true = build_event_stream(test_df)
    val_events, val_true = build_event_stream(val_df)
    print(f"   Test events: {len(test_events):,}  (attacks: {test_true.sum():,})")

    results = {}

    print("\n=== Campaign-level recall for the three arms already known (rerun for per-event tracking) ===")
    flagged_rules, _ = run_pass(test_events, None)
    results["rules_only"] = full_report("rules-only", test_events, flagged_rules, test_true)

    ml_scorer_only = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps, known_ips_set, known_countries_set)
    flagged_ml = run_ml_only(test_events, ml_scorer_only)
    results["ml_only"] = full_report("ML-only", test_events, flagged_ml, test_true)

    ml_scorer_hybrid = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps, known_ips_set, known_countries_set)
    flagged_hybrid_permanent, _ = run_pass(test_events, ml_scorer_hybrid, ml_cooldown_seconds=None)
    results["hybrid_fixed_permanent_throttle"] = full_report(
        "hybrid (Batch 3.5, permanent throttle)", test_events, flagged_hybrid_permanent, test_true)

    print("\n=== Tuning ML re-alert cooldown on VALIDATION only ===")
    tuning_results = []
    for cooldown in COOLDOWN_GRID_SECONDS:
        ml_scorer_val = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps, known_ips_set, known_countries_set)
        flagged_val, _ = run_pass(val_events, ml_scorer_val, ml_cooldown_seconds=cooldown)
        m = full_report(f"cooldown={cooldown}", val_events, flagged_val, val_true)
        m["cooldown_seconds"] = cooldown
        tuning_results.append(m)

    best = max(tuning_results, key=lambda r: r["f1"])
    best_cooldown = best["cooldown_seconds"]
    print(f"\n   Best on validation by event-level F1: cooldown={best_cooldown} "
          f"(F1={best['f1']:.4f}, campaign-recall={best['campaign_level_recall']:.4f})")
    best_by_campaign = max(tuning_results, key=lambda r: r["campaign_level_recall"])
    if best_by_campaign["cooldown_seconds"] != best_cooldown:
        print(f"   NOTE: best by campaign-level recall alone would have been "
              f"cooldown={best_by_campaign['cooldown_seconds']} "
              f"(campaign-recall={best_by_campaign['campaign_level_recall']:.4f}, "
              f"F1={best_by_campaign['f1']:.4f}). Proceeding with the F1-selected "
              f"candidate for consistency with every prior batch's tuning criterion.")

    print(f"\n=== Evaluating cooldown={best_cooldown} ONCE on the untouched TEST set ===")
    ml_scorer_final = StreamingFrequencyMLScorer(iso_model, scaler, freq_maps, known_ips_set, known_countries_set)
    flagged_final, counts_final = run_pass(test_events, ml_scorer_final, ml_cooldown_seconds=best_cooldown)
    results["hybrid_cooldown_tuned"] = full_report(
        f"hybrid (cooldown={best_cooldown}, tuned on validation)", test_events, flagged_final, test_true)
    results["hybrid_cooldown_tuned"]["alert_type_counts"] = counts_final
    results["hybrid_cooldown_tuned"]["chosen_cooldown_seconds"] = best_cooldown
    results["cooldown_tuning_grid"] = tuning_results

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_6_campaign_and_cooldown_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 90)
    print("  FINAL COMPARISON")
    print("=" * 90)
    print(f"   {'arm':<38}{'event-recall':<14}{'campaign-recall':<17}{'f1':<10}{'alerts/1000':<12}")
    for name in ["rules_only", "ml_only", "hybrid_fixed_permanent_throttle", "hybrid_cooldown_tuned"]:
        m = results[name]
        print(f"   {name:<38}{m['recall']:<14.4f}{m['campaign_level_recall']:<17.4f}"
              f"{m['f1']:<10.4f}{m['alerts_per_1000_events']:<12.2f}")

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print(f"Saved -> {out_path}")
    print("Send this file back, plus the printed tables above, for the paper rewrite.")
