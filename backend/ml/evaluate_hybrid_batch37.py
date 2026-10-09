# backend/ml/evaluate_hybrid_batch37.py
"""
Batch 3.7: fixes a state bug in the hybrid replay, makes replays fast, and
maps the trade-off between catching attacks and raising false alarms.

WHY THIS BATCH EXISTS
======================
Batch 3.6 found that hybrid catches fewer distinct attacking IPs (2,797)
than ML-only alone (3,171), even though hybrid contains the same ML
detector plus rules. A pipeline that runs both should not do worse than
one of its parts at finding campaigns.

The hypothesis (not verified until this batch runs): in hybrid, the ML
scorer is only called for events that reach step 6 of analyze_event(). Rules
claim some events first, and block checks skip others. The scorer keeps a
running per-IP failure counter (the failed_rate feature) that it updates
inside score_event(), so in hybrid that counter misses every event that
never reached the scorer. The model was trained and evaluated with a
failed_rate that counts every event from the IP, so hybrid feeds it a
different feature than it learned on. This is the same class of bug as
Decision 13 in the thesis (a counter that is not updated on every path).

THE FIX TESTED HERE
====================
ML state is updated on every event, whatever the rules do. Rules still
decide what gets alerted and in what order, but the ML feature values no
longer depend on the hybrid logic. Because they no longer depend on it,
every event's ML anomaly score can be computed once, in one vectorized
pass, and the hybrid replay just looks the flag up. That is also why this
script should run in minutes: Batch 3.6 needed 178 minutes because it
called the sklearn model once per event, roughly 104,000 single-row calls
per replay.

Batch scoring is only valid if it matches the streaming scorer, so the
script checks that (see EQUIVALENCE CHECKS below) before trusting it.

WHAT THIS SCRIPT PRODUCES
==========================
1. Settled-configuration comparison on the untouched test set: rules-only,
   ML-only, the fixed hybrid, and a "parallel union" (rules and ML run
   independently and OR-ed, with no gating), which is the coverage a
   hybrid should be able to reach.
2. Campaign metrics beyond campaign recall: how many attack events happen
   before the first alert on an IP, and what share of attack events fall
   AFTER the first alert. The second number is what a blocking response
   could in principle prevent. It assumes blocks are enforced, which this
   prototype only simulates, so treat it as an upper bound, not a result.
3. An operating-point frontier. IsolationForest's contamination setting
   only moves the decision threshold, not the trees, so the script fits
   once and derives every threshold from the training-score percentile
   (the same rule sklearn uses internally, verified below). For each
   setting it reports event recall, campaign recall, F1, false-positive
   rate, and false alerts per 1,000 real-world logins at 1% attack
   prevalence.
4. Three pre-declared operating policies, chosen on VALIDATION only:
   A) highest event F1, B) highest campaign recall with validation
   FPR <= 10%, C) highest campaign recall with validation FPR <= 20%.
   The test frontier is printed for every setting so you can see whether
   validation predicted it, but the policies are the only settings meant
   to be reported as choices.

EQUIVALENCE CHECKS (printed and saved, not asserted)
=======================================================
  a) Vectorized flags at contamination 0.4 vs iso_model.predict on test.
  b) ML-only test TP/FP vs Batch 3 (27,258 / 23,686).
  c) Rules-only test TP/FP vs Batch 3 (2,857 / 3,786).
If any of these do not match, do not trust the rest of the output. Send
the printout back and we will find out why before anything is written up.

HOW TO RUN
==========
Save in backend/ml/ next to the other scripts. From backend/:

    python ml/evaluate_hybrid_batch37.py

Expect roughly 10-20 minutes, mostly streaming the CSV and scoring the
561k training rows once. Writes backend/results/batch3_7_results.json.
Send that file back or paste the printed tables.
"""

import os
import sys
import json
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import (
    stream_dataset, user_disjoint_split, parse_bool_col, RESULTS_DIR, SEED_BASE,
)
from train_from_dataset_v3 import fit_frequency_maps
from evaluate_hybrid_and_baselines import (
    compute_metrics, extract_matrix, SETTLED_CONTAMINATION, DEFAULT_THRESHOLD,
)

TS_FMT = "%Y-%m-%d %H:%M:%S"
SWEEP_GRID = [0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
FPR_BUDGETS = [0.10, 0.20]

# Numbers printed by the earlier batches, used only for comparison lines.
BATCH3_ML_ONLY = {"TP": 27258, "FP": 23686}
BATCH3_RULES_ONLY = {"TP": 2857, "FP": 3786}
BATCH36_HYBRID = {"event_recall": 0.2418, "campaign_recall": 0.5156, "f1": 0.2795,
                  "alerts_per_1000": 245.02, "campaign_ips_caught": 2797}
BATCH36_ML_ONLY_CAMPAIGN_IPS = 3171


# ── Data preparation ─────────────────────────────────────────────────────────

def sort_stream_df(df):
    """Stable sort by time. A stable sort keeps tied timestamps in a fixed
    order, so events and feature rows stay aligned row for row."""
    return df.sort_values("Login Timestamp", kind="mergesort").reset_index(drop=True)


def events_from_sorted_df(df_sorted):
    """Same event dicts as build_event_stream(), built from an already sorted
    frame so nothing gets re-sorted, plus 'ts' (a parsed datetime, taken from
    the same string the rule code would parse, so rule results match)."""
    ips = df_sorted["IP Address"].astype(str).tolist()
    users = df_sorted["User ID"].astype(str).tolist()
    stamps = df_sorted["Login Timestamp"].tolist()
    ok = (df_sorted["Login Successful"].astype(str).str.strip().str.lower()
          .isin(["true", "1", "yes"]).tolist())
    countries = df_sorted["Country"].fillna("XX").astype(str).tolist()
    devices = df_sorted["Device Type"].fillna("Unknown").astype(str).tolist()

    events = []
    for ip, user, stamp, success, country, device in zip(ips, users, stamps, ok,
                                                           countries, devices):
        ts_str = stamp.strftime(TS_FMT)
        events.append({
            "ip": ip, "user": user, "timestamp": ts_str,
            "ts": datetime.strptime(ts_str, TS_FMT),
            "status": "SUCCESS" if success else "FAILED",
            "country": country, "device_type": device,
        })
    true_attack = (
        df_sorted["Is Attack IP"].astype(str).str.strip().str.lower().isin(["true", "1", "yes"]) |
        df_sorted["Is Account Takeover"].astype(str).str.strip().str.lower().isin(["true", "1", "yes"])
    ).values
    return events, true_attack


def features_presorted(df_sorted, freq_maps, known_ips_set, known_countries_set):
    """Same 10 features, same order, as extract_features_freq(), for a frame
    that is ALREADY sorted by time. failed_rate is the inclusive per-IP
    cumulative failure rate over every event, which is exactly what the
    streaming scorer computes when it sees every event."""
    df = df_sorted.reset_index(drop=True)
    hour = pd.to_datetime(df["Login Timestamp"], errors="coerce").dt.hour.fillna(12)
    hour_sin = np.sin(2 * np.pi * hour / 24)
    hour_cos = np.cos(2 * np.pi * hour / 24)

    is_failed = (~parse_bool_col(df["Login Successful"])).astype(int)
    fail_cumsum = is_failed.groupby(df["IP Address"]).cumsum()
    total_cumsum = df.groupby("IP Address").cumcount() + 1
    failed_rate = fail_cumsum / total_cumsum

    ip_freq = df["IP Address"].astype(str).str.strip().map(freq_maps["ip"]).fillna(0.0)
    user_freq = df["User ID"].astype(str).str.strip().map(freq_maps["user"]).fillna(0.0)
    country_freq = (df["Country"].fillna("XX").astype(str).str.strip()
                    .map(freq_maps["country"]).fillna(0.0))
    device_freq = (df["Device Type"].fillna("Unknown").astype(str).str.strip()
                   .map(freq_maps["device"]).fillna(0.0))
    is_new_ip = (~df["IP Address"].astype(str).isin(known_ips_set)).astype(int)
    is_new_country = (~df["Country"].fillna("XX").astype(str).isin(known_countries_set)).astype(int)

    cols = [hour_sin, hour_cos, is_failed, ip_freq, user_freq, failed_rate,
            country_freq, device_freq, is_new_ip, is_new_country]
    return np.column_stack([c.to_numpy() for c in cols]).astype(float)


# ── Hybrid replay with precomputed ML flags ──────────────────────────────────

class ReplayDetectorV4:
    """Rule logic identical to ReplayDetectorV3 (Batch 3.6), with the fix from
    Batch 3.5 (rule_blocked_ips and ml_blocked_ips kept separate). The one
    change: the ML decision arrives as a precomputed flag per event instead of
    being computed inside the pipeline. ML state therefore updates on every
    event regardless of what the rules do."""

    def __init__(self, threshold=5, use_ml=False, ml_cooldown_seconds=0,
                 internal_ip_guard=True):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.rule_blocked_ips = set()
        self.ml_blocked_ips = set()
        self.use_ml = use_ml
        self.ml_cooldown_seconds = ml_cooldown_seconds
        self.internal_ip_guard = internal_ip_guard
        self.ml_last_alerted = {}
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.ip_users_tried = defaultdict(set)
        self.internal_ip_prefixes = ("192.168.", "10.0.", "172.16.")
        self.suspicious_last_fired = {}
        self.alert_type_counts = defaultdict(int)

    def _slow_brute_force_check(self, ip, timestamp):
        recent = [t for t in self.ip_attempt_times[ip]
                  if abs((timestamp - t).total_seconds()) <= 3600]
        unique_users = len(self.ip_users_tried[ip])
        spread = ((timestamp - recent[0]).total_seconds() / 60) if recent else 0
        if (len(recent) >= 4 and self.failed_attempts[ip] < self.threshold
                and spread >= 5 and unique_users < 3):
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
        last = self.ml_last_alerted.get(ip)
        if last is None:
            return False
        if self.ml_cooldown_seconds is None:
            return True
        return (timestamp - last).total_seconds() < self.ml_cooldown_seconds

    def analyze_event(self, ev, ml_flag=False):
        ip, user, timestamp = ev["ip"], ev["user"], ev["ts"]
        self.ip_users_tried[ip].add(user)

        if ev["status"] == "SUCCESS" and 0 <= timestamp.hour <= 5:
            last = self.suspicious_last_fired.get(ip)
            if last is None or (timestamp - last).total_seconds() > 600:
                self.suspicious_last_fired[ip] = timestamp
                self.alert_type_counts["Suspicious Login Time"] += 1
                return "Suspicious Login Time"

        if ev["status"] == "SUCCESS":
            prev = self.user_last_login.get(user)
            self.user_last_login[user] = (ip, timestamp)
            if prev is not None:
                last_ip, last_time = prev
                if ip != last_ip and abs((timestamp - last_time).total_seconds()) < 120:
                    self.alert_type_counts["Multiple IP Login"] += 1
                    return "Multiple IP Login"

        if ev["status"] == "FAILED":
            if ip in self.rule_blocked_ips:
                return None
            self.ip_attempt_times[ip].append(timestamp)
            self.failed_attempts[ip] += 1
            unique_users = len(self.ip_users_tried[ip])

            for result in (self._slow_brute_force_check(ip, timestamp),):
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

        if self.use_ml and ml_flag:
            internal = self.internal_ip_guard and ip.startswith(self.internal_ip_prefixes)
            if not internal:
                if ev["status"] == "FAILED":
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


def run_hybrid(events, ml_flags, cooldown=0, internal_ip_guard=True):
    """ml_flags=None runs the rules alone."""
    det = ReplayDetectorV4(threshold=DEFAULT_THRESHOLD, use_ml=ml_flags is not None,
                           ml_cooldown_seconds=cooldown, internal_ip_guard=internal_ip_guard)
    if ml_flags is None:
        flagged = [det.analyze_event(e) is not None for e in events]
    else:
        flagged = [det.analyze_event(e, bool(m)) is not None for e, m in zip(events, ml_flags)]
    return flagged, dict(det.alert_type_counts)


# ── Metrics ───────────────────────────────────────────────────────────────────

def campaign_metrics(events, flagged, true_attack):
    """Per attacking IP, over its attack events in time order: was any event
    flagged, how many attack events came before the first flag, and how many
    came after it. 'After' counts events a working block could have stopped."""
    per_ip = defaultdict(list)
    for e, f, t in zip(events, flagged, true_attack):
        if t:
            per_ip[e["ip"]].append(bool(f))
    seen, caught, total_events, after_events, before = len(per_ip), 0, 0, 0, []
    for seq in per_ip.values():
        total_events += len(seq)
        if any(seq):
            caught += 1
            k = seq.index(True)
            before.append(k)
            after_events += len(seq) - k - 1
    return {
        "campaign_level_recall": round(caught / seen, 4) if seen else 0.0,
        "campaign_ips_seen": seen,
        "campaign_ips_caught": caught,
        "median_attack_events_before_first_alert": float(np.median(before)) if before else None,
        "share_attack_events_after_first_alert":
            round(after_events / total_events, 4) if total_events else 0.0,
    }


def precision_at_prevalence(tpr, fpr, prevalence):
    denom = prevalence * tpr + (1 - prevalence) * fpr
    return round(prevalence * tpr / denom, 4) if denom > 0 else 0.0


def summarize(events, flagged, true_attack):
    m = compute_metrics(flagged, true_attack)
    m.update(campaign_metrics(events, flagged, true_attack))
    m["precision_at_5pct_prevalence"] = precision_at_prevalence(m["recall"], m["fpr"], 0.05)
    m["precision_at_1pct_prevalence"] = precision_at_prevalence(m["recall"], m["fpr"], 0.01)
    m["false_alerts_per_1000_logins_at_1pct_prevalence"] = round(m["fpr"] * 990, 1)
    return m


# ── Sweep over operating points ──────────────────────────────────────────────

def sweep(scores, train_scores, events, true_attack, grid):
    rows = []
    for c in grid:
        threshold = np.percentile(train_scores, 100.0 * c)
        ml_flags = scores < threshold
        flagged, _ = run_hybrid(events, ml_flags, cooldown=0)
        row = summarize(events, flagged, true_attack)
        row["contamination"] = c
        ml_only = summarize(events, ml_flags, true_attack)
        row["ml_only_f1"] = ml_only["f1"]
        row["ml_only_campaign_recall"] = ml_only["campaign_level_recall"]
        rows.append(row)
    return rows


def print_frontier(title, rows):
    print(f"\n   {title}")
    print(f"   {'contam':<8}{'evt-recall':<12}{'camp-recall':<13}{'F1':<8}{'FPR':<8}"
          f"{'false alerts/1000 logins @1%':<30}{'share after 1st alert':<22}")
    for r in rows:
        print(f"   {r['contamination']:<8}{r['recall']:<12.4f}{r['campaign_level_recall']:<13.4f}"
              f"{r['f1']:<8.4f}{r['fpr']:<8.4f}"
              f"{r['false_alerts_per_1000_logins_at_1pct_prevalence']:<30}"
              f"{r['share_attack_events_after_first_alert']:<22.4f}")


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


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nStarting Batch 3.7...\n")
    started = datetime.now()

    normal_df, attack_df = stream_dataset()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("\nFitting the settled Isolation Forest (contamination=0.4) once...")
    X_train = extract_matrix(train_df, freq_maps, known_ips_set, known_countries_set)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    iso = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200,
                          random_state=SEED_BASE, n_jobs=-1, max_samples=100000,
                          max_features=1.0)
    iso.fit(X_train_scaled)

    print("Scoring the training rows once (the percentile source for every threshold)...")
    train_scores = iso.score_samples(X_train_scaled)

    print("Sorting val/test by time and scoring every event in one vectorized pass...")
    val_sorted, test_sorted = sort_stream_df(val_df), sort_stream_df(test_df)
    val_events, val_true = events_from_sorted_df(val_sorted)
    test_events, test_true = events_from_sorted_df(test_sorted)
    X_val_scaled = scaler.transform(features_presorted(val_sorted, freq_maps, known_ips_set, known_countries_set))
    X_test_scaled = scaler.transform(features_presorted(test_sorted, freq_maps, known_ips_set, known_countries_set))
    val_scores = iso.score_samples(X_val_scaled)
    test_scores = iso.score_samples(X_test_scaled)
    print(f"   Test events: {len(test_events):,} (attacks: {int(test_true.sum()):,})")

    results = {}
    checks = {}

    # ── Equivalence checks ───────────────────────────────────────────────────
    settled_threshold = np.percentile(train_scores, 100.0 * SETTLED_CONTAMINATION)
    vec_flags = test_scores < settled_threshold
    predict_flags = iso.predict(X_test_scaled) == -1
    checks["vectorized_vs_predict_mismatches"] = int((vec_flags != predict_flags).sum())
    checks["offset_vs_percentile_abs_diff"] = float(abs(iso.offset_ - settled_threshold))

    ml_only = summarize(test_events, vec_flags, test_true)
    rules_flags, rules_counts = run_hybrid(test_events, None)
    rules_only = summarize(test_events, rules_flags, test_true)
    checks["ml_only_matches_batch3"] = (ml_only["TP"], ml_only["FP"]) == (
        BATCH3_ML_ONLY["TP"], BATCH3_ML_ONLY["FP"])
    checks["rules_only_matches_batch3"] = (rules_only["TP"], rules_only["FP"]) == (
        BATCH3_RULES_ONLY["TP"], BATCH3_RULES_ONLY["FP"])

    print("\n" + "=" * 78)
    print("  EQUIVALENCE CHECKS (if any of these fail, do not trust what follows)")
    print("=" * 78)
    print(f"   Vectorized flags vs iso.predict, mismatches: {checks['vectorized_vs_predict_mismatches']} (want 0)")
    print(f"   |iso.offset_ - percentile threshold|: {checks['offset_vs_percentile_abs_diff']:.3e} (want ~0)")
    print(f"   ML-only TP/FP {ml_only['TP']}/{ml_only['FP']} vs Batch 3 "
          f"{BATCH3_ML_ONLY['TP']}/{BATCH3_ML_ONLY['FP']}: "
          f"{'MATCH' if checks['ml_only_matches_batch3'] else 'DIFFERENT'}")
    print(f"   Rules-only TP/FP {rules_only['TP']}/{rules_only['FP']} vs Batch 3 "
          f"{BATCH3_RULES_ONLY['TP']}/{BATCH3_RULES_ONLY['FP']}: "
          f"{'MATCH' if checks['rules_only_matches_batch3'] else 'DIFFERENT'}")

    # ── Settled-configuration comparison on test ────────────────────────────
    hybrid_flags, hybrid_counts = run_hybrid(test_events, vec_flags, cooldown=0)
    hybrid = summarize(test_events, hybrid_flags, test_true)
    hybrid["alert_type_counts"] = hybrid_counts
    union_flags = np.asarray(rules_flags, dtype=bool) | vec_flags
    union = summarize(test_events, union_flags, test_true)

    results["rules_only"] = rules_only
    results["ml_only"] = ml_only
    results["hybrid_ml_state_fixed"] = hybrid
    results["parallel_union_no_gating"] = union

    print("\n" + "=" * 78)
    print("  SETTLED CONFIGURATION ON THE TEST SET (contamination=0.4, cooldown=0)")
    print("=" * 78)
    print(f"   {'arm':<28}{'evt-recall':<12}{'camp-recall':<13}{'F1':<8}{'FPR':<8}"
          f"{'alerts/1000':<13}{'IPs caught':<12}{'share after 1st alert':<22}")
    for name in ["rules_only", "ml_only", "hybrid_ml_state_fixed", "parallel_union_no_gating"]:
        r = results[name]
        print(f"   {name:<28}{r['recall']:<12.4f}{r['campaign_level_recall']:<13.4f}{r['f1']:<8.4f}"
              f"{r['fpr']:<8.4f}{r['alerts_per_1000_events']:<13.2f}"
              f"{r['campaign_ips_caught']:<12}{r['share_attack_events_after_first_alert']:<22.4f}")
    print(f"\n   For comparison, Batch 3.6 hybrid (ML state only updated on events that "
          f"reached the scorer): event recall {BATCH36_HYBRID['event_recall']}, "
          f"{BATCH36_HYBRID['campaign_ips_caught']} IPs caught, F1 {BATCH36_HYBRID['f1']}, "
          f"alerts/1000 {BATCH36_HYBRID['alerts_per_1000']}.")
    print(f"   Batch 3.6 ML-only caught {BATCH36_ML_ONLY_CAMPAIGN_IPS} IPs; this run's ML-only "
          f"caught {ml_only['campaign_ips_caught']}.")

    # ── Diagnostics on the campaign gap ─────────────────────────────────────
    internal = ("192.168.", "10.0.", "172.16.")
    attack_ips = {e["ip"] for e, t in zip(test_events, test_true) if t}
    ml_caught = {e["ip"] for e, f, t in zip(test_events, vec_flags, test_true) if t and f}
    hyb_caught = {e["ip"] for e, f, t in zip(test_events, hybrid_flags, test_true) if t and f}
    missing = ml_caught - hyb_caught
    internal_attack_ips = {ip for ip in attack_ips if ip.startswith(internal)}
    diag = {
        "attacking_ips_in_test": len(attack_ips),
        "attacking_ips_with_internal_prefix": len(internal_attack_ips),
        "ips_caught_by_ml_only_but_not_hybrid": len(missing),
        "of_those_with_internal_prefix": len(missing & internal_attack_ips),
    }
    results["diagnostics"] = diag
    print("\n   Diagnostics on the ML-only vs hybrid campaign gap:")
    for k, v in diag.items():
        print(f"      {k}: {v}")

    # ── Frontier and policies ────────────────────────────────────────────────
    print("\nSweeping operating points (hybrid, ML state fixed, cooldown=0)...")
    val_rows = sweep(val_scores, train_scores, val_events, val_true, SWEEP_GRID)
    test_rows = sweep(test_scores, train_scores, test_events, test_true, SWEEP_GRID)
    policies = choose_policies(val_rows)
    results["frontier_validation"] = val_rows
    results["frontier_test"] = test_rows
    results["policies_chosen_on_validation"] = policies

    print("\n" + "=" * 78)
    print("  OPERATING-POINT FRONTIER")
    print("=" * 78)
    print_frontier("VALIDATION (this is where policies are chosen)", val_rows)
    print_frontier("TEST (descriptive; shows whether validation predicted it)", test_rows)

    print("\n" + "=" * 78)
    print("  PRE-DECLARED POLICIES: chosen on validation, reported once on test")
    print("=" * 78)
    by_c_test = {r["contamination"]: r for r in test_rows}
    policy_results = {}
    for name, c in policies.items():
        if c is None:
            print(f"   {name}: no setting on the grid met the FPR budget on validation")
            continue
        t = by_c_test[c]
        policy_results[name] = {"contamination": c, "test": t}
        print(f"   {name}: contamination={c}  test event-recall={t['recall']:.4f}  "
              f"campaign-recall={t['campaign_level_recall']:.4f}  F1={t['f1']:.4f}  "
              f"FPR={t['fpr']:.4f}  false alerts per 1000 logins @1%={t['false_alerts_per_1000_logins_at_1pct_prevalence']}")
    results["policy_results_on_test"] = policy_results
    results["equivalence_checks"] = checks

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_path = os.path.join(RESULTS_DIR, "batch3_7_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2,
                  default=lambda o: o.item() if hasattr(o, "item") else str(o))

    elapsed = (datetime.now() - started).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print(f"Saved -> {out_path}")
    print("Send the file back, or paste the tables above.")
