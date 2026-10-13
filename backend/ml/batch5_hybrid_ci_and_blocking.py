# backend/ml/batch5_hybrid_ci_and_blocking.py
"""
Batch 5: reviewer report 2, item 3 (the hybrid's advantage rests on mixed units).

What it answers
  1. Confidence intervals on campaign recall and FPR for rules-only,
     Isolation-Forest-only and the hybrid:
       a) over 10 Isolation Forest seeds (42-51), each replayed in full;
       b) paired cluster bootstrap on the seed-42 run: attacking IPs are
          resampled for campaign recall, benign IPs for FPR.
  2. Campaign-level false positives: benign IPs and benign users flagged,
     benign IPs BLOCKED, and the benign logins an enforced block would have
     denied afterwards (the denial-of-service cost the reviewer asks for).
  3. Where the hybrid's lower FPR comes from: every benign event the
     Isolation Forest flags but the hybrid does not is attributed to
     "IP already blocked by a rule", "IP already blocked by the ML step" or
     "other"; rule alerts the Isolation Forest did not raise are counted
     separately. The same decomposition is done for attack events.
  4. Replay construction: the paper's test stream gives each attacking IP
     only part of its events (attacks are split row by row between
     validation and test). A sensitivity replay over validation + test
     combined gives every attacking IP all of its sampled events.

The settled configuration is unchanged: contamination 0.4 (40th percentile
of training scores), ML cooldown 0 s, internal-IP guard off, rule and ML
block sets kept separate (ReplayDetectorV4 from Batch 3.7, imported, not
copied).

Check before trusting anything: the seed-42 line must reproduce Table 2
(rules-only recall 0.082 / FPR 0.055; IF-only 0.779 / 0.342 / campaign
0.585; hybrid 0.284 / 0.266 / campaign 0.600). The script prints MATCH or
DIFFERENT for each.

HOW TO RUN (from backend/; reuses Batch 4's cached sample, no CSV read)
    python ml/batch5_hybrid_ci_and_blocking.py --quick    # smoke test, ~2-4 min
    python ml/batch5_hybrid_ci_and_blocking.py            # full run, ~15-30 min

Writes backend/data/batch5_results.json and backend/data/batch5_summary.txt.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv():
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
from train_from_dataset_v2 import RESULTS_DIR, SEED_BASE, stream_dataset, user_disjoint_split  # noqa: E402
from train_from_dataset_v3 import fit_frequency_maps, extract_features_freq  # noqa: E402
from evaluate_hybrid_and_baselines import compute_metrics, SETTLED_CONTAMINATION, DEFAULT_THRESHOLD  # noqa: E402
from evaluate_hybrid_batch37 import (ReplayDetectorV4, sort_stream_df,  # noqa: E402
                                     events_from_sorted_df, features_presorted)

CACHE_PATH = os.path.join(RESULTS_DIR, "rba_sample_cache.pkl")
TABLE2 = {  # published Table 2, used only for the reproduction check
    "rules_only": {"recall": 0.082, "fpr": 0.055, "campaign_recall": 0.283},
    "ml_only":    {"recall": 0.779, "fpr": 0.342, "campaign_recall": 0.585},
    "hybrid":     {"recall": 0.284, "fpr": 0.266, "campaign_recall": 0.600},
}


# ── Data ─────────────────────────────────────────────────────────────────────

def load_pools():
    if os.path.exists(CACHE_PATH):
        print(f"Loading cached sample pools from {CACHE_PATH}")
        return pd.read_pickle(CACHE_PATH)
    normal_df, attack_df = stream_dataset()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    pd.to_pickle((normal_df, attack_df), CACHE_PATH)
    return normal_df, attack_df


class Stream:
    """A time-sorted replay stream with everything precomputed once."""

    def __init__(self, df, freq_maps, known_ips, known_countries):
        self.df = sort_stream_df(df)
        self.events, self.true = events_from_sorted_df(self.df)
        self.true = np.asarray(self.true, bool)
        self.X = features_presorted(self.df, freq_maps, known_ips, known_countries)
        self.ips = np.array([e["ip"] for e in self.events], dtype=object)
        self.users = np.array([e["user"] for e in self.events], dtype=object)
        self.success = np.array([e["status"] == "SUCCESS" for e in self.events])
        attack_ips = set(self.ips[self.true])
        self.attack_ips = attack_ips
        self.mixed_ips = attack_ips & set(self.ips[~self.true])


# ── Replay with block bookkeeping ────────────────────────────────────────────

def replay(stream, ml_flags):
    """Runs the settled hybrid (or rules-only if ml_flags is None) and records,
    per event, whether it was flagged and why an ML-flagged event went silent."""
    det = ReplayDetectorV4(threshold=DEFAULT_THRESHOLD, use_ml=ml_flags is not None,
                           ml_cooldown_seconds=0, internal_ip_guard=False)
    n = len(stream.events)
    flagged = np.zeros(n, bool)
    silent_reason = np.zeros(n, np.int8)  # 1 rule block, 2 ML block, 3 other
    block_idx, block_by = {}, {}
    for i, e in enumerate(stream.events):
        ip = e["ip"]
        pre_rule, pre_ml = ip in det.rule_blocked_ips, ip in det.ml_blocked_ips
        m = bool(ml_flags[i]) if ml_flags is not None else False
        flagged[i] = det.analyze_event(e, m) is not None
        if ip not in block_idx:
            if ip in det.rule_blocked_ips:
                block_idx[ip], block_by[ip] = i, "rule"
            elif ip in det.ml_blocked_ips:
                block_idx[ip], block_by[ip] = i, "ml"
        if m and not flagged[i]:
            silent_reason[i] = 1 if pre_rule else (2 if pre_ml else 3)
    return {"flagged": flagged, "silent_reason": silent_reason,
            "block_idx": block_idx, "block_by": block_by}


def per_ip_caught(stream, flagged):
    caught = defaultdict(bool)
    for ip, f, t in zip(stream.ips, flagged, stream.true):
        if t:
            caught[ip] |= bool(f)
    ips = sorted(caught)
    return ips, np.array([caught[ip] for ip in ips])


def arm_metrics(stream, flagged):
    m = compute_metrics(flagged, stream.true)
    _, c = per_ip_caught(stream, flagged)
    m["campaign_recall"] = round(float(c.mean()), 4)
    m["campaign_ips_caught"] = int(c.sum())
    m["campaign_ips_seen"] = int(len(c))
    ben = ~stream.true
    ben_ips = set(stream.ips[ben]) - stream.attack_ips
    ben_users = set(stream.users[ben])
    m["benign_ips_flagged"] = len(set(stream.ips[ben & flagged]) - stream.attack_ips)
    m["benign_ips_total"] = len(ben_ips)
    m["benign_users_flagged"] = len(set(stream.users[ben & flagged]))
    m["benign_users_total"] = len(ben_users)
    return m


def blocking_harm(stream, rep):
    """Benign IPs blocked, and the benign logins an enforced block would deny."""
    ben = ~stream.true
    blocked_benign = {ip: i for ip, i in rep["block_idx"].items() if ip not in stream.attack_ips}
    by = defaultdict(int)
    for ip in blocked_benign:
        by[rep["block_by"][ip]] += 1
    idx = np.arange(len(stream.events))
    after = np.array([ip in blocked_benign and i > blocked_benign[ip]
                      for i, ip in zip(idx, stream.ips)])
    denied = after & ben
    trigger = np.array([ip in blocked_benign and i == blocked_benign[ip]
                        for i, ip in zip(idx, stream.ips)]) & ben
    users_after = set(stream.users[denied])
    users_trigger = set(stream.users[trigger & stream.success])
    n_ben_users = len(set(stream.users[ben]))
    return {
        "benign_ips_blocked": len(blocked_benign),
        "benign_ips_blocked_by": dict(by),
        "benign_ips_total": len(set(stream.ips[ben]) - stream.attack_ips),
        "benign_events_after_block": int(denied.sum()),
        "benign_successful_logins_after_block": int((denied & stream.success).sum()),
        "share_benign_events_after_block": round(float(denied.sum() / ben.sum()), 4),
        "benign_users_with_login_after_block": len(users_after),
        "benign_users_whose_success_triggered_a_block": len(users_trigger),
        "benign_users_affected_any": len(users_after | users_trigger),
        "benign_users_total": n_ben_users,
        "share_benign_users_affected": round(len(users_after | users_trigger) / n_ben_users, 4),
        "attack_ips_blocked": len([ip for ip in rep["block_idx"] if ip in stream.attack_ips]),
    }


def fpr_decomposition(stream, ml_flags, rep):
    """Benign (and attack) events: IF-only flags vs hybrid flags, attributed."""
    out = {}
    for name, mask in (("benign", ~stream.true), ("attack", stream.true)):
        ml = ml_flags & mask
        hy = rep["flagged"] & mask
        sr = rep["silent_reason"]
        d = {
            "if_only_flags": int(ml.sum()),
            "hybrid_flags": int(hy.sum()),
            "if_flag_silenced_ip_rule_blocked": int(((sr == 1) & mask).sum()),
            "if_flag_silenced_ip_ml_blocked": int(((sr == 2) & mask).sum()),
            "if_flag_silenced_other": int(((sr == 3) & mask).sum()),
            "rule_alerts_without_if_flag": int((hy & ~ml_flags).sum()),
        }
        d["check_identity_holds"] = (d["if_only_flags"] - d["if_flag_silenced_ip_rule_blocked"]
                                     - d["if_flag_silenced_ip_ml_blocked"] - d["if_flag_silenced_other"]
                                     + d["rule_alerts_without_if_flag"]) == d["hybrid_flags"]
        n = int(mask.sum())
        d["rate_points"] = {k: round(100 * v / n, 2) for k, v in d.items()
                            if isinstance(v, int) and not isinstance(v, bool)}
        out[name] = d
    return out


# ── Bootstrap ────────────────────────────────────────────────────────────────

def bootstrap(stream, flags_by_arm, reps, seed):
    rng = np.random.RandomState(seed)
    arms = list(flags_by_arm)
    # campaign recall: resample attacking IPs
    caught = {}
    for a in arms:
        ips, c = per_ip_caught(stream, flags_by_arm[a])
        caught[a] = c.astype(float)
    n_att = len(ips)
    # FPR: resample benign IPs (cluster bootstrap)
    ben = ~stream.true
    codes, uniq = pd.factorize(stream.ips[ben])
    n_events = np.bincount(codes)
    fp = {a: np.bincount(codes, weights=flags_by_arm[a][ben].astype(float), minlength=len(uniq))
          for a in arms}
    cr = {a: [] for a in arms}
    fr = {a: [] for a in arms}
    for _ in range(reps):
        w_att = np.bincount(rng.randint(0, n_att, n_att), minlength=n_att)
        w_ben = np.bincount(rng.randint(0, len(uniq), len(uniq)), minlength=len(uniq))
        tot = (w_ben * n_events).sum()
        for a in arms:
            cr[a].append((w_att * caught[a]).sum() / n_att)
            fr[a].append((w_ben * fp[a]).sum() / tot)
    cr = {a: np.array(v) for a, v in cr.items()}
    fr = {a: np.array(v) for a, v in fr.items()}

    def ci(x):
        return [round(float(np.percentile(x, 2.5)), 4), round(float(np.percentile(x, 97.5)), 4)]

    res = {"reps": reps, "campaign_recall_95ci": {a: ci(cr[a]) for a in arms},
           "fpr_95ci": {a: ci(fr[a]) for a in arms}}
    if "hybrid" in arms and "ml_only" in arms:
        dc, dfp = cr["hybrid"] - cr["ml_only"], fr["hybrid"] - fr["ml_only"]
        res["diff_hybrid_minus_ml"] = {
            "campaign_recall_95ci": ci(dc), "campaign_recall_share_reps_gt0": round(float((dc > 0).mean()), 4),
            "fpr_95ci": ci(dfp), "fpr_share_reps_lt0": round(float((dfp < 0).mean()), 4),
        }
    return res


# ── Stream statistics (replay construction) ──────────────────────────────────

def stream_stats(stream):
    att = stream.true
    df = pd.DataFrame({"ip": stream.ips[att], "failed": ~stream.success[att]})
    per_ip = df.groupby("ip").agg(events=("failed", "size"), failed=("failed", "sum"))
    return {
        "attack_events": int(att.sum()), "attacking_ips": int(len(per_ip)),
        "attack_events_per_ip_median": float(per_ip["events"].median()),
        "attack_events_per_ip_p90": float(per_ip["events"].quantile(0.9)),
        "share_attacking_ips_with_ge5_failed": round(float((per_ip["failed"] >= 5).mean()), 4),
        "share_attack_events_from_ips_with_ge5_failed":
            round(float(per_ip.loc[per_ip["failed"] >= 5, "events"].sum() / att.sum()), 4),
        "mixed_label_ips": len(stream.mixed_ips),
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def fit_if(X_train_scaled, seed):
    iso = IsolationForest(contamination=SETTLED_CONTAMINATION, n_estimators=200, random_state=seed,
                          n_jobs=-1, max_samples=min(100_000, len(X_train_scaled)), max_features=1.0)
    iso.fit(X_train_scaled)
    thr = np.percentile(iso.score_samples(X_train_scaled), 100.0 * SETTLED_CONTAMINATION)
    return iso, thr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--data", help="path to rba-dataset.csv (only needed if no cache)")
    args = ap.parse_args()
    q = args.quick
    data_path = args.data or os.environ.get("RBA_DATASET_PATH")
    if data_path:
        _v2.DATASET_PATH = data_path
    seeds = [SEED_BASE, SEED_BASE + 1] if q else [SEED_BASE + i for i in range(10)]
    reps = 200 if q else 2000
    tag = "_QUICK" if q else ""
    start = datetime.now()

    normal_df, attack_df = load_pools()
    train_df, val_df, test_df = user_disjoint_split(normal_df, attack_df)
    if q:
        train_df = train_df.sample(n=min(60_000, len(train_df)), random_state=SEED_BASE)
        val_df = val_df.sample(n=min(20_000, len(val_df)), random_state=SEED_BASE)
        test_df = test_df.sample(n=min(20_000, len(test_df)), random_state=SEED_BASE)

    freq_maps, known_ips, known_countries = fit_frequency_maps(train_df)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(extract_features_freq(train_df, freq_maps, known_ips, known_countries))

    print("Building replay streams...")
    test = Stream(test_df, freq_maps, known_ips, known_countries)
    combined = Stream(pd.concat([val_df, test_df], ignore_index=True), freq_maps, known_ips, known_countries)
    X_test_s, X_comb_s = scaler.transform(test.X), scaler.transform(combined.X)

    results = {"mode": "quick" if q else "full", "seeds": seeds,
               "stream_stats": {"test": stream_stats(test), "val_plus_test": stream_stats(combined)}}

    print("Rules-only replays...")
    rules_test = replay(test, None)
    rules_comb = replay(combined, None)

    per_seed = []
    seed42 = None
    for seed in seeds:
        t0 = datetime.now()
        iso, thr = fit_if(X_train_scaled, seed)
        ml = iso.score_samples(X_test_s) < thr
        hyb = replay(test, ml)
        row = {"seed": seed,
               "rules_only": arm_metrics(test, rules_test["flagged"]),
               "ml_only": arm_metrics(test, ml),
               "hybrid": arm_metrics(test, hyb["flagged"]),
               "hybrid_blocking": blocking_harm(test, hyb),
               "fpr_decomposition": fpr_decomposition(test, ml, hyb)}
        per_seed.append(row)
        if seed == SEED_BASE:
            seed42 = (iso, thr, ml, hyb)
        print(f"   seed {seed}: campaign recall hybrid {row['hybrid']['campaign_recall']:.4f} "
              f"vs IF {row['ml_only']['campaign_recall']:.4f}; FPR hybrid {row['hybrid']['fpr']:.4f} "
              f"vs IF {row['ml_only']['fpr']:.4f}  ({(datetime.now() - t0).seconds}s)")
    results["per_seed"] = per_seed

    def stat(path):
        vals = np.array([path(r) for r in per_seed], float)
        return {"mean": round(float(vals.mean()), 4), "std": round(float(vals.std()), 4),
                "min": round(float(vals.min()), 4), "max": round(float(vals.max()), 4)}

    summary = {}
    for arm in ("rules_only", "ml_only", "hybrid"):
        summary[arm] = {k: stat(lambda r, a=arm, k=k: r[a][k])
                        for k in ("recall", "campaign_recall", "f1", "fpr", "alerts_per_1000_events",
                                  "benign_ips_flagged", "benign_users_flagged")}
    summary["diff_hybrid_minus_ml"] = {
        "campaign_recall": stat(lambda r: r["hybrid"]["campaign_recall"] - r["ml_only"]["campaign_recall"]),
        "fpr": stat(lambda r: r["hybrid"]["fpr"] - r["ml_only"]["fpr"]),
        "seeds_with_hybrid_campaign_recall_higher":
            int(sum(r["hybrid"]["campaign_recall"] > r["ml_only"]["campaign_recall"] for r in per_seed)),
    }
    summary["hybrid_blocking"] = {k: stat(lambda r, k=k: r["hybrid_blocking"][k])
                                  for k in ("benign_ips_blocked", "benign_events_after_block",
                                            "benign_successful_logins_after_block",
                                            "benign_users_affected_any", "share_benign_users_affected")}
    results["across_seeds"] = summary

    # Reproduction check against Table 2 (seed 42)
    s42 = per_seed[0]
    check = {}
    for arm, exp in TABLE2.items():
        got = {"recall": s42[arm]["recall"], "fpr": s42[arm]["fpr"],
               "campaign_recall": s42[arm]["campaign_recall"]}
        check[arm] = {"expected": exp, "got": got,
                      "match": all(abs(got[k] - exp[k]) < 0.0015 for k in exp)}
    results["table2_reproduction_seed42"] = check

    print("Bootstrap (seed 42)...")
    _, _, ml42, hyb42 = seed42
    results["bootstrap_seed42"] = bootstrap(
        test, {"rules_only": rules_test["flagged"], "ml_only": ml42, "hybrid": hyb42["flagged"]},
        reps, SEED_BASE)
    results["rules_only_blocking"] = blocking_harm(test, rules_test)

    print("Sensitivity replay: validation + test combined (full sampled campaigns)...")
    iso42, thr42, _, _ = seed42
    ml_comb = iso42.score_samples(X_comb_s) < thr42
    hyb_comb = replay(combined, ml_comb)
    results["val_plus_test_replay_seed42"] = {
        "rules_only": arm_metrics(combined, rules_comb["flagged"]),
        "ml_only": arm_metrics(combined, ml_comb),
        "hybrid": arm_metrics(combined, hyb_comb["flagged"]),
        "hybrid_blocking": blocking_harm(combined, hyb_comb),
    }
    results["elapsed_minutes"] = round((datetime.now() - start).total_seconds() / 60, 1)

    # ── Save ──
    os.makedirs(RESULTS_DIR, exist_ok=True)
    jpath = os.path.join(RESULTS_DIR, f"batch5_results{tag}.json")
    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o))

    L = [f"Batch 5 summary ({results['mode']}), {results['elapsed_minutes']} min", ""]
    L.append("Table 2 reproduction (seed 42): " + ", ".join(
        f"{a} {'MATCH' if c['match'] else 'DIFFERENT ' + str(c['got'])}" for a, c in check.items())
        + ("  [quick mode: expected to differ]" if q else "  [if any DIFFERENT, stop and send this file]"))
    L += ["", f"Across {len(seeds)} seeds (mean, min-max):"]
    L.append(f"   {'arm':<12}  {'event recall':<26}{'campaign recall':<26}{'FPR':<26}benign IPs flagged")
    for arm in ("rules_only", "ml_only", "hybrid"):
        s = summary[arm]
        f = lambda d: f"{d['mean']:.4f} ({d['min']:.4f}-{d['max']:.4f})"
        L.append(f"   {arm:<12}  {f(s['recall']):<26}{f(s['campaign_recall']):<26}{f(s['fpr']):<26}"
                 f"{s['benign_ips_flagged']['mean']:.0f}")
    d = summary["diff_hybrid_minus_ml"]
    L.append(f"   hybrid - IF campaign recall: mean {d['campaign_recall']['mean']:+.4f} "
             f"(min {d['campaign_recall']['min']:+.4f}, max {d['campaign_recall']['max']:+.4f}); "
             f"hybrid higher in {d['seeds_with_hybrid_campaign_recall_higher']}/{len(seeds)} seeds")
    L.append(f"   hybrid - IF FPR: mean {d['fpr']['mean']:+.4f} (min {d['fpr']['min']:+.4f}, max {d['fpr']['max']:+.4f})")
    b = results["bootstrap_seed42"]
    L += ["", f"Bootstrap 95% CI, seed 42 ({b['reps']} reps; attacking IPs / benign IPs resampled):"]
    for arm in ("rules_only", "ml_only", "hybrid"):
        L.append(f"   {arm:<12} campaign recall {b['campaign_recall_95ci'][arm]}  FPR {b['fpr_95ci'][arm]}")
    dd = b["diff_hybrid_minus_ml"]
    L.append(f"   hybrid - IF  campaign recall {dd['campaign_recall_95ci']} (>0 in {dd['campaign_recall_share_reps_gt0']:.1%} of reps)"
             f"  FPR {dd['fpr_95ci']}")
    hb = per_seed[0]["hybrid_blocking"]
    L += ["", "Hybrid blocking cost on the test stream (seed 42):",
          f"   benign IPs blocked {hb['benign_ips_blocked']} of {hb['benign_ips_total']} {hb['benign_ips_blocked_by']}",
          f"   benign events after their IP was blocked {hb['benign_events_after_block']} "
          f"({hb['share_benign_events_after_block']:.2%} of benign events), of which successful logins "
          f"{hb['benign_successful_logins_after_block']}",
          f"   benign users affected {hb['benign_users_affected_any']} of {hb['benign_users_total']} "
          f"({hb['share_benign_users_affected']:.2%})",
          f"   attacking IPs blocked {hb['attack_ips_blocked']}"]
    fd = per_seed[0]["fpr_decomposition"]["benign"]
    L += ["", "Where the hybrid's lower FPR comes from (seed 42, benign events, % of benign events):",
          f"   IF-only FPR {fd['rate_points']['if_only_flags']}  -> hybrid FPR {fd['rate_points']['hybrid_flags']}",
          f"   IF flag silenced, IP already rule-blocked: -{fd['rate_points']['if_flag_silenced_ip_rule_blocked']}",
          f"   IF flag silenced, IP already ML-blocked:   -{fd['rate_points']['if_flag_silenced_ip_ml_blocked']}",
          f"   IF flag silenced, other:                   -{fd['rate_points']['if_flag_silenced_other']}",
          f"   rule alerts the IF did not raise:          +{fd['rate_points']['rule_alerts_without_if_flag']}",
          f"   identity check: {fd['check_identity_holds']}"]
    fa = per_seed[0]["fpr_decomposition"]["attack"]
    L.append(f"   (attack events: IF recall {fa['rate_points']['if_only_flags']} -> hybrid "
             f"{fa['rate_points']['hybrid_flags']}; silenced by blocks "
             f"-{fa['rate_points']['if_flag_silenced_ip_rule_blocked'] + fa['rate_points']['if_flag_silenced_ip_ml_blocked']})")
    st, sc = results["stream_stats"]["test"], results["stream_stats"]["val_plus_test"]
    vt = results["val_plus_test_replay_seed42"]
    L += ["", "Replay construction:",
          f"   test stream: {st['attacking_ips']} attacking IPs, median {st['attack_events_per_ip_median']} events/IP, "
          f"{st['share_attacking_ips_with_ge5_failed']:.1%} of IPs with >=5 failed attempts",
          f"   val+test:    {sc['attacking_ips']} attacking IPs, median {sc['attack_events_per_ip_median']} events/IP, "
          f"{sc['share_attacking_ips_with_ge5_failed']:.1%} of IPs with >=5 failed attempts",
          "   val+test replay (seed 42): " + "; ".join(
              f"{a} recall {vt[a]['recall']:.4f} campaign {vt[a]['campaign_recall']:.4f} FPR {vt[a]['fpr']:.4f}"
              for a in ("rules_only", "ml_only", "hybrid"))]
    text = "\n".join(L)
    spath = os.path.join(RESULTS_DIR, f"batch5_summary{tag}.txt")
    with open(spath, "w") as f:
        f.write(text)
    print("\n" + text + f"\n\nSaved -> {jpath}\nSaved -> {spath}")


if __name__ == "__main__":
    main()
