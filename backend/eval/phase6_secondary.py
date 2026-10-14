# backend/eval/phase6_secondary.py
"""
Phase 6 secondary results (eval/PROTOCOL.md amendment 9), on May:

  python -m eval.phase6_secondary s1   leakage replication: Phase 2 forest
                                       variants (a), (b), (c) x seeds 42-44
  python -m eval.phase6_secondary s2   the eight cached Phase 4 HGB fits on
                                       Phase 4 features (one causal pass)
  python -m eval.phase6_secondary s3   the legacy system on May (eval/harness)
  python -m eval.phase6_secondary s4   label audit (descriptive)

--half val_b --dev-only runs a stage on a development half instead (code
check before the test is read; --smoke N limits the scored events).
S5 comes from `python -m eval.phase6 replay`; S6 is the live demo.
"""

import argparse
import contextlib
import io
import os
import pickle
import sys
import time
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval import phase4 as P4  # noqa: E402
from eval import phase4b as P4B  # noqa: E402
from eval import phase5 as P5  # noqa: E402
from eval import phase5b as P5B  # noqa: E402
from eval import phase6 as P6  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402

SEEDS = (42, 43, 44)
save_json = P5.save_json


def _out_name(stage, args):
    return f"phase6_{stage}.json" if not args.dev_only else f"phase6_{stage}_devcheck.json"


def _parts(S, half, smoke):
    hm = S.halves[half].copy()
    if smoke:
        idx = np.flatnonzero(hm)
        hm[idx[smoke:]] = False
    return OrderedDict([("all", hm), ("new_attackers", hm & S.strata["new_attackers"])])


def _summ(vals):
    v = [x for x in vals if x is not None]
    return {"mean": float(np.mean(v)), "min": float(np.min(v)), "max": float(np.max(v))} if v else None


# ── S1: leakage replication ──────────────────────────────────────────────────

def stage_s1(args):
    from eval import phase2_baseline as P2
    clk = Clock()
    S = P6.Stream6(args.dev_only)
    parts = _parts(S, args.half, args.smoke)
    rows = np.flatnonzero(parts["all"])
    t = time.time()
    fr_win = P3.windowed_failed_rate(S, P3.ML_WINDOW_DAYS)
    clk.tick("30-day windowed failed_rate over the stream", t)
    seeds = tuple(int(x) for x in args.seeds.split(","))
    benign = ~S.truth[:S.n_train]
    allr = np.ones(S.n_train, bool)
    out = OrderedDict()
    for v, desc in P4B.D1_VARIANTS.items():
        if args.variants and v not in args.variants.split(","):
            continue
        t = time.time()
        maps_rows, fit_rows = {"a": (benign, benign), "b": (allr, benign), "c": (allr, allr)}[v]
        maps_df = P4B.frame(S, maps_rows)
        fit_df = maps_df if maps_rows is fit_rows else P4B.frame(S, fit_rows)
        prep = P4B.prepare(maps_df, fit_df)
        X = P3.raw_features(S, prep, fr_win)
        Xs = prep.scaler.transform(X[rows])
        clk.tick(f"S1 ({v}): maps, scaler, features", t)
        res = OrderedDict([("description", desc), ("map_rows", prep.n_map_rows), ("fit_rows", prep.n_fit_rows)])
        for seed in seeds:
            t = time.time()
            model, s_train = P2.fit_forest(prep.X_train, seed)
            thr = np.percentile(s_train, 100.0 * P3.CONTAMINATION)
            s = np.zeros(S.n)
            s[rows] = -P2.score_samples(model, Xs)
            r = {k: P4.event_metrics(S, s, m) for k, m in parts.items()}
            if v == "a" and seed == 42 and not args.smoke:
                # must reproduce the cached Phase 3 decisions on the dev events
                dev = np.arange(S.n_dev)
                d = P2.score_samples(model, prep.scaler.transform(X[dev])) - thr
                cached = np.load(P3B.ML_DECISION)[:S.n_dev]
                r["check_vs_cached_phase3_decisions"] = {
                    "bit_identical": bool(np.array_equal(d, cached)),
                    "max_abs_diff": float(np.max(np.abs(d - cached)))}
            res[f"seed_{seed}"] = r
            clk.tick(f"S1 ({v}) seed {seed}: fit, score {len(rows):,} events", t)
            print(v, seed, {k: {m: (round(x, 4) if x is not None else None) for m, x in rr.items()}
                            for k, rr in r.items() if k in parts}, flush=True)
        res["over_seeds"] = {k: {m: _summ([res[f"seed_{sd}"][k][m] for sd in seeds])
                                 for m in ("roc_auc", "pr_auc", "tpr_at_1pct_fpr")} for k in parts}
        out[v] = res
    save_json(_out_name("s1", args), {"protocol": "eval/PROTOCOL.md amendment 9, S1", "half": args.half,
                                      "events": {k: int(m.sum()) for k, m in parts.items()},
                                      "base_rate": {k: float(S.truth[m].mean()) for k, m in parts.items()},
                                      "variants": out, "timings_seconds": clk.total()})


# ── S2: supervised reference ─────────────────────────────────────────────────

def stage_s2(args):
    from ml import features_v4 as F
    clk = Clock()
    S = P6.Stream6(args.dev_only)
    parts = _parts(S, args.half, args.smoke)
    rows = np.flatnonzero(parts["all"])
    last = int(rows.max()) + 1
    t = time.time()
    path = P6.cpath("X_v4.npy" if not args.dev_only else "X_v4_devcheck.npy")
    X = np.lib.format.open_memmap(path, mode="w+", dtype=np.float64, shape=(last, F.N_FEATURES))
    fx = F.FeatureExtractorV4()
    for i, e in enumerate(P6.events(S)):
        if i >= last:
            break
        X[i] = fx.update_and_extract(e)
        if i % 1_000_000 == 0 and i:
            print(f"  {i:,} events, {time.time() - t:.0f} s", flush=True)
    X.flush()
    clk.tick(f"Phase 4 features, one causal pass ({last:,} events)", t)
    # check: the dev rows equal the Phase 4 feature cache
    t = time.time()
    X4 = np.load(os.path.join(P4.CACHE, "X.npy"), mmap_mode="r")
    m = min(last, S.n_dev, X4.shape[0])
    eq = all(np.array_equal(np.asarray(X[a:min(a + 500_000, m)]), np.asarray(X4[a:min(a + 500_000, m)]),
                            equal_nan=True) for a in range(0, m, 500_000))
    clk.tick("check against the Phase 4 feature cache", t)
    sel4 = P5.load_json("phase4_selection.json")
    ref = {fs: h["name"] for fs, h in sel4["hgb_best"].items()}
    out = OrderedDict()
    for name, _, meta in P4.references():
        t = time.time()
        with open(P4.cache(f"model_{name}.pkl"), "rb") as f:
            model = pickle.load(f)
        cols = F.columns(meta["groups"])
        s = np.zeros(S.n)
        s[rows] = model.predict_proba(np.ascontiguousarray(X[rows][:, cols], dtype=np.float32))[:, 1]
        out[name] = {"feature_set": meta["feature_set"], "is_phase4_reference": name == ref[meta["feature_set"]],
                     **{k: P4.event_metrics(S, s, pm) for k, pm in parts.items()}}
        clk.tick(f"S2 {name}", t)
        print(name, {k: out[name][k] for k in parts}, flush=True)
    save_json(_out_name("s2", args), {"protocol": "eval/PROTOCOL.md amendment 9, S2", "half": args.half,
                                      "dev_rows_equal_phase4_cache": bool(eq), "dev_rows_checked": int(m),
                                      "events": {k: int(pm.sum()) for k, pm in parts.items()},
                                      "fits": out, "timings_seconds": clk.total()})


# ── S3: the legacy system ────────────────────────────────────────────────────

def stage_s3(args):
    from eval import gate, harness
    clk = Clock()
    S = P6.Stream6(args.dev_only)
    hm = _parts(S, args.half, args.smoke)["all"]
    idx = np.flatnonzero(hm)
    t = time.time()
    stamps = S.timestamps()
    country = S.df["Country"].astype(str).replace("", "XX").to_numpy(dtype=object)
    device = S.df["Device Type"].astype(str).replace("", "Unknown").to_numpy(dtype=object)
    ev = [{"timestamp": stamps[i], "user": str(S.user_ids[S.user[i]]), "ip": S.ip_names[S.ip[i]],
           "status": "SUCCESS" if S.success[i] else "FAILED", "country": country[i],
           "device_type": device[i]} for i in idx]
    truth = S.truth[idx]
    clk.tick(f"{len(ev):,} events (state starts empty at the first)", t)
    t = time.time()
    with harness.override_config(RULES_MODE="legacy", ML_MODE="legacy"):
        det = gate.load_detector()
        r = harness.replay(ev, harness.PrecomputedScorer(det))
    clk.tick("legacy agents (dry pass, batch scoring, replay)", t)
    t = time.time()
    summ = harness.summarize(r, ev, truth)
    ips = S.ip[idx]
    att = np.zeros(S.n_ip, bool)
    att[ips[truth]] = True
    types = Counter()
    for ty, c in zip(r.alert_type, r.confidence):
        if ty:
            types[ty if ty != "ML Anomaly Detected" else f"{ty} ({c})"] += 1
    per = OrderedDict()
    label = np.array([(ty if ty != "ML Anomaly Detected" else f"{ty} ({c})") if ty else ""
                      for ty, c in zip(r.alert_type, r.confidence)], dtype=object)
    for ty in sorted(types):
        m = label == ty
        y = truth[m]
        lo, hi = P3B.bootstrap(ips[m], y)
        per[ty] = {"alerts": int(m.sum()), "precision": float(y.mean()), "ci_low": lo, "ci_high": hi,
                   "attacking_ips_flagged": int(len(np.unique(ips[m][y]))),
                   "benign_ips_flagged": int(len(np.unique(ips[m][~att[ips[m]]])))}
    flagged = label != ""
    lo, hi = P3B.bootstrap(ips[flagged], truth[flagged])
    # HIGH-alert simulated blocks: benign users affected, excluding the placeholder ID
    blk = r.response_block_idx
    unk = S.unknown[idx]
    users_ex = set()
    for k, e in enumerate(ev):
        b = blk.get(e["ip"])
        if b is not None and k > b and not truth[k] and not unk[k]:
            users_ex.add(e["user"])
    out = {"protocol": "eval/PROTOCOL.md amendment 9, S3", "half": args.half,
           "model_sha256": P6_sha(os.path.join(BACKEND, "data", "model.pkl")),
           "summary": {k: v for k, v in summ.items() if k != "breakdown"},
           "alert_precision_ci": [lo, hi], "per_alert_type": per,
           "high_block_benign_users_affected_excl_placeholder": len(users_ex),
           "timings_seconds": clk.total()}
    clk.tick("metrics", t)
    out["timings_seconds"] = clk.total()
    save_json(_out_name("s3", args), out)
    print({k: v for k, v in out["summary"].items()})
    for ty, x in per.items():
        print(f"  {ty:40s} n {x['alerts']:>7} prec {x['precision']:.3f} [{x['ci_low']:.3f}, {x['ci_high']:.3f}] "
              f"att {x['attacking_ips_flagged']} ben {x['benign_ips_flagged']}")


def P6_sha(path):
    from eval.freeze import sha256_bytes
    return sha256_bytes(path)


# ── S4: label audit ──────────────────────────────────────────────────────────

def stage_s4(args):
    clk = Clock()
    t = time.time()
    S = P6.build(args.dev_only, clk)
    half = args.half
    hm = S.halves[half]
    before = np.arange(S.n) < (S.n_dev if half == "may" else S.n_train)
    ret = S.att_dev if half == "may" else S.att_train
    country, _ = pd.factorize(S.df["Country"].astype(str).to_numpy())
    country = country.astype(np.int64)
    n_country = int(country.max()) + 1
    att_asns = np.unique(S.asn[before & S.truth])
    asn_hit = np.isin(S.asn, att_asns)
    upto = np.arange(S.n) <= int(np.flatnonzero(hm).max())      # whole history to the half's end
    hist_ph = np.bincount(S.ip[upto], weights=S.unknown[upto], minlength=S.n_ip)
    hist_succ = np.bincount(S.ip[upto], weights=S.success[upto], minlength=S.n_ip)
    clk.tick("stream", t)
    ips = S.ip[hm]
    present = np.zeros(S.n_ip, bool)
    present[ips] = True
    att = S.attacking_ips(hm)
    alerted = np.zeros(S.n_ip, bool)
    ap = S.a_pos[hm[S.a_pos]]
    alerted[S.ip[ap]] = True
    benign = present & ~att & ~ret
    groups = OrderedDict([
        ("R (returning attacking, alerted)", att & ret & alerted),
        ("N alerted (new attacking)", att & ~ret & alerted),
        ("N not alerted (new attacking)", att & ~ret & ~alerted),
        ("BA (benign, alerted, new-attacker stratum)", benign & alerted),
        ("BN (benign, not alerted, new-attacker stratum)", benign & ~alerted),
    ])
    ev = np.bincount(ips, minlength=S.n_ip)
    fail = np.bincount(ips, weights=S.failed[hm], minlength=S.n_ip)
    ph = np.bincount(ips, weights=S.unknown[hm], minlength=S.n_ip)
    succ = np.bincount(ips, weights=S.success[hm], minlength=S.n_ip)
    days = P5B._distinct_per_ip(S, hm, S.day, int(S.day.max()) + 1)
    accts = P5B._distinct_per_ip(S, hm, S.user, S.n_user)
    ctry = P5B._distinct_per_ip(S, hm, country, n_country)
    asn_ip = np.zeros(S.n_ip, bool)
    asn_ip[S.ip[hm & asn_hit]] = True
    q = P5B._q
    res = OrderedDict()
    for g, gm in groups.items():
        idx = np.flatnonzero(gm)
        res[g] = {"ips": int(len(idx)), "events": int(ev[idx].sum()),
                  "events_per_ip": q(ev[idx]), "active_days": q(days[idx]),
                  "failure_ratio": q(fail[idx] / np.maximum(ev[idx], 1)),
                  "distinct_accounts": q(accts[idx]), "placeholder_attempts": q(ph[idx]),
                  "successful_logins": q(succ[idx]), "distinct_countries": q(ctry[idx]),
                  "share_single_event": float((ev[idx] == 1).mean()) if len(idx) else None,
                  "share_le_5_events": float((ev[idx] <= 5).mean()) if len(idx) else None,
                  "share_asn_hosts_earlier_attacker": float(asn_ip[idx].mean()) if len(idx) else None}
    ba = groups["BA (benign, alerted, new-attacker stratum)"]
    PM = P5B.PLACEHOLDER_MIN
    strict = ba & (hist_ph >= PM) & (hist_succ == 0)
    res["BA strict misuse"] = {
        "definition": f">= {PM} placeholder attempts and 0 successful logins over the IP's whole "
                      "history up to the end of the half",
        "ips": int(strict.sum()), "of_BA": int(ba.sum()), "share": float(strict.sum() / max(ba.sum(), 1)),
        "their_half_events": int(ev[strict].sum()),
        "their_half_alerted_events": int(strict[S.ip[ap]].sum()),
        "half_only_variant_ips": int((ba & (ph >= PM) & (succ == 0)).sum())}
    R_ = groups["R (returning attacking, alerted)"]
    res["R strict misuse (reference)"] = {
        "ips": int((R_ & (hist_ph >= PM) & (hist_succ == 0)).sum()), "of_R": int(R_.sum())}
    res["alerted_events_by_group"] = {g: int(gm[S.ip[ap]].sum()) for g, gm in groups.items()}
    out = {"protocol": "eval/PROTOCOL.md amendment 9, S4 (descriptive only)", "half": half,
           "earlier_attack_asns": int(len(att_asns)), "groups": res, "timings_seconds": clk.total()}
    save_json(_out_name("s4", args), out)
    for g, r in res.items():
        if "events_per_ip" in r:
            print(f"{g:50s} IPs {r['ips']:>7}  ev {r['events_per_ip']['median']}/{r['events_per_ip']['p90']} "
                  f"days {r['active_days']['median']}/{r['active_days']['p90']} fail {r['failure_ratio']['median']} "
                  f"accts {r['distinct_accounts']['median']}/{r['distinct_accounts']['p90']} "
                  f"ph {r['placeholder_attempts']['median']}/{r['placeholder_attempts']['p90']} "
                  f"succ {r['successful_logins']['median']}/{r['successful_logins']['p90']} "
                  f"le5 {r['share_le_5_events']:.2f} asn {r['share_asn_hosts_earlier_attacker']:.3f}")
        else:
            print(g, r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["s1", "s2", "s3", "s4"])
    ap.add_argument("--half", default="may")
    ap.add_argument("--dev-only", action="store_true")
    ap.add_argument("--smoke", type=int, default=0)
    ap.add_argument("--variants", default="", help="s1: subset of a,b,c (code check only)")
    ap.add_argument("--seeds", default="42,43,44", help="s1: seeds (code check only)")
    args = ap.parse_args()
    return {"s1": stage_s1, "s2": stage_s2, "s3": stage_s3, "s4": stage_s4}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
