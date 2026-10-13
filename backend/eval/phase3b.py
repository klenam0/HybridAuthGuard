# backend/eval/phase3b.py
"""
Phase 3b: the v3 rule selection under eval/PROTOCOL.md amendment 3.
dev_val is split in time into val_a (tuning) and val_b (confirmation);
state is always built causally from the start of the development stream.
The locked test month is never read.

Stages (run from backend/; each well under 10 minutes):
  python -m eval.phase3b select    grids on val_a only (bootstrap lower bound
                                   criterion); writes the selection. Never
                                   computes a metric on val_b.
  python -m eval.phase3b confirm   val_b metrics of the chosen settings and
                                   the ML step, read back from disk
  python -m eval.phase3b workload  alerts, incidents and budget curves on val_b
  python -m eval.phase3b replay    real v3 agents at the chosen settings, no
                                   blocking; equivalence on val_a and val_b

The ML step reuses results/phase3_cache/ml_decision_v3.npy (Phase 3 stage
ml: the Phase 2 Isolation Forest design, seed 42, contamination 0.3, v3
failed_rate). Intermediates: results/phase3b_cache/ (gitignored). Results:
results/phase3b_selection.json, phase3b_confirm.json, phase3b_workload.json,
phase3b_replay_check.json. PHASE3B_OUT redirects all of them (smoke tests).
"""

import argparse
import contextlib
import io
import json
import os
import sys
import time

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval.phase3_rules import (Clock, Detector, Keyed, Stream, distinct_counts,  # noqa: E402
                               failures_before, multi_ip_stats)

RESULTS = os.environ.get("PHASE3B_OUT") or P3.RESULTS
CACHE = os.path.join(RESULTS, "phase3b_cache")
ML_DECISION = os.path.join(P3.CACHE, "ml_decision_v3.npy")

# ── Amendment 3 ──────────────────────────────────────────────────────────────
VAL_B_START = int(np.datetime64("2020-04-15T00:00:00", "s").astype(np.int64))
LONG = [300, 1800, 3600, 21600, 86400, 172800, 604800]
GRID = {
    R.BF: {"window": [60, 300, 600, 1800, 3600], "min": [3, 5, 10, 20, 50]},
    R.SLOW: {"window": [3600, 10800, 21600, 43200, 86400, 172800, 604800],
             "min": [3, 4, 6, 10, 20], "spread": [300, 900, 1800]},
    R.CS: {"window": LONG, "min": [1, 2, 3, 5, 10, 20]},
    R.INVALID: {"window": LONG, "min": [2, 3, 5, 10, 20]},
    R.DIST: {"window": LONG, "min": [1, 2, 3, 5, 10, 20]},
    R.SAF: {"window": LONG, "min": [1, 2, 3, 5, 10]},
    R.MULTI: P3.GRID[R.MULTI],
}
MIN_ALERTS = 30
BOOT_N, BOOT_CHUNK, BOOT_SEED = 1000, 100, 42
TIE_SEED = 42
BUDGETS = (100, 500, 2000)
HALVES = ("val_a", "val_b")
SUBSETS = ("all", "excl_placeholder", "cold")
FAILS = "fails criterion (reported at the best lower bound)"
MEETS = "meets criterion (alert tier)"


def save_json(name, obj):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, default=P3._jsonable)
        f.write("\n")
    return path


def load_json(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f)


def stream():
    """The Phase 3 stream plus the two halves, their subsets and base rates."""
    S = Stream()
    if os.environ.get("PHASE3_LIMIT"):   # smoke test: split the stand-in val by time
        cut = int(np.median(S.t[S.val]))
    else:
        cut = VAL_B_START
    S.val_a = S.val & (S.t < cut)
    S.val_b = S.val & (S.t >= cut)
    S.halves = {"val_a": S.val_a, "val_b": S.val_b}
    S.subsets = {h: {"all": m, "excl_placeholder": m & ~S.unknown, "cold": m & S.cold}
                 for h, m in S.halves.items()}
    S.base = {h: float(S.truth[m].mean()) for h, m in S.halves.items()}
    S.att = {h: S.attacking_ips(m) for h, m in S.halves.items()}
    S.day = S.t // 86400
    return S


# ── Bootstrap and the criterion ──────────────────────────────────────────────

def bootstrap(ips, y):
    """95% percentile interval of alert precision, IPs resampled with
    replacement (clustered by IP); default_rng(42) per call."""
    if len(ips) == 0:
        return 0.0, 0.0
    _, codes = np.unique(ips, return_inverse=True)
    n_i = np.bincount(codes).astype(np.int64)
    a_i = np.bincount(codes, weights=y.astype(np.float64))
    K = len(n_i)
    rng = np.random.default_rng(BOOT_SEED)
    prec = np.empty(BOOT_N)
    for c in range(0, BOOT_N, BOOT_CHUNK):
        idx = rng.integers(0, K, size=(BOOT_CHUNK, K))
        prec[c:c + BOOT_CHUNK] = a_i[idx].sum(1) / n_i[idx].sum(1)
    lo, hi = np.percentile(prec, [2.5, 97.5])
    return float(lo), float(hi)


def half_metrics(S, alert_pos, half):
    """Alerts at alert_pos on the half's events: count, precision with its
    bootstrap interval, attacking and benign IPs flagged."""
    m = S.halves[half]
    p = alert_pos[m[alert_pos]]
    y = S.truth[p]
    ips = S.ip[p]
    lo, hi = bootstrap(ips, y)
    att = S.att[half]
    return {"alerts": int(len(p)), "attack_alerts": int(y.sum()),
            "precision": float(y.mean()) if len(p) else 0.0, "ci_low": lo, "ci_high": hi,
            "attacking_ips_flagged": int(len(np.unique(ips[y]))),
            "benign_ips_flagged": int(len(np.unique(ips[~att[ips]])))}


def criterion(S, m, half):
    return m["alerts"] >= MIN_ALERTS and m["ci_low"] >= 2 * S.base[half]


def grid_row(S, det):
    m = half_metrics(S, det.alert_pos, "val_a")
    return {"params": det.params, **m, "matches_val_a": int(S.val_a[det.match_pos].sum()),
            "meets_criterion": bool(criterion(S, m, "val_a")),
            "eligible_alert_count": m["alerts"] >= MIN_ALERTS}


def choose(rows):
    """Amendment 3: max attacking IPs flagged on val_a s.t. >= 30 alerts and
    bootstrap lower bound >= 2x the val_a base rate; ties higher lower bound,
    fewer alerts, grid order. Else the eligible setting with the best lower
    bound."""
    meet = [(i, r) for i, r in enumerate(rows) if r["meets_criterion"]]
    if meet:
        return max(meet, key=lambda ir: (ir[1]["attacking_ips_flagged"], ir[1]["ci_low"],
                                         -ir[1]["alerts"], -ir[0]))[1], MEETS
    pool = [(i, r) for i, r in enumerate(rows) if r["eligible_alert_count"]] or list(enumerate(rows))
    return max(pool, key=lambda ir: (ir[1]["ci_low"], ir[1]["attacking_ips_flagged"],
                                     -ir[1]["alerts"], -ir[0]))[1], FAILS


# ── Stage: select (val_a only) ───────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = stream()
    clk.tick("load dev stream", t)
    pair = S.user * S.n_ip + S.ip
    out = {"base_rate_val_a": S.base["val_a"], "precision_threshold_val_a": 2 * S.base["val_a"],
           "min_alerts": MIN_ALERTS, "bootstrap": {"resamples": BOOT_N, "seed": BOOT_SEED},
           "events_val_a": int(S.val_a.sum()), "grid": {k: {p: list(v) for p, v in g.items()}
                                                      for k, g in GRID.items()},
           "grids": {}, "chosen": {}, "status": {}}
    chosen = {}

    def settle(name, rows, dets, key):
        best, status = choose(rows)
        out["grids"][name], out["chosen"][name], out["status"][name] = rows, best, status
        chosen[name] = dets[key(best["params"])]

    t = time.time()
    rf = np.flatnonzero(S.real_fail)
    kd = Keyed(S, rf, S.ip)
    bf_cnt = {W: kd.count_since(W)[0] for W in GRID[R.BF]["window"]}
    slow_cnt, slow_spread = {}, {}
    for W in GRID[R.SLOW]["window"]:
        c, lf = kd.count_since(W)
        slow_cnt[W], slow_spread[W] = c, kd.spread(lf)
    clk.tick("window counts: failures per IP (BF, slow BF)", t)

    t = time.time()
    rows, dets = [], {}
    for W in GRID[R.BF]["window"]:
        for N in GRID[R.BF]["min"]:
            m = rf[bf_cnt[W] >= N]
            d = dets[(W, N)] = Detector(R.BF, {"window": W, "min": N}, m, S.ip[m], S)
            rows.append(grid_row(S, d))
    settle(R.BF, rows, dets, lambda p: (p["window"], p["min"]))
    bw, bn = out["chosen"][R.BF]["params"]["window"], out["chosen"][R.BF]["params"]["min"]
    clk.tick(f"grid Brute Force ({len(rows)})", t)

    t = time.time()
    rows, dets = [], {}
    below = bf_cnt[bw] < bn
    for W in GRID[R.SLOW]["window"]:
        for N in GRID[R.SLOW]["min"]:
            for sp in GRID[R.SLOW]["spread"]:
                m = rf[below & (slow_cnt[W] >= N) & (slow_spread[W] >= sp)]
                d = dets[(W, N, sp)] = Detector(R.SLOW, {"window": W, "min": N, "spread": sp},
                                                m, S.ip[m], S)
                rows.append(grid_row(S, d))
    settle(R.SLOW, rows, dets, lambda p: (p["window"], p["min"], p["spread"]))
    clk.tick(f"grid Slow Brute Force ({len(rows)})", t)

    t = time.time()
    ua = np.flatnonzero(S.unknown)
    kd_u = Keyed(S, ua, S.ip)
    rows, dets = [], {}
    for W in GRID[R.INVALID]["window"]:
        c, _ = kd_u.count_since(W)
        for N in GRID[R.INVALID]["min"]:
            m = ua[c >= N]
            d = dets[(W, N)] = Detector(R.INVALID, {"window": W, "min": N}, m, S.ip[m], S)
            rows.append(grid_row(S, d))
    settle(R.INVALID, rows, dets, lambda p: (p["window"], p["min"]))
    clk.tick(f"grid Invalid Account Spraying ({len(rows)})", t)

    for name, key, item in ((R.CS, S.ip, S.user), (R.DIST, S.user, S.ip)):
        t = time.time()
        dc = distinct_counts(S, rf, key, item, GRID[name]["window"])
        clk.tick(f"distinct counts ({name}, Python pass x{len(dc)})", t)
        t = time.time()
        rows, dets = [], {}
        for W in GRID[name]["window"]:
            for N in GRID[name]["min"]:
                m = rf[dc[W] >= N]
                k = S.ip[m] if name == R.CS else pair[m]
                d = dets[(W, N)] = Detector(name, {"window": W, "min": N}, m, k, S)
                rows.append(grid_row(S, d))
        settle(name, rows, dets, lambda p: (p["window"], p["min"]))
        clk.tick(f"grid {name} ({len(rows)})", t)

    t = time.time()
    rows, dets = [], {}
    for W in GRID[R.SAF]["window"]:
        sp, acc = failures_before(S, S.user, W)
        sp2, ipc = failures_before(S, S.ip, W)
        assert np.array_equal(sp, sp2)
        for N in GRID[R.SAF]["min"]:
            hit = (acc >= N) | (ipc >= N)
            m = sp[hit]
            d = dets[(W, N)] = Detector(R.SAF, {"window": W, "min": N}, m, pair[m], S)
            r = grid_row(S, d)
            a = np.isin(m, d.alert_pos) & S.val_a[m]
            r["account_branch_alert_share_val_a"] = float(np.mean((acc[hit] >= N)[a])) if a.any() else 0.0
            rows.append(r)
    settle(R.SAF, rows, dets, lambda p: (p["window"], p["min"]))
    clk.tick(f"grid Success After Failures ({len(rows)})", t)

    t = time.time()
    mp, base, ex = multi_ip_stats(S)
    rows, dets = [], {}
    for exempt in GRID[R.MULTI]["exempt"]:
        hit = base.copy()
        for e in exempt:
            hit &= ~ex[e]
        m = mp[hit]
        d = dets[tuple(exempt)] = Detector(R.MULTI, {"exempt": list(exempt)}, m, pair[m], S)
        rows.append(grid_row(S, d))
    settle(R.MULTI, rows, dets, lambda p: tuple(p["exempt"]))
    clk.tick("grid Multiple IP Login", t)

    t = time.time()
    lo, hi = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
    m = np.flatnonzero(S.success & (S.hour >= lo) & (S.hour <= hi))
    d = Detector(R.OFF_HOURS, {"hours": [lo, hi], "cooldown": P3.OFF_HOURS_DEDUP}, m, S.ip[m], S,
                 cooldown=P3.OFF_HOURS_DEDUP)
    r = grid_row(S, d)
    out["grids"][R.OFF_HOURS], out["chosen"][R.OFF_HOURS] = [r], r
    out["status"][R.OFF_HOURS] = "not tuned; " + (MEETS if r["meets_criterion"] else FAILS)
    chosen[R.OFF_HOURS] = d

    # The ML step is fixed (not tuned); only checked against the criterion.
    ml_match, ml_alert = ml_arrays(S)
    r = half_metrics(S, ml_alert, "val_a")
    r["params"] = {"seed": P3.SEED, "contamination": P3.CONTAMINATION, "dedup_s": P3.DEDUP}
    r["meets_criterion"] = bool(criterion(S, r, "val_a"))
    out["chosen"][R.ML] = r
    out["status"][R.ML] = "fixed; " + (MEETS if r["meets_criterion"] else FAILS)
    clk.tick("Suspicious Login Time and ML on val_a", t)

    os.makedirs(CACHE, exist_ok=True)
    arrays = {}
    for name, det in chosen.items():
        arrays[f"match::{name}"] = det.match_pos
        arrays[f"alert::{name}"] = det.alert_pos
    np.savez_compressed(os.path.join(CACHE, "chosen_rules.npz"), **arrays)
    out["settings"] = settings_from(out)
    out["timings_seconds"] = clk.total()
    save_json("phase3b_selection.json", out)
    print(f"val_a base rate {S.base['val_a']:.5f}, threshold {2 * S.base['val_a']:.5f}")
    for name, c in out["chosen"].items():
        n_meet = sum(r["meets_criterion"] for r in out["grids"].get(name, [c]))
        print(f"{name:26s} {str(c['params']):52s} {c['alerts']:>8} {c['precision']:.4f} "
              f"[{c['ci_low']:.4f}, {c['ci_high']:.4f}] att {c['attacking_ips_flagged']:>6} "
              f"ben {c['benign_ips_flagged']:>6} meet {n_meet}  {out['status'][name]}")


def ml_arrays(S):
    decision = np.load(ML_DECISION, mmap_mode="r")[:S.n]
    return P3.ml_arrays(S, np.asarray(decision))


def settings_from(sel):
    c = sel["chosen"]
    return {
        "V3_BF_WINDOW_SECONDS": c[R.BF]["params"]["window"],
        "V3_BF_MIN_FAILURES": c[R.BF]["params"]["min"],
        "V3_SLOW_BF_WINDOW_SECONDS": c[R.SLOW]["params"]["window"],
        "V3_SLOW_BF_MIN_FAILURES": c[R.SLOW]["params"]["min"],
        "V3_SLOW_BF_MIN_SPREAD_SECONDS": c[R.SLOW]["params"]["spread"],
        "V3_CS_WINDOW_SECONDS": c[R.CS]["params"]["window"],
        "V3_CS_MIN_ACCOUNTS": c[R.CS]["params"]["min"],
        "V3_INVALID_WINDOW_SECONDS": c[R.INVALID]["params"]["window"],
        "V3_INVALID_MIN_ATTEMPTS": c[R.INVALID]["params"]["min"],
        "V3_DIST_WINDOW_SECONDS": c[R.DIST]["params"]["window"],
        "V3_DIST_MIN_IPS": c[R.DIST]["params"]["min"],
        "V3_SAF_WINDOW_SECONDS": c[R.SAF]["params"]["window"],
        "V3_SAF_MIN_FAILURES": c[R.SAF]["params"]["min"],
        "V3_MULTI_IP_WINDOW_SECONDS": P3.MULTI_WINDOW,
        "V3_MULTI_IP_EXEMPT": tuple(c[R.MULTI]["params"]["exempt"]),
        "V3_KNOWN_IP_TTL_SECONDS": P3.KNOWN_IP_TTL,
        "V3_DEDUP_SECONDS": {"default": P3.DEDUP, R.OFF_HOURS: P3.OFF_HOURS_DEDUP},
        "V3_DUPLICATE_WINDOW_SECONDS": 300,
        "ML_FAILED_RATE_WINDOW_DAYS": P3.ML_WINDOW_DAYS,
        "V3_BLOCK_DETECTORS": (),
    }


def chosen_settings():
    sel = load_json("phase3b_selection.json")
    return sel, settings_from(sel)


def load_alerts(S, with_ml):
    z = np.load(os.path.join(CACHE, "chosen_rules.npz"))
    match = {d: z[f"match::{d}"] for d in R.RULE_DETECTORS}
    alert = {d: z[f"alert::{d}"] for d in R.RULE_DETECTORS}
    if with_ml:
        match[R.ML], alert[R.ML] = ml_arrays(S)
    return match, alert


# ── Stage: confirm (val_b, chosen settings only) ─────────────────────────────

def stage_confirm(args):
    clk = Clock()
    t = time.time()
    S = stream()
    sel = load_json("phase3b_selection.json")      # the choice is fixed on disk
    _, alert = load_alerts(S, with_ml=True)
    out = {"base_rate": S.base, "precision_threshold": {h: 2 * S.base[h] for h in HALVES},
           "events": {h: int(S.halves[h].sum()) for h in HALVES}, "detectors": {}}
    for name in list(R.RULE_DETECTORS) + [R.ML]:
        c = sel["chosen"][name]
        a = {k: c[k] for k in ("alerts", "attack_alerts", "precision", "ci_low", "ci_high",
                               "attacking_ips_flagged", "benign_ips_flagged")}
        b = half_metrics(S, alert[name], "val_b")
        out["detectors"][name] = {
            "params": c["params"], "status_val_a": sel["status"][name], "val_a": a,
            "val_a_meets": bool(c["meets_criterion"]), "val_b": b,
            "val_b_holds": bool(criterion(S, b, "val_b")),
            "val_b_meets_val_a_threshold": bool(b["alerts"] >= MIN_ALERTS
                                                and b["ci_low"] >= 2 * S.base["val_a"])}
    out["timings_seconds"] = clk.total()
    clk.tick("val_b metrics", t)
    save_json("phase3b_confirm.json", out)
    print(f"base rate val_a {S.base['val_a']:.5f} val_b {S.base['val_b']:.5f}")
    for name, d in out["detectors"].items():
        a, b = d["val_a"], d["val_b"]
        print(f"{name:26s} A {a['alerts']:>7} {a['precision']:.4f} [{a['ci_low']:.4f},{a['ci_high']:.4f}] "
              f"{a['attacking_ips_flagged']:>5}/{a['benign_ips_flagged']:>6} | "
              f"B {b['alerts']:>7} {b['precision']:.4f} [{b['ci_low']:.4f},{b['ci_high']:.4f}] "
              f"{b['attacking_ips_flagged']:>5}/{b['benign_ips_flagged']:>6} | "
              f"A {'meets' if d['val_a_meets'] else 'FAILS'}  B {'holds' if d['val_b_holds'] else 'FAILS'}")


# ── Stage: workload (val_b) ──────────────────────────────────────────────────

def incidents(S, alert, part, score_of):
    """Alerts on part's events grouped per (IP, calendar day)."""
    names = list(alert)
    pos, det = [], []
    for j, d in enumerate(names):
        p = alert[d][part[alert[d]]]
        pos.append(p)
        det.append(np.full(len(p), j, np.int64))
    pos, det = np.concatenate(pos), np.concatenate(det)
    key = S.ip[pos] * np.int64(1 << 20) + S.day[pos]
    uk, inc = np.unique(key, return_inverse=True)
    n = len(uk)
    attack = np.zeros(n, bool)
    np.logical_or.at(attack, inc, S.truth[pos])
    mask = np.zeros(n, np.int64)
    np.bitwise_or.at(mask, inc, np.int64(1) << det)
    n_det = np.zeros(n, np.int64)
    score = np.zeros(n)
    for j, d in enumerate(names):
        has = (mask >> j) & 1 == 1
        n_det += has
        score = np.where(has, np.maximum(score, score_of[d]), score)
    return {"ip": uk >> 20, "day": uk & ((1 << 20) - 1), "attack": attack, "n_det": n_det,
            "score": score, "alerts": len(pos)}


def workload(S, alert, part, att, n_days, score_of):
    I = incidents(S, alert, part, score_of)
    n = len(I["attack"])
    att_ips = int(att.sum())
    out = {"alerts": I["alerts"], "alerts_per_day": I["alerts"] / n_days,
           "incidents": n, "incidents_per_day": n / n_days,
           "attack_incidents": int(I["attack"].sum()),
           "incident_precision": float(I["attack"].mean()) if n else 0.0,
           "attacking_ips": att_ips,
           "attacking_ips_flagged": int(len(np.unique(I["ip"][I["attack"]]))),
           "benign_ips_flagged": int(len(np.unique(I["ip"][~att[I["ip"]]]))),
           "budgets": {}}
    tie = np.random.default_rng(TIE_SEED).random(n)
    order = np.lexsort((tie, -I["n_det"], -I["score"], I["day"]))
    day_sorted = I["day"][order]
    starts = np.searchsorted(day_sorted, day_sorted, side="left")
    rank = np.empty(n, np.int64)
    rank[order] = np.arange(n) - starts
    for B in BUDGETS:
        take = rank < B
        caught = len(np.unique(I["ip"][take & I["attack"]]))
        out["budgets"][str(B)] = {
            "incidents_taken": int(take.sum()), "incidents_taken_per_day": float(take.sum() / n_days),
            "incident_precision": float(I["attack"][take].mean()) if take.any() else 0.0,
            "attacking_ips_caught": int(caught),
            "attacking_ips_caught_share": caught / att_ips if att_ips else 0.0}
    return out


def stage_workload(args):
    clk = Clock()
    t = time.time()
    S = stream()
    sel = load_json("phase3b_selection.json")
    _, alert = load_alerts(S, with_ml=True)
    score_of = {d: sel["chosen"][d]["precision"] for d in alert}
    n_days = int(len(np.unique(S.day[S.val_b])))
    configs = {"rules_v3": {d: p for d, p in alert.items() if d != R.ML}, "rules_v3_plus_ml": alert}
    out = {"half": "val_b", "days": n_days, "incident_score_val_a_precision": score_of,
           "configs": {}}
    for cname, al in configs.items():
        out["configs"][cname] = {}
        for sub in SUBSETS:
            part = S.subsets["val_b"][sub]
            out["configs"][cname][sub] = workload(S, al, part, S.attacking_ips(part), n_days, score_of)
    clk.tick("incidents and budgets on val_b", t)
    out["timings_seconds"] = clk.total()
    save_json("phase3b_workload.json", out)
    for cname, per in out["configs"].items():
        for sub, w in per.items():
            print(f"{cname:18s} {sub:17s} alerts/d {w['alerts_per_day']:>9.0f} inc/d {w['incidents_per_day']:>8.0f} "
                  f"inc prec {w['incident_precision']:.4f} attIPs {w['attacking_ips_flagged']}/{w['attacking_ips']} "
                  f"benIPs {w['benign_ips_flagged']}")
            for B, b in w["budgets"].items():
                print(f"{'':36s} B={B:>5}: taken/d {b['incidents_taken_per_day']:>7.0f} prec "
                      f"{b['incident_precision']:.4f} caught {b['attacking_ips_caught']} "
                      f"({b['attacking_ips_caught_share']:.3f})")


# ── Stage: replay (real agents, no blocking; equivalence per half) ───────────

def stage_replay(args):
    from agents.analysis_agent import AnalysisAgent
    from agents.detection_agent import DetectionAgent
    from agents.response_agent import ResponseAgent
    from eval.harness import NullEmailAlerter, override_config
    clk = Clock()
    t = time.time()
    S = stream()
    _, settings = chosen_settings()
    decision = np.asarray(np.load(ML_DECISION, mmap_mode="r")[:S.n])
    match, alert = load_alerts(S, with_ml=True)
    stamps = S.timestamps()
    users = [str(u) for u in S.user_ids]
    countries = S.df["Country"].astype(str).replace("", "XX").to_numpy(dtype=object)
    devices = S.df["Device Type"].astype(str).replace("", "Unknown").to_numpy(dtype=object)
    status = ["SUCCESS" if ok else "FAILED" for ok in S.success.tolist()]
    clk.tick("load stream, chosen settings, ML decisions", t)

    names = list(R.DETECTORS)
    idx = {d: j for j, d in enumerate(names)}
    got_match = np.zeros((S.n, len(names)), dtype=bool)
    got_alert = np.zeros((S.n, len(names)), dtype=bool)
    got_blocked = np.zeros(S.n, dtype=bool)
    blocks = 0
    scorer = P3.PrecomputedV3Scorer(decision, S.event_id)
    t = time.time()
    with override_config(RULES_MODE="v3", **settings), contextlib.redirect_stdout(io.StringIO()):
        agent = DetectionAgent(anomaly_detector=scorer)
        analysis = AnalysisAgent()
        response = ResponseAgent(email_alerter=NullEmailAlerter())
        ip_names, ipc, uc, ts_ = S.ip_names, S.ip, S.user, S.t
        for i in range(S.n):
            e = {"timestamp": stamps[i], "user": users[uc[i]], "ip": ip_names[ipc[i]],
                 "status": status[i], "country": countries[i], "device_type": devices[i],
                 "asn": int(S.asn[i]), "event_id": int(S.event_id[i])}
            got_blocked[i] = response.block_list.is_blocked(e["ip"], int(ts_[i]))
            det = agent.analyze(e)
            for d in det.matched:
                got_match[i, idx[d]] = True
            for a in det.alerts:
                got_alert[i, idx[a["type"]]] = True
                a["timestamp"] = e["timestamp"]
                response.take_action(analysis.evaluate_alert(a))
                blocks += bool(response.last_response["simulated_block"])
            response.actions_log.clear()
    t_replay = time.time() - t
    clk.tick("real v3 replay (detection + analysis + response), no blocking", t)

    spans = {"dev_train": ~S.val, "val_a": S.val_a, "val_b": S.val_b}
    check, ok = {}, True
    for d in names:
        em = np.zeros(S.n, bool)
        em[match[d]] = True
        ea = np.zeros(S.n, bool)
        ea[alert[d]] = True
        gm, ga = got_match[:, idx[d]], got_alert[:, idx[d]]
        check[d] = {}
        for span, m in spans.items():
            cm, ca = int((em != gm)[m].sum()), int((ea != ga)[m].sum())
            check[d][span] = {"offline_matches": int(em[m].sum()), "replay_matches": int(gm[m].sum()),
                              "match_mismatches": cm, "offline_alerts": int(ea[m].sum()),
                              "replay_alerts": int(ga[m].sum()), "alert_mismatches": ca}
            ok &= cm == 0 and ca == 0
    ok &= blocks == 0 and not got_blocked.any()
    out = {"equivalent": bool(ok), "settings": settings, "blocks_placed": blocks,
           "blocked_source_events": int(got_blocked.sum()),
           "ml_scored_events": int(scorer.i), "events": int(S.n), "per_detector": check,
           "state_sizes_end": agent.state_sizes(),
           "replay_seconds": round(t_replay, 1), "replay_us_per_event": round(1e6 * t_replay / S.n, 1),
           "timings_seconds": clk.total()}
    save_json("phase3b_replay_check.json", out)
    for d in names:
        print(f"{d:26s} " + "  ".join(
            f"{s}: m {c['match_mismatches']} a {c['alert_mismatches']} ({c['replay_alerts']})"
            for s, c in check[d].items()))
    print(f"equivalent={ok} blocks={blocks} blocked_events={int(got_blocked.sum())} "
          f"replay {t_replay:.0f} s")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["select", "confirm", "workload", "replay"])
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)
    return {"select": stage_select, "confirm": stage_confirm, "workload": stage_workload,
            "replay": stage_replay}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
