# backend/eval/phase5.py
"""
Phase 5: incident triage and the graded response policy under
eval/PROTOCOL.md amendment 6. Rules frozen at amendment 3, data/model_v4.pkl
unchanged (no ML alert), so incidents come from the eight rule detectors.
val_a chooses, val_b confirms. The locked test month is never read.

Stages (run from backend/, in order):
  python -m eval.phase5 fit        T3: logistic regression on the dev_train
                                   incidents (labels; amendment 6 exception)
  python -m eval.phase5 select     T0-T3 on val_a (end-of-day budgets, day-
                                   clustered bootstrap); the choice; the
                                   tier rates calibrated on val_a for the
                                   chosen score. No val_b metric.
  python -m eval.phase5 confirm    val_b for all candidates and the tiers,
                                   read from disk
  python -m eval.phase5 response   the deployed causal run over the whole
                                   stream: tiers, blocks, challenges, emails;
                                   response cost per stratum on val_b; rule
                                   detectors on new vs returning attackers
  python -m eval.phase5 store      SQLite alert store cost on a 1-day replay
  python -m eval.phase5 replay     real agents with the new defaults;
                                   equivalence with `response`

Reuses results/phase3b_cache/chosen_rules.npz (frozen rule alerts) and the
d_asn_fail_ratio column of results/phase4_cache/X.npy. Intermediates go to
results/phase5_cache/ (gitignored).
"""

import argparse
import contextlib
import io
import json
import math
import os
import sys
import time
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from agents import triage as TR  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval import phase4 as P4  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402
from ml import features_v4 as F  # noqa: E402

RESULTS = P4.RESULTS
CACHE = os.path.join(RESULTS, "phase5_cache")
save_json, load_json = P4.save_json, P4.load_json

# ── Amendment 6 ──────────────────────────────────────────────────────────────
CANDIDATES = TR.SCORES                      # tie order
BUDGETS = (100, 500, 2000)
SELECT_B = 500
RATES = (5, 10, 20, 50, 100, 200, 300, 500, 1000, 2000, 5000)
BLOCK_BAR, STEP_BAR, STEP_BAR_B = 0.80, 0.2149, 0.1915
MIN_INCIDENTS = 30
BOOT_N, BOOT_SEED, TIE_SEED = 1000, 42, 42
QUEUE_RATE = 500
TTL = 3600
STRATA = ("all", "excl_placeholder", "cold_users", "new_attackers", "returning_attackers")
DETS = R.RULE_DETECTORS
SHIFT = np.int64(1 << 20)


def cpath(name):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, name)


# ── Stream, strata, per-IP daily counters ────────────────────────────────────

def stream():
    S = P3B.stream()
    att_train = np.zeros(S.n_ip, bool)
    att_train[S.ip[:S.n_train][S.truth[:S.n_train]]] = True
    S.att_train = att_train
    returning = att_train[S.ip]
    S.strata = OrderedDict([("all", np.ones(S.n, bool)), ("excl_placeholder", ~S.unknown),
                            ("cold_users", S.cold), ("new_attackers", ~returning),
                            ("returning_attackers", returning)])
    S.key = S.ip * SHIFT + S.day
    S.asn_ratio = asn_ratio(S)
    df = pd.DataFrame({"k": S.key, "f": S.failed.astype(np.int64), "s": S.success.astype(np.int64),
                       "p": S.unknown.astype(np.int64), "a": S.asn_ratio})
    g = df.groupby("k", sort=False)
    S.c_failed = g["f"].cumsum().to_numpy()
    S.c_success = g["s"].cumsum().to_numpy()
    S.c_placeholder = g["p"].cummax().to_numpy()
    S.c_asn_max = g["a"].cummax().to_numpy()
    z = np.load(os.path.join(P3B.CACHE, "chosen_rules.npz"))
    S.rule_alerts = {d: z[f"alert::{d}"] for d in DETS}
    pos = np.concatenate([S.rule_alerts[d] for d in DETS])
    bit = np.concatenate([np.full(len(S.rule_alerts[d]), j, np.int64) for j, d in enumerate(DETS)])
    up, inv = np.unique(pos, return_inverse=True)
    mask = np.zeros(len(up), np.int64)
    np.bitwise_or.at(mask, inv, np.int64(1) << bit)
    S.a_pos, S.a_mask, S.a_cnt = up, mask, np.bincount(inv).astype(np.int64)
    return S


def asn_ratio(S):
    path = cpath("asn_ratio.npy")
    if os.path.exists(path):
        a = np.load(path)
        if len(a) == S.n:
            return a
    X = np.load(os.path.join(P4.CACHE, "X.npy"), mmap_mode="r")
    assert X.shape[0] == S.n
    a = np.ascontiguousarray(X[:, F.FEATURE_NAMES.index("d_asn_fail_ratio")], dtype=np.float64)
    np.save(path, a)
    return a


_LOG1P = {}


def log1p_int(v):
    """math.log1p of non-negative integers, as the live tracker computes it."""
    v = np.asarray(v, np.int64)
    m = int(v.max()) if len(v) else 0
    tab = _LOG1P.get("tab")
    if tab is None or len(tab) <= m:
        tab = _LOG1P["tab"] = np.array([math.log1p(i) for i in range(max(m + 1, 1024))])
    return tab[v]


# ── Incidents and their running scores ───────────────────────────────────────

class Incidents:
    """Rule alerts on events in `part`, grouped per (IP, day), with running
    features at each alerted event and the incidents' final values."""

    def __init__(self, S, part, t3=None):
        sel = part[S.a_pos]
        p = self.p = S.a_pos[sel]
        mask, cnt = S.a_mask[sel], S.a_cnt[sel]
        key = S.key[p]
        ind = ((mask[:, None] >> np.arange(len(DETS))) & 1).astype(np.int64)
        g = pd.DataFrame(ind).groupby(key, sort=False)
        self.ind = g.cummax().to_numpy()
        self.alerts = pd.Series(cnt).groupby(key, sort=False).cumsum().to_numpy()
        self.n_det = self.ind.sum(1)
        self.failed, self.success = S.c_failed[p], S.c_success[p]
        self.placeholder, self.asn = S.c_placeholder[p], S.c_asn_max[p]
        prec = np.array([config.TRIAGE_DETECTOR_PRECISION[d] for d in DETS])
        self.top = np.where(self.ind == 1, prec[None, :], -np.inf).max(1)
        self.uk, self.inc = np.unique(key, return_inverse=True)
        n = self.n_inc = len(self.uk)
        self.ip, self.day = self.uk // SHIFT, self.uk % SHIFT
        self.attack = np.zeros(n, bool)
        np.logical_or.at(self.attack, self.inc, S.truth[p])
        self.last = np.zeros(n, np.int64)
        np.maximum.at(self.last, self.inc, np.arange(len(p)))
        self.t3 = t3

    def features(self):
        """T3 feature matrix at every alerted event (T3_FEATURES order)."""
        cols = [self.ind[:, j].astype(np.float64) for j in range(len(DETS))]
        cols += [self.n_det.astype(np.float64), log1p_int(self.alerts), log1p_int(self.failed),
                 log1p_int(self.success), self.placeholder.astype(np.float64), self.asn]
        return np.column_stack(cols)

    def running(self, name):
        """Running score components at every alerted event (tuple order)."""
        if name == "T0":
            return [self.top, self.n_det.astype(np.float64)]
        if name == "T1":
            return [self.n_det.astype(np.float64), self.asn]
        if name == "T2":
            return [self.top, self.asn]
        return [t3_linear_columns(self.features(), self.t3)]

    def final(self, name):
        return [c[self.last] for c in self.running(name)]


def t3_linear_columns(X, params):
    """agents.triage.t3_linear, column by column (bit-identical)."""
    z = np.full(len(X), params["intercept"], np.float64)
    for j, (m, s, c) in enumerate(zip(params["mean"], params["scale"], params["coef"])):
        z = z + c * ((X[:, j] - m) / s)
    return z


def t3_params():
    path = os.path.join(RESULTS, "phase5_t3.json")
    return load_json("phase5_t3.json")["params"] if os.path.exists(path) else None


# ── End-of-day budgets ───────────────────────────────────────────────────────

def day_bootstrap(x):
    x = np.asarray(x, np.float64)
    if len(x) == 0:
        return 0.0, 0.0
    rng = np.random.default_rng(BOOT_SEED)
    idx = rng.integers(0, len(x), size=(BOOT_N, len(x)))
    lo, hi = np.percentile(x[idx].mean(1), [2.5, 97.5])
    return float(lo), float(hi)


def day_rank(I, comps):
    """Rank of each incident within its day by its final score (ties random,
    default_rng(42), as amendment 3)."""
    n = I.n_inc
    tie = np.random.default_rng(TIE_SEED).random(n)
    order = np.lexsort(tuple([tie] + [-c for c in reversed(comps)] + [I.day]))
    ds = I.day[order]
    starts = np.searchsorted(ds, ds, side="left")
    rank = np.empty(n, np.int64)
    rank[order] = np.arange(n) - starts
    return rank


def budget_metrics(S, I, comps, att):
    rank = day_rank(I, comps)
    days = np.unique(I.day)
    att_n = int(att.sum())
    out = {"incidents": int(I.n_inc), "incidents_per_day": I.n_inc / max(len(days), 1),
           "days": int(len(days)), "attacking_ips": att_n,
           "incident_precision": float(I.attack.mean()) if I.n_inc else 0.0, "budgets": {}}
    for B in BUDGETS:
        take = rank < B
        dp, dc, dn = [], [], []
        for d in days:
            m = take & (I.day == d)
            dn.append(int(m.sum()))
            dp.append(float(I.attack[m].mean()) if m.any() else 0.0)
            dc.append(int(len(np.unique(I.ip[m & I.attack]))))
        lo, hi = day_bootstrap(dp)
        caught = int(len(np.unique(I.ip[take & I.attack])))
        out["budgets"][str(B)] = {
            "incidents_taken": int(take.sum()), "incident_precision": float(I.attack[take].mean()) if take.any() else 0.0,
            "mean_daily_precision": float(np.mean(dp)) if dp else 0.0, "daily_ci_low": lo, "daily_ci_high": hi,
            "mean_daily_attacking_ips_caught": float(np.mean(dc)) if dc else 0.0,
            "attacking_ips_caught": caught, "attacking_ips_caught_share": caught / att_n if att_n else 0.0,
            "daily_precision": dp, "daily_attacking_ips_caught": dc, "daily_taken": dn}
    return out


def candidate_curves(S, half, t3):
    """Budget curves of every candidate in every stratum of a half."""
    out = OrderedDict()
    for name in CANDIDATES:
        if name == "T3" and t3 is None:
            continue
        out[name] = OrderedDict()
        for st, m in S.strata.items():
            part = m & S.halves[half]
            I = Incidents(S, part, t3)
            out[name][st] = budget_metrics(S, I, I.final(name), S.attacking_ips(part))
    return out


def choose(curves):
    """Amendment 6: most mean daily attacking IPs caught at B = 500 on val_a,
    subject to the day-clustered lower bound of mean daily precision >= T0's
    point value; ties to the earlier candidate; none qualifies: T0."""
    bar = curves["T0"]["all"]["budgets"][str(SELECT_B)]["mean_daily_precision"]
    rows = []
    for i, (name, per) in enumerate(curves.items()):
        b = per["all"]["budgets"][str(SELECT_B)]
        rows.append({"candidate": name, "order": i, "qualifies": bool(b["daily_ci_low"] >= bar),
                     "mean_daily_attacking_ips_caught": b["mean_daily_attacking_ips_caught"],
                     "mean_daily_precision": b["mean_daily_precision"],
                     "daily_ci_low": b["daily_ci_low"], "daily_ci_high": b["daily_ci_high"]})
    q = [r for r in rows if r["qualifies"]]
    if q:
        best = max(q, key=lambda r: (r["mean_daily_attacking_ips_caught"], -r["order"]))
        return best["candidate"], True, bar, rows
    return "T0", False, bar, rows


# ── Causal tiers ─────────────────────────────────────────────────────────────

class Causal:
    """The causal rate-based regions of a score over the whole stream (all
    events): running ranks, per-day cutoffs from the previous incident day,
    and per incident the first alerted event in each rate-k region."""

    def __init__(self, S, name, t3):
        I = self.I = Incidents(S, np.ones(S.n, bool), t3)
        run = I.running(name)
        order = np.lexsort(tuple(reversed(run)))
        diff = np.zeros(len(order), bool)
        for c in run:
            cs = c[order]
            diff[1:] |= cs[1:] != cs[:-1]
        rank = np.empty(len(order), np.int64)
        rank[order] = np.cumsum(diff)
        self.rank = rank
        self.run = run
        fin = rank[I.last]
        self.days = np.unique(I.day)
        self.finals_by_day = {}
        o = np.lexsort((-fin, I.day))
        ds = I.day[o]
        for d in self.days:
            lo, hi = np.searchsorted(ds, d, "left"), np.searchsorted(ds, d, "right")
            self.finals_by_day[int(d)] = fin[o[lo:hi]]          # descending
        self._entry = {}

    def cutoff(self, k):
        """Per incident day: the rank cutoff for rate k (ALL -> -1, NONE -> inf)."""
        out = {}
        prev = None
        for d in self.days:
            if prev is None:
                out[int(d)] = np.inf
            else:
                f = self.finals_by_day[prev]
                out[int(d)] = f[k - 1] if len(f) >= k else -1
            prev = int(d)
        return out

    def entry(self, k):
        """Per incident: index (into I.p) of its first alerted event in the
        rate-k region, or -1."""
        if k in self._entry:
            return self._entry[k]
        I = self.I
        cut = self.cutoff(k)
        c_ev = np.array([cut[int(d)] for d in self.days], dtype=np.float64)
        ev_day = I.day[I.inc]
        c_at = c_ev[np.searchsorted(self.days, ev_day)]
        hit = self.rank >= c_at
        e = np.full(I.n_inc, len(I.p), np.int64)
        idx = np.flatnonzero(hit)
        np.minimum.at(e, I.inc[idx], idx)
        e[e == len(I.p)] = -1
        self._entry[k] = e
        return e


def region_metrics(S, I, members, half_mask_inc, strata=True):
    """Incident precision with its IP-clustered interval for the incidents in
    `members` (bool per incident) restricted to a half."""
    m = members & half_mask_inc
    lo, hi = P3B.bootstrap(I.ip[m], I.attack[m])
    out = {"incidents": int(m.sum()), "attack_incidents": int(I.attack[m].sum()),
           "precision": float(I.attack[m].mean()) if m.any() else 0.0, "ci_low": lo, "ci_high": hi,
           "attacking_ips": int(len(np.unique(I.ip[m & I.attack]))),
           "benign_incident_ips": int(len(np.unique(I.ip[m & ~I.attack])))}
    if strata:
        out["strata"] = stratum_breakdown(S, I, m)
    return out


def stratum_breakdown(S, I, m):
    """The same incidents seen through each stratum: an incident is in the
    stratum if one of its alerted events is; attack if one of those is."""
    out = OrderedDict()
    if not hasattr(I, "_strata"):
        I._strata = {}
        for st, sm in S.strata.items():
            ev = sm[I.p]
            has = np.bincount(I.inc, weights=ev, minlength=I.n_inc) > 0
            att = np.bincount(I.inc, weights=ev & S.truth[I.p], minlength=I.n_inc) > 0
            I._strata[st] = (has, att)
    for st in S.strata:
        if st == "all":
            continue
        has, att = I._strata[st]
        mm = m & has
        lo, hi = P3B.bootstrap(I.ip[mm], att[mm])
        out[st] = {"incidents": int(mm.sum()), "precision": float(att[mm].mean()) if mm.any() else 0.0,
                   "ci_low": lo, "ci_high": hi, "attacking_ips": int(len(np.unique(I.ip[mm & att])))}
    return out


def calibrate(S, C):
    """Tier rates on val_a (amendment 6)."""
    I = C.I
    in_a = np.isin(I.day, np.unique(S.day[S.val_a]))
    rows = []
    for k in RATES:
        r = region_metrics(S, I, C.entry(k) >= 0, in_a)
        r["rate"] = k
        r["meets_block"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= BLOCK_BAR)
        rows.append(r)
    kb = max([r["rate"] for r in rows if r["meets_block"]], default=0)
    blocked = C.entry(kb) >= 0 if kb else np.zeros(I.n_inc, bool)
    bands = []
    for k in RATES:
        if k <= kb:
            continue
        r = region_metrics(S, I, (C.entry(k) >= 0) & ~blocked, in_a)
        r["rate"] = k
        r["meets_step_up"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR)
        bands.append(r)
    ks = max([r["rate"] for r in bands if r["meets_step_up"]], default=0)
    return {"block_rate": kb, "step_up_rate": ks, "queue_rate": QUEUE_RATE,
            "region_rows_val_a": rows, "step_up_band_rows_val_a": bands}


# ── Stage: fit (T3) ──────────────────────────────────────────────────────────

def stage_fit(args):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    clk = Clock()
    t = time.time()
    S = stream()
    clk.tick("stream, per-IP daily counters, rule alerts", t)
    t = time.time()
    I = Incidents(S, ~S.val, None)
    X = I.features()[I.last]
    y = I.attack
    sc = StandardScaler().fit(X)
    lr = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000).fit(sc.transform(X), y)
    params = {"features": list(TR.T3_FEATURES), "mean": sc.mean_.tolist(), "scale": sc.scale_.tolist(),
              "coef": lr.coef_[0].tolist(), "intercept": float(lr.intercept_[0])}
    clk.tick("fit T3 on dev_train incidents", t)
    out = {"protocol": "eval/PROTOCOL.md amendment 6, T3 (labels; declared exception)",
           "dev_train_incidents": int(I.n_inc), "dev_train_attack_incidents": int(y.sum()),
           "n_iter": int(lr.n_iter_[0]), "params": params,
           "standardised_coef": dict(zip(TR.T3_FEATURES, lr.coef_[0].tolist())),
           "timings_seconds": clk.total()}
    save_json("phase5_t3.json", out)
    for f, c in out["standardised_coef"].items():
        print(f"{f:40s} {c:+.4f}")
    print(f"incidents {I.n_inc}, attack {int(y.sum())}, iterations {out['n_iter']}")


# ── Stage: select (val_a only) ───────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = stream()
    t3 = t3_params()
    assert t3 is not None, "run `fit` first"
    clk.tick("stream, counters, alerts, T3 params", t)
    t = time.time()
    curves = candidate_curves(S, "val_a", t3)
    clk.tick("budget curves T0-T3 x strata on val_a", t)
    chosen, met, bar, rows = choose(curves)
    t = time.time()
    C = Causal(S, chosen, t3)
    cal = calibrate(S, C)
    clk.tick(f"causal regions and tier calibration ({chosen}) on val_a", t)
    out = {"protocol": "eval/PROTOCOL.md amendment 6", "half": "val_a",
           "bar_T0_mean_daily_precision_B500": bar, "selection_rows": rows,
           "chosen": chosen, "qualifies": met,
           "status": (f"{chosen} chosen: meets the amendment 6 criterion" if met else
                      "no candidate qualifies; T0 kept (amendment 6 fallback)"),
           "tiers": cal, "curves_val_a": curves, "timings_file": "phase5_select_timings.json"}
    save_json("phase5_selection.json", out)
    save_json("phase5_select_timings.json", {"timings_seconds": clk.total()})
    print(f"bar (T0 mean daily precision @500, val_a) {bar:.4f}")
    for r in rows:
        print(f"{r['candidate']}: caught/day {r['mean_daily_attacking_ips_caught']:.1f} prec/day "
              f"{r['mean_daily_precision']:.4f} [{r['daily_ci_low']:.4f}, {r['daily_ci_high']:.4f}] "
              f"{'qualifies' if r['qualifies'] else '-'}")
    print(out["status"])
    for r in cal["region_rows_val_a"]:
        print(f"  region k={r['rate']:>5}: n {r['incidents']:>6} prec {r['precision']:.3f} "
              f"[{r['ci_low']:.3f}, {r['ci_high']:.3f}] att {r['attacking_ips']}")
    for r in cal["step_up_band_rows_val_a"]:
        print(f"  band   k={r['rate']:>5}: n {r['incidents']:>6} prec {r['precision']:.3f} "
              f"[{r['ci_low']:.3f}, {r['ci_high']:.3f}] {'meets' if r['meets_step_up'] else ''}")
    print(f"block rate {cal['block_rate']}, step-up rate {cal['step_up_rate']}, queue {QUEUE_RATE}")


# ── Stage: confirm (val_b, the choice from disk) ─────────────────────────────

def stage_confirm(args):
    clk = Clock()
    t = time.time()
    S = stream()
    sel = load_json("phase5_selection.json")       # fixed on disk
    t3 = t3_params()
    clk.tick("stream and selection", t)
    t = time.time()
    curves = candidate_curves(S, "val_b", t3)
    clk.tick("budget curves T0-T3 x strata on val_b", t)
    bar_b = curves["T0"]["all"]["budgets"][str(SELECT_B)]["mean_daily_precision"]
    ch = sel["chosen"]
    b = curves[ch]["all"]["budgets"][str(SELECT_B)]
    t = time.time()
    C = Causal(S, ch, t3)
    I = C.I
    in_b = np.isin(I.day, np.unique(S.day[S.val_b]))
    tiers = sel["tiers"]
    kb, ks = tiers["block_rate"], tiers["step_up_rate"]
    blk = C.entry(kb) >= 0 if kb else np.zeros(I.n_inc, bool)
    stp = (C.entry(ks) >= 0) & ~blk if ks else np.zeros(I.n_inc, bool)
    q = (C.entry(QUEUE_RATE) >= 0) & ~blk & ~stp
    tier_b = {"block": region_metrics(S, I, blk, in_b), "step_up": region_metrics(S, I, stp, in_b),
              "queue": region_metrics(S, I, q, in_b),
              "log": region_metrics(S, I, ~blk & ~stp & ~q, in_b)}
    for name, r in tier_b.items():
        r["meets_0.80"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= BLOCK_BAR)
        r["meets_0.2149"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR)
        r["meets_0.1915"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR_B)
    clk.tick("tiers on val_b", t)
    out = {"protocol": "eval/PROTOCOL.md amendment 6", "half": "val_b", "chosen": ch,
           "bar_T0_mean_daily_precision_B500_val_b": bar_b,
           "chosen_holds": bool(b["daily_ci_low"] >= bar_b),
           "chosen_meets_val_a_bar": bool(b["daily_ci_low"] >= sel["bar_T0_mean_daily_precision_B500"]),
           "tiers_val_b": tier_b, "curves_val_b": curves, "timings_seconds": clk.total()}
    save_json("phase5_confirm.json", out)
    print(f"val_b bar {bar_b:.4f}; {ch} holds: {out['chosen_holds']}")
    for name, per in curves.items():
        bb = per["all"]["budgets"]
        print(f"{name}: " + "  ".join(f"B{B}: caught/d {v['mean_daily_attacking_ips_caught']:.1f} "
                                      f"prec/d {v['mean_daily_precision']:.3f} [{v['daily_ci_low']:.3f}]"
                                      for B, v in bb.items()))
    for name, r in tier_b.items():
        print(f"  tier {name:8s} n {r['incidents']:>6} prec {r['precision']:.3f} "
              f"[{r['ci_low']:.3f}, {r['ci_high']:.3f}]")


# ── Stage: response (the deployed causal run) ────────────────────────────────

def deployed(S, sel, t3):
    """Per alerted event: running score rank and tier; per event: blocked /
    challenged before it; the email log. Mirrors ResponseAgent (v3)."""
    ch = sel["chosen"]
    tiers = sel["tiers"]
    rates = {"block": tiers["block_rate"], "step_up": tiers["step_up_rate"], "queue": tiers["queue_rate"]}
    C = Causal(S, ch, t3)
    I = C.I
    pos_inc = np.arange(len(I.p))
    tier_ev = np.full(len(I.p), 3, np.int8)               # index into TIERS
    for ti, tier in reversed(list(enumerate(TR.RATED_TIERS))):
        k = rates[tier]
        if not k:
            continue
        e = C.entry(k)
        inside = (e[I.inc] >= 0) & (pos_inc >= e[I.inc])
        tier_ev = np.where(inside, np.int8(ti), tier_ev)
    prev = (pd.Series(tier_ev).groupby(I.inc, sort=False).shift(1)
            .fillna(3).to_numpy().astype(np.int8))
    # placements: block on block-tier alerted events, challenge on step-up
    blocked = before_ttl(S, I.p[tier_ev == 0])
    challenged = before_ttl(S, I.p[tier_ev == 1])
    # emails: first entry into an email tier
    email_idx = [TR.TIERS.index(x) for x in config.EMAIL_TIERS]
    enter = np.isin(tier_ev, email_idx) & ~np.isin(prev, email_idx)
    notifier = TR.IncidentNotifier(_RecordingAlerter())
    outcome = {}
    for j in np.flatnonzero(enter):
        p = int(I.p[j])
        ip = S.ip_names[S.ip[p]]
        inc = {"incident_id": f"{ip}|{int(S.day[p])}", "ip": ip, "tier": TR.TIERS[tier_ev[j]],
               "previous_tier": TR.TIERS[prev[j]]}
        outcome[p] = notifier.notify(inc, int(S.t[p]))
    notifier.flush()
    return {"C": C, "I": I, "tier_ev": tier_ev, "prev_ev": prev, "blocked": blocked,
            "challenged": challenged, "email_outcome": outcome, "email_log": notifier.log,
            "rates": rates}


class _RecordingAlerter:
    enabled = True

    def send_incident(self, incident):
        return True

    def send_digest(self, hour, incidents):
        return True


def before_ttl(S, place_pos):
    """Per event: a placement on its IP at an earlier stream position with
    t_place + TTL > t (BlockList semantics; checked before the event)."""
    pt = np.full(S.n, np.nan)
    pt[place_pos] = S.t[place_pos]
    s = pd.Series(pt)
    g = s.groupby(S.ip, sort=False).shift(1)
    last = g.groupby(S.ip, sort=False).ffill().to_numpy()
    return ~np.isnan(last) & (S.t < last + TTL)


def response_cost(S, D, half="val_b"):
    I = D["I"]
    tier_ev = D["tier_ev"]
    hm = S.halves[half]
    place_b = np.zeros(S.n, bool)
    place_b[I.p[tier_ev == 0]] = True
    place_c = np.zeros(S.n, bool)
    place_c[I.p[tier_ev == 1]] = True
    out = OrderedDict()
    for st, sm in S.strata.items():
        E = sm & hm
        att = S.attacking_ips(E)
        has = np.zeros(S.n_ip, bool)
        has[S.ip[E]] = True
        ben = has & ~att
        r = {"events": int(E.sum()), "attacking_ips": int(att.sum()), "benign_ips": int(ben.sum())}
        for label, under, place in (("block", D["blocked"], place_b),
                                    ("step_up", D["challenged"] & ~D["blocked"], place_c)):
            placed = np.zeros(S.n_ip, bool)
            placed[S.ip[place & hm]] = True
            ev = E & under
            benign_ev = ev & ~S.truth
            legit = benign_ev & ~S.unknown
            r[label] = {
                "legitimate_users_affected": int(len(np.unique(S.user[legit]))),
                "benign_events_affected": int(benign_ev.sum()),
                "benign_successes_affected": int((benign_ev & S.success).sum()),
                "attack_events_affected": int((ev & S.truth).sum()),
                "ips_placed_attacking": int((placed & att).sum()),
                "ips_placed_benign": int((placed & ben).sum()),
                "ips_with_event_affected_attacking": int(len(np.unique(S.ip[ev & S.truth]))),
                "ips_with_event_affected_benign": int(len(np.unique(S.ip[ev][ben[S.ip[ev]]]))),
            }
        out[st] = r
    return out


def email_per_day(S, D):
    per = {}
    for kind, hour, ids, outcome in D["email_log"]:
        if kind == "cooldown":
            continue
        d = int(hour // 24)
        per.setdefault(d, Counter())[kind] += 1
    spans = OrderedDict([("dev_train", ~S.val), ("val_a", S.val_a), ("val_b", S.val_b)])
    out = OrderedDict()
    for span, m in spans.items():
        days = np.unique(S.day[m])
        rows = [{"day": str(np.datetime64(int(d), "D")), "emails": per.get(int(d), Counter())["email"],
                 "digests": per.get(int(d), Counter())["digest"]} for d in days]
        tot = [r["emails"] + r["digests"] for r in rows]
        out[span] = {"days": rows, "mean_per_day": float(np.mean(tot)) if tot else 0.0,
                     "max_per_day": int(max(tot)) if tot else 0}
    c = Counter(o for o in D["email_outcome"].values())
    return out, dict(c)


def detector_new_vs_returning(S):
    out = OrderedDict()
    for half in ("val_a", "val_b"):
        out[half] = OrderedDict()
        for st in ("all", "new_attackers", "returning_attackers"):
            part = S.strata[st] & S.halves[half]
            att = S.attacking_ips(part)
            out[half][st] = {"attacking_ips": int(att.sum()), "detectors": OrderedDict()}
            union = []
            for d in DETS:
                p = S.rule_alerts[d][part[S.rule_alerts[d]]]
                union.append(p)
                y = S.truth[p]
                lo, hi = P3B.bootstrap(S.ip[p], y)
                out[half][st]["detectors"][d] = {
                    "alerts": int(len(p)), "precision": float(y.mean()) if len(p) else 0.0,
                    "ci_low": lo, "ci_high": hi, "attacking_ips_flagged": int(len(np.unique(S.ip[p[y]]))),
                    "benign_ips_flagged": int(len(np.unique(S.ip[p][~att[S.ip[p]]])))}
            u = np.unique(np.concatenate(union))
            out[half][st]["any_rule_attacking_ips_flagged"] = int(len(np.unique(S.ip[u[S.truth[u]]])))
    return out


def stage_response(args):
    clk = Clock()
    t = time.time()
    S = stream()
    sel = load_json("phase5_selection.json")
    t3 = t3_params()
    clk.tick("stream and selection", t)
    t = time.time()
    D = deployed(S, sel, t3)
    clk.tick("deployed causal run (tiers, blocks, challenges, emails)", t)
    t = time.time()
    I = D["I"]
    tier_inc = np.full(I.n_inc, 3, np.int8)
    np.minimum.at(tier_inc, I.inc, D["tier_ev"])
    per_tier = OrderedDict()
    for half in ("val_a", "val_b"):
        in_h = np.isin(I.day, np.unique(S.day[S.halves[half]]))
        n_days = len(np.unique(S.day[S.halves[half]]))
        per_tier[half] = OrderedDict()
        for ti, tier in enumerate(TR.TIERS):
            r = region_metrics(S, I, tier_inc == ti, in_h)
            r["per_day"] = r["incidents"] / n_days
            per_tier[half][tier] = r
    cost = {"val_a": response_cost(S, D, "val_a"), "val_b": response_cost(S, D, "val_b")}
    emails, outcomes = email_per_day(S, D)
    dets = detector_new_vs_returning(S)
    clk.tick("costs, emails, detectors", t)
    np.savez_compressed(cpath("deployed.npz"), p=I.p, tier_ev=D["tier_ev"], prev_ev=D["prev_ev"],
                        rank=D["C"].rank, blocked=D["blocked"], challenged=D["challenged"],
                        **{f"score{j}": c for j, c in enumerate(D["C"].run)})
    with open(cpath("email_log.json"), "w") as f:
        json.dump({"log": D["email_log"], "outcome": {str(k): v for k, v in D["email_outcome"].items()}}, f)
    out = {"protocol": "eval/PROTOCOL.md amendment 6", "chosen": sel["chosen"], "rates": D["rates"],
           "tiers_per_half": per_tier, "response_cost": cost, "emails_per_day": emails,
           "email_outcomes": outcomes, "detectors_new_vs_returning": dets,
           "blocks_placed_events": int((D["tier_ev"] == 0).sum()),
           "challenges_placed_events": int((D["tier_ev"] == 1).sum()),
           "timings_seconds": clk.total()}
    save_json("phase5_response.json", out)
    for half, per in per_tier.items():
        for tier, r in per.items():
            print(f"{half} {tier:8s} {r['per_day']:>8.1f}/day prec {r['precision']:.3f} "
                  f"[{r['ci_low']:.3f}, {r['ci_high']:.3f}]")
    for st, r in cost["val_b"].items():
        print(f"val_b {st:20s} block users {r['block']['legitimate_users_affected']:>6} "
              f"ben IPs {r['block']['ips_placed_benign']:>5} att IPs {r['block']['ips_placed_attacking']:>5} | "
              f"step-up users {r['step_up']['legitimate_users_affected']:>6} ben IPs "
              f"{r['step_up']['ips_placed_benign']:>5} att IPs {r['step_up']['ips_placed_attacking']:>5}")
    for span, e in emails.items():
        print(f"emails {span}: mean {e['mean_per_day']:.1f}/day, max {e['max_per_day']}")
    print("outcomes", outcomes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["fit", "select", "confirm", "response", "store", "replay"])
    ap.add_argument("--day", default="2020-04-20", help="store: the day replayed")
    ap.add_argument("--limit", type=int, default=0, help="replay: first N events only (smoke)")
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)
    stages = {"fit": stage_fit, "select": stage_select, "confirm": stage_confirm,
              "response": stage_response}
    if args.stage in ("store", "replay"):
        from eval import phase5_ops
        stages["store"], stages["replay"] = phase5_ops.stage_store, phase5_ops.stage_replay
    return stages[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
