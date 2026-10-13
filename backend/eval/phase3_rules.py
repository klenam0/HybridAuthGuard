# backend/eval/phase3_rules.py
"""
Phase 3 evaluation of the v3 rule engine (agents/rules_v3.py) under
eval/PROTOCOL.md amendment 2. The locked test month is never read.

One pass over the development stream records, for every event, the window
statistics each v3 detector needs, for every window in the amendment's
grids. Thresholds and alert de-duplication are then applied offline, so a
grid point costs a vectorised comparison plus one pass over its matches,
not a replay. The real v3 agents are replayed once, at the chosen setting,
and must reproduce the offline matches, alerts and blocks exactly.

Stages (run from backend/; each well under 10 minutes):
  python -m eval.phase3_rules select   window statistics, grids, selection
  python -m eval.phase3_rules ml       seed-42 Isolation Forest (Phase 2 design)
                                       refitted; every event scored with the
                                       v3 failed_rate (30-day window)
  python -m eval.phase3_rules replay   real v3 agents (detection, analysis,
                                       response) over the stream; equivalence
  python -m eval.phase3_rules legacy   legacy rules-only replay (per-detector
                                       IP coverage for the comparison)
  python -m eval.phase3_rules report   comparison tables, response cost,
                                       label-noise characterisation
Intermediate arrays: results/phase3_cache/ (gitignored). Results:
results/phase3_selection.json, phase3_ml.json, phase3_replay_check.json,
phase3_legacy_rules.json, phase3_rules_devval.json and
phase3_rules_devval_summary.txt.
"""

import argparse
import contextlib
import io
import json
import os
import sys
import time
from collections import defaultdict, deque

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from eval import datasets  # noqa: E402

RESULTS = os.path.join(BACKEND, "results")
CACHE = os.path.join(RESULTS, "phase3_cache")
TS = datasets.TS
COLS = [TS, "User ID", "IP Address", "Country", "Device Type", "ASN",
        "Login Successful", "Is Attack IP", "Is Account Takeover", "index"]

# ── Amendment 2 ──────────────────────────────────────────────────────────────
GRID = {
    R.BF: {"window": [60, 300, 600, 1800, 3600], "min": [3, 5, 10, 20, 50]},
    R.SLOW: {"window": [3600, 10800, 21600, 43200, 86400], "min": [3, 4, 6, 10, 20],
             "spread": [300, 900, 1800]},
    R.CS: {"window": [300, 1800, 3600, 21600, 86400], "min": [2, 3, 5, 10, 20]},
    R.INVALID: {"window": [300, 1800, 3600, 21600, 86400], "min": [2, 3, 5, 10, 20]},
    R.DIST: {"window": [300, 1800, 3600, 21600, 86400], "min": [2, 3, 5, 10, 20]},
    R.SAF: {"window": [300, 1800, 3600, 21600, 86400], "min": [1, 2, 3, 5, 10]},
    R.MULTI: {"exempt": [(), ("known_ip",), ("same_prefix",), ("same_asn",),
                         ("known_ip", "same_prefix", "same_asn")]},
}
MIN_ALERTS = 30
DEDUP = 3600
OFF_HOURS_DEDUP = 600
KNOWN_IP_TTL = 30 * 86400
MULTI_WINDOW = 120
BLOCK_TTL = 3600
ML_WINDOW_DAYS = 30
SEED, CONTAMINATION = 42, 0.30
PARTS = ("dev_val", "dev_val_excl_placeholder", "dev_val_cold")


def _save_json(name, obj):
    path = os.path.join(RESULTS, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, default=_jsonable)
        f.write("\n")
    return path


def _jsonable(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, tuple):
        return list(o)
    raise TypeError(type(o))


def _load_json(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f)


class Clock:
    def __init__(self):
        self.t0 = time.time()
        self.timings = {}

    def tick(self, name, t):
        self.timings[name] = round(time.time() - t, 1)
        print(f"[{self.timings[name]:7.1f} s] {name}", flush=True)

    def total(self):
        self.timings["total"] = round(time.time() - self.t0, 1)
        return self.timings


# ── The stream as arrays ─────────────────────────────────────────────────────

class Stream:
    """The development stream (dev_train then dev_val) as column arrays."""

    def __init__(self):
        df = datasets.load("dev", columns=COLS)
        n_train = int((df[TS] < datasets.DEV_TRAIN_END).sum())
        limit = int(os.environ.get("PHASE3_LIMIT", "0"))
        if limit:   # smoke test only: first `limit` rows, first half as "train"
            df, n_train = df.iloc[:limit].reset_index(drop=True), limit // 2
        self.df = df
        n = self.n = len(df)
        self.n_train = n_train
        secs = df[TS].to_numpy().astype("datetime64[s]")
        self.t = secs.astype(np.int64)                 # == epoch_seconds(timestamp)
        self.t0 = int(self.t[0])
        assert np.all(np.diff(self.t) >= 0), "stream must be time-ordered"
        self.hour = (self.t // 3600) % 24

        ipcat = df["IP Address"]
        if not isinstance(ipcat.dtype, pd.CategoricalDtype):
            ipcat = ipcat.astype("category")
        self.ip = ipcat.cat.codes.to_numpy().astype(np.int64)
        self.ip_names = ipcat.cat.categories.astype(str).to_numpy(dtype=object)
        assert all(s == s.strip() for s in self.ip_names)
        self.n_ip = len(self.ip_names)

        uid = df["User ID"].to_numpy()
        codes, uniq = pd.factorize(uid)
        self.user = codes.astype(np.int64)
        self.user_ids = uniq
        self.n_user = len(uniq)
        unknown_ids = [int(x) for x in config.UNKNOWN_ACCOUNT_IDS]
        self.unknown = np.isin(uid, unknown_ids)

        ok = df["Login Successful"].to_numpy().astype(bool)
        self.success, self.failed = ok, ~ok
        self.real_fail = self.failed & ~self.unknown
        self.real_succ = self.success & ~self.unknown
        self.truth = (df["Is Attack IP"].to_numpy() | df["Is Account Takeover"].to_numpy()).astype(bool)
        self.asn = df["ASN"].to_numpy().astype(np.int64)
        self.event_id = df["index"].to_numpy().astype(np.int64)

        pos = np.arange(n)
        self.val = pos >= self.n_train
        train_users = np.unique(uid[:self.n_train])
        self.cold = self.val & ~np.isin(uid, train_users)
        self.parts = {
            "dev_val": self.val,
            "dev_val_excl_placeholder": self.val & ~self.unknown,
            "dev_val_cold": self.cold,
        }
        assert not (self.cold & self.unknown).any()
        self.base_rate = float(self.truth[self.val].mean())
        self.threshold = 2 * self.base_rate

    def attacking_ips(self, part):
        """Per IP code: has an attack event inside part."""
        a = np.zeros(self.n_ip, dtype=bool)
        a[self.ip[part & self.truth]] = True
        return a

    def timestamps(self):
        return [s.replace("T", " ") for s in
                np.datetime_as_string(self.t.astype("datetime64[s]"), unit="s")]


# ── Window statistics (vectorised where possible) ────────────────────────────

class Keyed:
    """Positions pos sorted by (key, stream order), for windowed counts."""

    def __init__(self, S, pos, key):
        self.pos = pos
        k = key[pos]
        self.order = np.argsort(k, kind="stable")
        self.ts = (S.t[pos] - S.t0)[self.order]
        self.comp = (k[self.order].astype(np.int64) << 33) + self.ts
        self.rank = np.arange(len(pos))

    def left(self, W):
        return np.searchsorted(self.comp, self.comp - W, side="left")

    def unsort(self, sorted_values, dtype):
        out = np.empty(len(self.pos), dtype=dtype)
        out[self.order] = sorted_values
        return out

    def count_since(self, W):
        """Events of the same key with time >= t - W, up to and including self."""
        lf = self.left(W)
        return self.unsort(self.rank - lf + 1, np.int32), lf

    def spread(self, lf):
        """t - (earliest time inside the window)."""
        return self.unsort(self.ts - self.ts[lf], np.int64)


def failures_before(S, key, W):
    """For each real-account SUCCESS: real failures of the same key with time
    in [t - W, t] earlier in the stream (Success After Failures)."""
    pos = np.flatnonzero(S.real_fail | S.real_succ)
    kd = Keyed(S, pos, key)
    isf = S.real_fail[pos][kd.order].astype(np.int64)
    cum = np.cumsum(isf)
    lf = kd.left(W)
    before = np.where(lf > 0, cum[np.maximum(lf - 1, 0)], 0)
    cnt = kd.unsort(cum - before, np.int32)
    succ = S.real_succ[pos]
    return pos[succ], cnt[succ]


def distinct_counts(S, pos, key, item, windows):
    """Distinct items per key among events with time >= t - W, up to self.
    Mirrors rules_v3.Window(distinct=True); a Python pass per window."""
    keys, items, ts = key[pos].tolist(), item[pos].tolist(), S.t[pos].tolist()
    out = {}
    for W in windows:
        res = np.zeros(len(pos), dtype=np.int32)
        dq, cnt = {}, {}
        for j, (k, it, tt) in enumerate(zip(keys, items, ts)):
            d = dq.get(k)
            if d is None:
                d = dq[k] = deque()
                c = cnt[k] = {}
            else:
                c = cnt[k]
            d.append((tt, it))
            c[it] = c.get(it, 0) + 1
            cut = tt - W
            while d[0][0] < cut:
                _, x = d.popleft()
                v = c[x] - 1
                if v:
                    c[x] = v
                else:
                    del c[x]
            res[j] = len(c)
        out[W] = res
    return out


def emit(S, pos, keys, cooldown):
    """Alert de-duplication: True where a match at pos raises an alert."""
    last = {}
    out = np.zeros(len(pos), dtype=bool)
    for j, (k, tt) in enumerate(zip(keys.tolist(), S.t[pos].tolist())):
        lt = last.get(k)
        if lt is None or tt - lt > cooldown:
            last[k] = tt
            out[j] = True
    return out


def multi_ip_stats(S):
    """Per real-account SUCCESS: the account's previous SUCCESS, and whether
    the current IP had a SUCCESS on the account before (and when)."""
    pos = np.flatnonzero(S.real_succ)
    d = pd.DataFrame({"u": S.user[pos], "ip": S.ip[pos], "t": S.t[pos], "asn": S.asn[pos]})
    g = d.groupby("u", sort=False)
    prev_ip = g["ip"].shift(1).to_numpy()
    prev_t = g["t"].shift(1).to_numpy()
    prev_asn = g["asn"].shift(1).to_numpy()
    prev_pair_t = d.groupby(["u", "ip"], sort=False)["t"].shift(1).to_numpy()
    has_prev = ~np.isnan(prev_t)
    diff = np.abs(d["t"].to_numpy() - np.nan_to_num(prev_t))
    base = has_prev & (d["ip"].to_numpy() != np.nan_to_num(prev_ip, nan=-1)) & (diff < MULTI_WINDOW)
    known = ~np.isnan(prev_pair_t) & (prev_pair_t >= d["t"].to_numpy() - KNOWN_IP_TTL)
    prefix = np.array([R.ip_prefix(s) for s in S.ip_names], dtype=object)
    pfx_codes = pd.factorize(pd.Series([str(p) for p in prefix]))[0]
    cur_p = pfx_codes[d["ip"].to_numpy()]
    prev_p = np.where(has_prev, pfx_codes[np.nan_to_num(prev_ip).astype(np.int64)], -2)
    same_prefix = has_prev & (cur_p == prev_p) & (prefix[d["ip"].to_numpy()] != None)  # noqa: E711
    same_asn = has_prev & (d["asn"].to_numpy() == np.nan_to_num(prev_asn, nan=-1))
    return pos, base, {"known_ip": known, "same_prefix": same_prefix, "same_asn": same_asn}


# ── Metrics ──────────────────────────────────────────────────────────────────

def alert_metrics(S, alert_pos, part, attacking=None):
    """Alerts (one per detector per event) at positions alert_pos, inside part."""
    p = alert_pos[part[alert_pos]]
    y = S.truth[p]
    if attacking is None:
        attacking = S.attacking_ips(part)
    ips = S.ip[p]
    att = np.unique(ips[y])
    ben = np.unique(ips[~attacking[ips]])
    return {"alerts": int(len(p)), "attack_alerts": int(y.sum()),
            "precision": float(y.mean()) if len(p) else 0.0,
            "attacking_ips_flagged": int(len(att)), "benign_ips_flagged": int(len(ben))}


class Detector:
    """Matches and alerts of one detector at one setting, as positions."""

    def __init__(self, name, params, match_pos, key, S, cooldown=DEDUP):
        self.name, self.params = name, params
        self.match_pos = match_pos
        self.alert_pos = match_pos[emit(S, match_pos, key, cooldown)]


def grid_row(S, det):
    m = alert_metrics(S, det.alert_pos, S.val, S._att_val)
    eligible = m["alerts"] >= MIN_ALERTS and m["precision"] >= S.threshold
    return {"params": det.params, **m, "matches_dev_val": int(S.val[det.match_pos].sum()),
            "meets_criterion": bool(eligible), "eligible_alert_count": m["alerts"] >= MIN_ALERTS}


def choose(rows):
    """Amendment 2: max attacking IPs flagged s.t. precision >= 2x base rate
    (and >= MIN_ALERTS alerts); else advisory with the best precision."""
    meet = [r for r in rows if r["meets_criterion"]]
    if meet:
        best = max(enumerate(meet), key=lambda ir: (ir[1]["attacking_ips_flagged"], ir[1]["precision"],
                                                    -ir[1]["alerts"], -ir[0]))[1]
        return best, "meets criterion (may block)"
    pool = [r for r in rows if r["eligible_alert_count"]] or rows
    best = max(enumerate(pool), key=lambda ir: (ir[1]["precision"], ir[1]["attacking_ips_flagged"],
                                                -ir[1]["alerts"], -ir[0]))[1]
    return best, "advisory only (alert, never block)"


# ── Stage: select ────────────────────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = Stream()
    S._att_val = S.attacking_ips(S.val)
    clk.tick("load dev stream", t)
    ip_key, pair = S.ip, S.user * S.n_ip + S.ip
    out = {"base_rate_dev_val": S.base_rate, "precision_threshold": S.threshold,
           "min_alerts": MIN_ALERTS, "grids": {}, "chosen": {}, "status": {}}
    chosen_det = {}

    # Brute Force and Slow Brute Force: real-account failures per IP.
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
    rows = []
    dets = {}
    for W in GRID[R.BF]["window"]:
        for N in GRID[R.BF]["min"]:
            m = rf[bf_cnt[W] >= N]
            d = Detector(R.BF, {"window": W, "min": N}, m, S.ip[m], S)
            rows.append(grid_row(S, d))
            dets[(W, N)] = d
    best, status = choose(rows)
    out["grids"][R.BF], out["chosen"][R.BF], out["status"][R.BF] = rows, best, status
    bw, bn = best["params"]["window"], best["params"]["min"]
    chosen_det[R.BF] = dets[(bw, bn)]
    clk.tick(f"grid Brute Force ({len(rows)} settings)", t)

    t = time.time()
    rows, dets = [], {}
    below = bf_cnt[bw] < bn
    for W in GRID[R.SLOW]["window"]:
        for N in GRID[R.SLOW]["min"]:
            for sp in GRID[R.SLOW]["spread"]:
                m = rf[below & (slow_cnt[W] >= N) & (slow_spread[W] >= sp)]
                d = Detector(R.SLOW, {"window": W, "min": N, "spread": sp}, m, S.ip[m], S)
                rows.append(grid_row(S, d))
                dets[(W, N, sp)] = d
    best, status = choose(rows)
    out["grids"][R.SLOW], out["chosen"][R.SLOW], out["status"][R.SLOW] = rows, best, status
    p = best["params"]
    chosen_det[R.SLOW] = dets[(p["window"], p["min"], p["spread"])]
    clk.tick(f"grid Slow Brute Force ({len(rows)} settings)", t)

    # Invalid Account Spraying: unknown-account attempts per IP.
    t = time.time()
    ua = np.flatnonzero(S.unknown)
    kd_u = Keyed(S, ua, S.ip)
    rows, dets = [], {}
    for W in GRID[R.INVALID]["window"]:
        c, _ = kd_u.count_since(W)
        for N in GRID[R.INVALID]["min"]:
            m = ua[c >= N]
            d = Detector(R.INVALID, {"window": W, "min": N}, m, S.ip[m], S)
            rows.append(grid_row(S, d))
            dets[(W, N)] = d
    best, status = choose(rows)
    out["grids"][R.INVALID], out["chosen"][R.INVALID], out["status"][R.INVALID] = rows, best, status
    chosen_det[R.INVALID] = dets[(best["params"]["window"], best["params"]["min"])]
    clk.tick("grid Invalid Account Spraying", t)

    # Credential Stuffing and Distributed Brute Force: distinct counts.
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
                d = Detector(name, {"window": W, "min": N}, m, k, S)
                rows.append(grid_row(S, d))
                dets[(W, N)] = d
        best, status = choose(rows)
        out["grids"][name], out["chosen"][name], out["status"][name] = rows, best, status
        chosen_det[name] = dets[(best["params"]["window"], best["params"]["min"])]
        clk.tick(f"grid {name}", t)

    # Success After Failures: account or IP branch.
    t = time.time()
    rows, dets = [], {}
    for W in GRID[R.SAF]["window"]:
        sp, acc = failures_before(S, S.user, W)
        sp2, ipc = failures_before(S, S.ip, W)
        assert np.array_equal(sp, sp2)
        for N in GRID[R.SAF]["min"]:
            hit = (acc >= N) | (ipc >= N)
            m = sp[hit]
            d = Detector(R.SAF, {"window": W, "min": N}, m, pair[m], S)
            r = grid_row(S, d)
            r["account_branch_alert_share"] = float(np.mean((acc[hit] >= N)[np.isin(m, d.alert_pos)])) \
                if len(d.alert_pos) else 0.0
            rows.append(r)
            dets[(W, N)] = d
    best, status = choose(rows)
    out["grids"][R.SAF], out["chosen"][R.SAF], out["status"][R.SAF] = rows, best, status
    chosen_det[R.SAF] = dets[(best["params"]["window"], best["params"]["min"])]
    clk.tick("grid Success After Failures", t)

    # Multiple IP Login variants.
    t = time.time()
    mp, base, ex = multi_ip_stats(S)
    rows, dets = [], {}
    for exempt in GRID[R.MULTI]["exempt"]:
        hit = base.copy()
        for e in exempt:
            hit &= ~ex[e]
        m = mp[hit]
        d = Detector(R.MULTI, {"exempt": list(exempt)}, m, pair[m], S)
        rows.append(grid_row(S, d))
        dets[tuple(exempt)] = d
    best, status = choose(rows)
    out["grids"][R.MULTI], out["chosen"][R.MULTI], out["status"][R.MULTI] = rows, best, status
    chosen_det[R.MULTI] = dets[tuple(best["params"]["exempt"])]
    clk.tick("grid Multiple IP Login variants", t)

    # Suspicious Login Time: not tuned.
    t = time.time()
    lo, hi = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
    m = np.flatnonzero(S.success & (S.hour >= lo) & (S.hour <= hi))
    d = Detector(R.OFF_HOURS, {"hours": [lo, hi], "cooldown": OFF_HOURS_DEDUP}, m, S.ip[m], S,
                 cooldown=OFF_HOURS_DEDUP)
    r = grid_row(S, d)
    out["grids"][R.OFF_HOURS] = [r]
    out["chosen"][R.OFF_HOURS] = r
    out["status"][R.OFF_HOURS] = ("not tuned (Phase 4); " + ("meets criterion (may block)"
                                  if r["meets_criterion"] else "advisory only (alert, never block)"))
    chosen_det[R.OFF_HOURS] = d
    clk.tick("Suspicious Login Time", t)

    os.makedirs(CACHE, exist_ok=True)
    arrays = {}
    for name, d in chosen_det.items():
        arrays[f"match::{name}"] = d.match_pos
        arrays[f"alert::{name}"] = d.alert_pos
    np.savez_compressed(os.path.join(CACHE, "chosen_rules.npz"), **arrays)
    out["timings_seconds"] = clk.total()
    _save_json("phase3_selection.json", out)
    for name in out["chosen"]:
        c = out["chosen"][name]
        print(f"{name:26s} {str(c['params']):60s} alerts {c['alerts']:>8} prec {c['precision']:.4f} "
              f"attIPs {c['attacking_ips_flagged']:>6} benIPs {c['benign_ips_flagged']:>7}  "
              f"{out['status'][name]}")


# ── Stage: ml ────────────────────────────────────────────────────────────────

def windowed_failed_rate(S, days):
    """Per event: real failure share of the IP's events (every status, every
    account) in the last `days` calendar days, up to and including the event.
    Mirrors AnomalyDetector._count_windowed on a time-ordered stream."""
    pos = np.arange(S.n)
    kd = Keyed(S, pos, S.ip)
    day = (S.t // 86400)[kd.order]
    k = S.ip[kd.order]
    comp = (k << 33) + day
    lf = np.searchsorted(comp, comp - (days - 1), side="left")
    isf = S.failed[kd.order].astype(np.int64)
    cum = np.cumsum(isf)
    before = np.where(lf > 0, cum[np.maximum(lf - 1, 0)], 0)
    total = np.arange(S.n) - lf + 1
    return kd.unsort((cum - before) / total, np.float64)


def cumulative_failed_rate(S):
    """Lifetime per-IP failed_rate over every event (the Phase 2 IF-only
    features)."""
    s = pd.Series(S.failed.astype(np.int64))
    g = s.groupby(S.ip)
    return (g.cumsum() / (g.cumcount() + 1)).to_numpy()


def raw_features(S, prepared, failed_rate):
    """Vectorised AnomalyDetector._extract_features_v2_frequency for every
    event (checked against eval.harness.build_features in stage ml)."""
    det = prepared.detector()
    df = S.df
    out = np.empty((S.n, 10), dtype=np.float64)
    h = S.hour.astype(np.float64)
    out[:, 0] = np.sin(2 * np.pi * h / 24)
    out[:, 1] = np.cos(2 * np.pi * h / 24)
    out[:, 2] = S.failed
    ipf = np.array([det.ip_freq_map.get(x, 0.0) for x in S.ip_names])
    out[:, 3] = ipf[S.ip]
    uf = np.array([det.user_freq_map.get(str(u), 0.0) for u in S.user_ids])
    out[:, 4] = uf[S.user]
    out[:, 5] = failed_rate
    for col, missing, fmap, j in (("Country", "XX", det.country_freq_map, 6),
                                  ("Device Type", "Unknown", det.device_freq_map, 7)):
        cat = df[col].astype("category")
        names = cat.cat.categories.astype(str).to_numpy(dtype=object)
        names = np.where((names == "") | (names == "nan"), missing, names)
        names = np.array([str(x).strip() for x in names], dtype=object)
        codes = cat.cat.codes.to_numpy()
        vals = np.array([fmap.get(x, 0.0) for x in names] + [fmap.get(missing, 0.0)])
        out[:, j] = vals[np.where(codes < 0, len(names), codes)]
        if col == "Country":
            newc = np.array([int(x not in det.known_countries_set) for x in names]
                            + [int(missing not in det.known_countries_set)])
            out[:, 9] = newc[np.where(codes < 0, len(names), codes)]
    newip = np.array([int(x not in det.known_ips_set) for x in S.ip_names])
    out[:, 8] = newip[S.ip]
    return out


def train_frame(S):
    df, n_train = S.df, S.n_train
    tr = df.iloc[:n_train][~S.truth[:n_train]]
    return pd.DataFrame({
        "Login Timestamp": tr[TS].to_numpy(),
        "User ID": tr["User ID"].to_numpy(),
        "IP Address": tr["IP Address"].astype(str).to_numpy(),
        "Country": tr["Country"].astype(str).replace("", np.nan).to_numpy(),
        "Device Type": tr["Device Type"].astype(str).replace("", np.nan).to_numpy(),
        "Login Successful": tr["Login Successful"].to_numpy(),
    })


def stage_ml(args):
    from sklearn.metrics import roc_auc_score
    from eval import harness, phase2_baseline as P2, streams
    clk = Clock()
    t = time.time()
    S = Stream()
    clk.tick("load dev stream", t)

    t = time.time()
    prepared = P2.Prepared(train_frame(S))
    fr_win = windowed_failed_rate(S, ML_WINDOW_DAYS)
    fr_cum = cumulative_failed_rate(S)
    X_win = raw_features(S, prepared, fr_win)
    clk.tick("frequency maps, scaler, v3 raw features (every event)", t)

    # Check the vectorised features against the harness on a slice.
    t = time.time()
    k = 200_000
    ev_slice, _ = streams.events_from_frame(S.df.iloc[:k])
    ref = harness.build_features(ev_slice, prepared.detector())
    mine = X_win[:k].copy()
    mine[:, 5] = ref[:, 5]                      # harness failed_rate is cumulative over its input
    feat_check = bool(np.array_equal(ref, mine))
    fr_cum_check = bool(np.allclose(ref[:, 5], cumulative_failed_rate_slice(S, k)))
    assert feat_check and fr_cum_check, "vectorised features differ from harness.build_features"
    clk.tick("feature check vs harness.build_features (first 200,000 events)", t)

    t = time.time()
    model, s_train = P2.fit_forest(prepared.X_train, SEED)
    thr = np.percentile(s_train, 100.0 * CONTAMINATION)
    s_win = P2.score_samples(model, prepared.scaler.transform(X_win))
    del X_win
    X_cum = raw_features(S, prepared, fr_cum)
    s_cum = P2.score_samples(model, prepared.scaler.transform(X_cum))
    del X_cum
    clk.tick(f"fit seed {SEED} + score every event twice (v3 and lifetime failed_rate)", t)

    d_win, d_cum = s_win - thr, s_cum - thr
    y = S.truth[S.val]
    p2 = _load_json("phase2_baseline_devval.json")
    p2_auc = p2["per_seed"][0]["if_only"]["dev_val"]["roc_auc"]
    auc_cum = float(roc_auc_score(y, -d_cum[S.val]))
    auc_win = float(roc_auc_score(y, -d_win[S.val]))
    np.save(os.path.join(CACHE, "ml_decision_v3.npy"), d_win)
    diff = ~np.isclose(fr_win, fr_cum)
    flag_win, flag_cum = d_win < min(0.0, config.ML_ALERT_MARGIN), d_cum < min(0.0, config.ML_ALERT_MARGIN)
    out = {
        "seed": SEED, "contamination": CONTAMINATION, "threshold_offset": float(thr),
        "ml_alert_margin": config.ML_ALERT_MARGIN,
        "feature_check_vs_harness_first_200k": feat_check,
        "refit_check": {"phase2_if_only_roc_auc_seed42": p2_auc,
                        "this_refit_lifetime_failed_rate_roc_auc": auc_cum,
                        "match_6dp": round(p2_auc, 6) == round(auc_cum, 6)},
        "v3_failed_rate_roc_auc_dev_val": auc_win,
        "events_with_different_failed_rate": {
            "all": int(diff.sum()), "dev_val": int(diff[S.val].sum()),
            "dev_val_share": float(diff[S.val].mean())},
        "ml_flag_flips_dev_val_vs_lifetime": int((flag_win != flag_cum)[S.val].sum()),
        "timings_seconds": clk.total(),
    }
    _save_json("phase3_ml.json", out)
    print(json.dumps(out, indent=2))


def cumulative_failed_rate_slice(S, k):
    s = pd.Series(S.failed[:k].astype(np.int64))
    g = s.groupby(S.ip[:k])
    return (g.cumsum() / (g.cumcount() + 1)).to_numpy()


# ── Combined v3 results (chosen setting) ─────────────────────────────────────

def chosen_settings():
    sel = _load_json("phase3_selection.json")
    c = sel["chosen"]
    return sel, {
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
        "V3_MULTI_IP_WINDOW_SECONDS": MULTI_WINDOW,
        "V3_MULTI_IP_EXEMPT": tuple(c[R.MULTI]["params"]["exempt"]),
        "V3_KNOWN_IP_TTL_SECONDS": KNOWN_IP_TTL,
        "V3_DEDUP_SECONDS": {"default": DEDUP, R.OFF_HOURS: OFF_HOURS_DEDUP},
        "V3_DUPLICATE_WINDOW_SECONDS": 300,
        "ML_FAILED_RATE_WINDOW_DAYS": ML_WINDOW_DAYS,
        "BLOCK_TTL_SECONDS": BLOCK_TTL,
    }


def load_rule_arrays(S):
    z = np.load(os.path.join(CACHE, "chosen_rules.npz"))
    match = {d: z[f"match::{d}"] for d in R.RULE_DETECTORS}
    alert = {d: z[f"alert::{d}"] for d in R.RULE_DETECTORS}
    return match, alert


def ml_arrays(S, decision):
    m = np.flatnonzero(decision < min(0.0, config.ML_ALERT_MARGIN))
    return m, m[emit(S, m, S.ip[m], DEDUP)]


def block_policy(sel, ml_meets):
    """Interim policy: block only on detectors that met the criterion."""
    blockers = [d for d in R.RULE_DETECTORS if sel["chosen"][d]["meets_criterion"]]
    if ml_meets:
        blockers.append(R.ML)
    return blockers


def blocked_source(S, block_pos, ttl):
    """Per event: its IP is on the block list when the event arrives, i.e. a
    blocking alert on an earlier event of the IP within ttl seconds."""
    bt = np.full(S.n, -np.inf)
    bt[block_pos] = S.t[block_pos]
    order = np.argsort(S.ip, kind="stable")
    k = S.ip[order]
    s = pd.Series(bt[order])
    cm = s.groupby(k).cummax()
    prev = cm.groupby(k).shift(1).fillna(-np.inf).to_numpy()
    out = np.empty(S.n, dtype=bool)
    out[order] = S.t[order] < prev + ttl
    return out


def response_cost(S, block_pos, blocked, part):
    """Blocks placed on dev_val events, on IPs that have an event in part;
    events and users affected inside part."""
    att = S.attacking_ips(part)
    in_part = np.zeros(S.n_ip, dtype=bool)
    in_part[S.ip[part]] = True
    bp = block_pos[S.val[block_pos]]
    bp = bp[in_part[S.ip[bp]]]
    ips = np.unique(S.ip[bp])
    ben = part & ~S.truth & blocked
    users = S.user[ben]
    users = users[~S.unknown[ben]]
    return {
        "blocks_placed": int(len(bp)),
        "benign_ips_blocked": int((~att[ips]).sum()),
        "attack_ips_blocked": int(att[ips].sum()),
        "benign_events_from_blocked_source": int(ben.sum()),
        "benign_successes_from_blocked_source": int((ben & S.success).sum()),
        "attack_events_from_blocked_source": int((part & S.truth & blocked).sum()),
        "legitimate_users_affected": int(len(np.unique(users))),
        "placeholder_benign_events_from_blocked_source": int((ben & S.unknown).sum()),
    }


def config_report(S, alerts, matches, part, block_pos, blocked):
    """Phase 2 style headline for one configuration on part. alerts/matches:
    detector -> positions."""
    att = S.attacking_ips(part)
    alerted = np.zeros(S.n, dtype=bool)
    matched = np.zeros(S.n, dtype=bool)
    all_alert_pos = []
    for d, p in alerts.items():
        alerted[p] = True
        all_alert_pos.append(p)
    for d, p in matches.items():
        matched[p] = True
    all_alert_pos = np.concatenate(all_alert_pos) if all_alert_pos else np.zeros(0, np.int64)
    y = S.truth
    out = {}
    for name, f in (("alerted", alerted), ("detected", matched)):
        pa = part & y
        pb = part & ~y
        fl = part & f
        out[f"{name}_event_recall"] = float(f[pa].mean()) if pa.any() else 0.0
        out[f"{name}_fpr"] = float(f[pb].mean()) if pb.any() else 0.0
        out[f"{name}_event_precision"] = float(y[fl].mean()) if fl.any() else 0.0
        cov = np.unique(S.ip[pa & f])
        out[f"{name}_attacking_ips_flagged"] = int(len(cov))
        out[f"{name}_campaign_coverage"] = float(len(cov) / att.sum()) if att.any() else 0.0
        out[f"{name}_benign_ips_flagged"] = int(len(np.unique(S.ip[fl & ~att[S.ip]])))
        out[f"{name}_events"] = int(fl.sum())
    am = alert_metrics(S, all_alert_pos, part, att)
    out["alerts"] = am["alerts"]
    out["alert_precision"] = am["precision"]
    out["attacking_ips"] = int(att.sum())
    out["per_detector"] = {d: alert_metrics(S, p, part, att) for d, p in alerts.items()}
    for d in out["per_detector"]:
        out["per_detector"][d]["matches"] = int(part[matches[d]].sum())
    out["response"] = response_cost(S, block_pos, blocked, part)
    return out


# ── Stage: replay (real agents, equivalence) ─────────────────────────────────

class PrecomputedV3Scorer:
    """ML step for the real v3 agent: the batch decision of event i, for the
    i-th score_event() call, checked by event_id."""

    def __init__(self, decision, event_ids):
        from ml.anomaly_model import AnomalyDetector
        self.det = AnomalyDetector()
        self.det.feature_count = 10
        self.decision = decision
        self.ids = event_ids
        self.i = 0

    def score_event(self, e):
        i = self.i
        if e.get("event_id") != self.ids[i]:
            raise RuntimeError(f"scorer out of step at {i}: {e.get('event_id')} != {self.ids[i]}")
        self.i += 1
        d = float(self.decision[i])
        return self.det.classify_score(-1 if d < 0 else 1, d)


def stage_replay(args):
    from agents.analysis_agent import AnalysisAgent
    from agents.detection_agent import DetectionAgent
    from agents.response_agent import ResponseAgent
    from eval.harness import NullEmailAlerter, override_config
    clk = Clock()
    t = time.time()
    S = Stream()
    sel, settings = chosen_settings()
    decision = np.load(os.path.join(CACHE, "ml_decision_v3.npy"))
    match, alert = load_rule_arrays(S)
    ml_match, ml_alert = ml_arrays(S, decision)
    ml_meets = alert_metrics(S, ml_alert, S.val)["precision"] >= S.threshold
    blockers = block_policy(sel, ml_meets)
    stamps = S.timestamps()
    users = [str(u) for u in S.user_ids]
    countries = S.df["Country"].astype(str).replace("", "XX").to_numpy(dtype=object)
    devices = S.df["Device Type"].astype(str).replace("", "Unknown").to_numpy(dtype=object)
    status = ["SUCCESS" if ok else "FAILED" for ok in S.success.tolist()]
    clk.tick("load stream, chosen setting, ML decisions", t)

    names = list(R.DETECTORS)
    idx = {d: j for j, d in enumerate(names)}
    got_match = np.zeros((S.n, len(names)), dtype=bool)
    got_alert = np.zeros((S.n, len(names)), dtype=bool)
    got_blocked = np.zeros(S.n, dtype=bool)
    scored = np.zeros(S.n, dtype=bool)
    scorer = PrecomputedV3Scorer(decision, S.event_id)
    sizes_peak = {}
    t = time.time()
    with override_config(RULES_MODE="v3", V3_BLOCK_DETECTORS=tuple(blockers), **settings), \
            contextlib.redirect_stdout(io.StringIO()):
        agent = DetectionAgent(anomaly_detector=scorer)
        analysis = AnalysisAgent()
        response = ResponseAgent(email_alerter=NullEmailAlerter())
        ip_names, ipc, uc, ts_ = S.ip_names, S.ip, S.user, S.t
        for i in range(S.n):
            e = {"timestamp": stamps[i], "user": users[uc[i]], "ip": ip_names[ipc[i]],
                 "status": status[i], "country": countries[i], "device_type": devices[i],
                 "asn": int(S.asn[i]), "event_id": int(S.event_id[i])}
            got_blocked[i] = response.block_list.is_blocked(e["ip"], int(ts_[i]))
            before = scorer.i
            det = agent.analyze(e)
            scored[i] = scorer.i > before
            for d in det.matched:
                got_match[i, idx[d]] = True
            for a in det.alerts:
                got_alert[i, idx[a["type"]]] = True
                a["timestamp"] = e["timestamp"]
                response.take_action(analysis.evaluate_alert(a))
            response.actions_log.clear()
            if i % 500_000 == 0:
                for k, v in agent.state_sizes().items():
                    sizes_peak[k] = max(sizes_peak.get(k, 0), v)
    t_replay = time.time() - t
    clk.tick("real v3 replay (detection + analysis + response) over the dev stream", t)
    sizes_end = agent.state_sizes()

    exp_match = {**match, R.ML: ml_match}
    exp_alert = {**alert, R.ML: ml_alert}
    bpos = np.unique(np.concatenate([exp_alert[d] for d in blockers])) if blockers else np.zeros(0, np.int64)
    exp_blocked = blocked_source(S, bpos, BLOCK_TTL)
    check = {}
    ok = True
    for d in names:
        em = np.zeros(S.n, bool)
        em[exp_match[d]] = True
        ea = np.zeros(S.n, bool)
        ea[exp_alert[d]] = True
        cm = int((em != got_match[:, idx[d]]).sum())
        ca = int((ea != got_alert[:, idx[d]]).sum())
        check[d] = {"offline_matches": int(em.sum()), "replay_matches": int(got_match[:, idx[d]].sum()),
                    "match_mismatches": cm, "offline_alerts": int(ea.sum()),
                    "replay_alerts": int(got_alert[:, idx[d]].sum()), "alert_mismatches": ca}
        ok &= cm == 0 and ca == 0
    bmis = int((exp_blocked != got_blocked).sum())
    ok &= bmis == 0
    reached = scorer.i
    out = {
        "equivalent": bool(ok),
        "settings": settings, "block_detectors": blockers, "ml_meets_criterion": bool(ml_meets),
        "per_detector": check,
        "blocked_source_mismatches": bmis, "blocked_source_events": int(got_blocked.sum()),
        "ml_scored_events": int(reached), "events": int(S.n),
        "attack_events_reaching_ml_share": float(scored[S.truth].mean()),
        "dev_val_attack_events_reaching_ml_share": float(scored[S.truth & S.val].mean()),
        "dev_val_benign_events_reaching_ml_share": float(scored[~S.truth & S.val].mean()),
        "state_sizes_end": sizes_end, "state_sizes_peak_sampled_every_500k": sizes_peak,
        "replay_seconds": round(t_replay, 1),
        "replay_us_per_event": round(1e6 * t_replay / S.n, 1),
        "timings_seconds": clk.total(),
    }
    _save_json("phase3_replay_check.json", out)
    print(json.dumps(out, indent=2, default=_jsonable))
    return 0 if ok else 1


# ── Stage: legacy (rules only, per-detector IP coverage) ─────────────────────

def stage_legacy(args):
    from eval import harness, streams
    clk = Clock()
    t = time.time()
    S = Stream()
    events, truth = streams.events_from_frame(S.df[[TS, "User ID", "IP Address", "Country", "Device Type",
                                                    "Login Successful", "Is Attack IP",
                                                    "Is Account Takeover"]])
    assert np.array_equal(truth, S.truth)
    clk.tick("load stream + events", t)
    t = time.time()
    r = harness.replay(events, None)
    clk.tick("legacy rules-only replay", t)
    del events
    types = np.array([x or "" for x in r.alert_type], dtype=object)
    alerts = {d: np.flatnonzero(types == d) for d in sorted(set(types) - {""})}
    p2 = _load_json("phase2_baseline_devval.json")["rules_only"]
    out = {"per_part": {}, "check_vs_phase2": {}}
    # Legacy blocks never expire (F02): response blocks are the first HIGH
    # alert per IP, from dev_train on.
    resp_first = np.array(sorted(r.response_block_idx.values()), dtype=np.int64)
    first = np.full(S.n_ip, S.n, dtype=np.int64)
    first[S.ip[resp_first]] = resp_first
    blocked = np.arange(S.n) > first[S.ip]
    for part in PARTS:
        rep = config_report(S, alerts, alerts, S.parts[part], resp_first, blocked)
        out["per_part"][part] = rep
        q = p2[part]
        out["check_vs_phase2"][part] = {
            "alerts": [rep["alerts"], q["alerts"]],
            "event_recall": [rep["alerted_event_recall"], q["event_recall"]],
            "fpr": [rep["alerted_fpr"], q["fpr"]],
            "attacking_ips_flagged": [rep["alerted_attacking_ips_flagged"], q["attacking_ips_flagged"]],
            "benign_ips_flagged": [rep["alerted_benign_ips_flagged"], q["benign_ips_flagged"]],
            "users_affected": [rep["response"]["legitimate_users_affected"],
                               q["response_blocks"]["benign_users_affected"]],
        }
    out["timings_seconds"] = clk.total()
    _save_json("phase3_legacy_rules.json", out)
    print(json.dumps(out["check_vs_phase2"], indent=2))


# ── Stage: report ────────────────────────────────────────────────────────────

def label_noise(S, rule_alerts):
    """Among benign dev_val events with a v3 rule alert: share whose IP
    (i) has no successful login in dev, (ii) only attempts the placeholder,
    (iii) tries >= 5 distinct real accounts in dev. Report only."""
    has_succ = np.zeros(S.n_ip, bool)
    has_succ[S.ip[S.success]] = True
    has_real = np.zeros(S.n_ip, bool)
    has_real[S.ip[~S.unknown]] = True
    only_ph = ~has_real
    pairs = np.unique(S.ip[~S.unknown] * np.int64(S.n_user) + S.user[~S.unknown])
    n_acc = np.bincount((pairs // S.n_user).astype(np.int64), minlength=S.n_ip)
    many = n_acc >= 5

    def shares(pos):
        p = np.unique(pos)
        p = p[S.val[p] & ~S.truth[p]]
        ips = S.ip[p]
        u = np.unique(ips)
        f = {"no_success_in_dev": ~has_succ, "only_placeholder": only_ph,
             "five_plus_accounts": many}
        r = {"benign_alerted_events": int(len(p)), "benign_alerted_ips": int(len(u))}
        for k, v in f.items():
            r[f"event_share_{k}"] = float(v[ips].mean()) if len(p) else 0.0
            r[f"ip_share_{k}"] = float(v[u].mean()) if len(u) else 0.0
        anyf = (~has_succ | only_ph | many)
        r["event_share_any"] = float(anyf[ips].mean()) if len(p) else 0.0
        r["ip_share_any"] = float(anyf[u].mean()) if len(u) else 0.0
        return r

    out = {"all_v3_rule_alerts": shares(np.concatenate(list(rule_alerts.values())))}
    for d, p in rule_alerts.items():
        out[d] = shares(p)
    # Reference: the same shares over all benign dev_val events.
    allb = np.flatnonzero(S.val & ~S.truth)
    out["reference_all_benign_dev_val_events"] = shares(allb)
    return out


def stage_report(args):
    clk = Clock()
    t = time.time()
    S = Stream()
    sel, settings = chosen_settings()
    decision = np.load(os.path.join(CACHE, "ml_decision_v3.npy"))
    match, alert = load_rule_arrays(S)
    ml_match, ml_alert = ml_arrays(S, decision)
    ml_val = alert_metrics(S, ml_alert, S.val)
    ml_meets = ml_val["precision"] >= S.threshold and ml_val["alerts"] >= MIN_ALERTS
    blockers = block_policy(sel, ml_meets)
    rule_blockers = [d for d in blockers if d != R.ML]
    clk.tick("load", t)

    t = time.time()
    res = {"settings": settings, "block_detectors": blockers, "base_rate_dev_val": S.base_rate,
           "precision_threshold": S.threshold,
           "ml_alerts_dev_val": ml_val, "ml_meets_criterion": bool(ml_meets),
           "status": sel["status"], "configs": {}}
    for ttl in (BLOCK_TTL, 86400):
        rb = np.unique(np.concatenate([alert[d] for d in rule_blockers])) if rule_blockers else np.zeros(0, np.int64)
        hb = np.unique(np.concatenate([alert[d] for d in rule_blockers]
                                      + ([ml_alert] if ml_meets else []))) if blockers else np.zeros(0, np.int64)
        r_blk, h_blk = blocked_source(S, rb, ttl), blocked_source(S, hb, ttl)
        tag = "" if ttl == BLOCK_TTL else f"_ttl{ttl}"
        res["configs"]["rules_v3" + tag] = {
            p: config_report(S, alert, match, S.parts[p], rb, r_blk) for p in PARTS}
        res["configs"]["hybrid_v3" + tag] = {
            p: config_report(S, {**alert, R.ML: ml_alert}, {**match, R.ML: ml_match},
                             S.parts[p], hb, h_blk) for p in PARTS}
    # The Phase 2 response policy (block on every HIGH, never expiring) is not
    # re-simulated for v3; the TTL rows show the interim policy.
    res["placeholder_dev_val"] = {
        d: alert_metrics(S, p, S.val & S.unknown, S.attacking_ips(S.val))
        for d, p in {**alert, R.ML: ml_alert}.items()}
    res["label_noise"] = label_noise(S, alert)
    res["ml_reach"] = _load_json("phase3_replay_check.json").get("attack_events_reaching_ml_share") \
        if os.path.exists(os.path.join(RESULTS, "phase3_replay_check.json")) else None
    clk.tick("metrics", t)
    res["timings_seconds"] = clk.total()
    _save_json("phase3_rules_devval.json", res)
    write_summary(res)
    print(open(os.path.join(RESULTS, "phase3_rules_devval_summary.txt"), encoding="utf-8").read())


def _f(v):
    return f"{v:.4f}" if isinstance(v, float) else str(v)


def write_summary(res):
    p2 = _load_json("phase2_baseline_devval.json")
    leg = _load_json("phase3_legacy_rules.json")["per_part"]
    L = ["Phase 3 v3 rule engine on dev_val (eval/PROTOCOL.md amendment 2)",
         f"base rate {res['base_rate_dev_val']:.4f}; precision threshold {res['precision_threshold']:.4f}",
         f"block detectors (interim policy, TTL {BLOCK_TTL} s): {res['block_detectors']}",
         f"ML (seed {SEED}, c={CONTAMINATION}) alerts on dev_val: {res['ml_alerts_dev_val']}", ""]
    for part in PARTS:
        L.append(f"[{part}]")
        rows = {
            "legacy rules": leg[part],
            "v3 rules": res["configs"]["rules_v3"][part],
            "v3 hybrid": res["configs"]["hybrid_v3"][part],
        }
        h2 = p2["per_seed"][0]["hybrid"][part]
        keys = ["alerted_event_recall", "alerted_fpr", "alerted_event_precision",
                "alerted_campaign_coverage", "alerted_attacking_ips_flagged",
                "alerted_benign_ips_flagged", "alerts", "alert_precision",
                "detected_event_recall", "detected_fpr", "detected_event_precision",
                "detected_attacking_ips_flagged", "detected_benign_ips_flagged"]
        L.append(f"  {'metric':34s}{'legacy rules':>14s}{'v3 rules':>14s}{'v3 hybrid':>14s}{'P2 hybrid s42':>15s}")
        p2map = {"alerted_event_recall": h2["event_recall"], "alerted_fpr": h2["fpr"],
                 "alerted_event_precision": h2["precision"],
                 "alerted_campaign_coverage": h2["campaign_recall"],
                 "alerted_attacking_ips_flagged": h2["attacking_ips_flagged"],
                 "alerted_benign_ips_flagged": h2["benign_ips_flagged"], "alerts": h2["alerts"],
                 "alert_precision": h2["precision"]}
        for k in keys:
            L.append(f"  {k:34s}" + "".join(f"{_f(r.get(k, '')):>14s}" for r in rows.values())
                     + f"{_f(p2map.get(k, '')):>15s}")
        for k in ("benign_ips_blocked", "attack_ips_blocked", "legitimate_users_affected",
                  "benign_events_from_blocked_source", "attack_events_from_blocked_source"):
            p2k = {"benign_ips_blocked": "benign_ips_blocked", "attack_ips_blocked": "attack_ips_blocked",
                   "legitimate_users_affected": "benign_users_affected",
                   "benign_events_from_blocked_source": "benign_events_after_block"}.get(k)
            L.append(f"  response {k:25s}" + "".join(f"{_f(r['response'][k]):>14s}" for r in rows.values())
                     + f"{_f(h2['response_blocks'].get(p2k, '')) if p2k else '':>15s}")
        L.append("  per detector (alerts, precision, attacking IPs, benign IPs): v3 hybrid")
        for d, m in rows["v3 hybrid"]["per_detector"].items():
            L.append(f"    {d:26s} {m['alerts']:>8} {m['precision']:.4f} {m['attacking_ips_flagged']:>7} "
                     f"{m['benign_ips_flagged']:>8}")
        L.append("  per detector: legacy rules")
        for d, m in rows["legacy rules"]["per_detector"].items():
            L.append(f"    {d:26s} {m['alerts']:>8} {m['precision']:.4f} {m['attacking_ips_flagged']:>7} "
                     f"{m['benign_ips_flagged']:>8}")
        L.append("")
    L.append(f"TTL 86400 s variant, dev_val response: rules {res['configs']['rules_v3_ttl86400']['dev_val']['response']}")
    L.append(f"                                      hybrid {res['configs']['hybrid_v3_ttl86400']['dev_val']['response']}")
    L.append(f"label noise: {json.dumps(res['label_noise']['all_v3_rule_alerts'])}")
    L.append(f"ML reach share (real replay): {res['ml_reach']}")
    L.append(f"timings (s): {res['timings_seconds']}")
    with open(os.path.join(RESULTS, "phase3_rules_devval_summary.txt"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["select", "ml", "replay", "legacy", "report"])
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)
    return {"select": stage_select, "ml": stage_ml, "replay": stage_replay,
            "legacy": stage_legacy, "report": stage_report}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
