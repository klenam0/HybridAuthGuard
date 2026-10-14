# backend/eval/lanl_d.py
"""
LANL phase L2, LA3.5 (D): label-free scorers on the LA3.3-filtered dev stream,
with causal state from day 0. No label is used to build or fit anything.

  D1  Isolation Forest (RBA S1 variant (c) construction): features
        hour_sin, hour_cos     sin/cos(2 pi h / 24), h = LA3.4 offset hour
        src_freq, user_freq, dst_freq
                               count / n over all dev_train filtered rows
                               (ml/train_from_dataset.fit_frequency_maps form;
                               unseen value -> 0.0)
        fail_rate_30d          the source computer's FAILED share over its
                               events (unfiltered stream) in the last 30
                               calendar days up to and including the event
                               (eval/phase3_rules.windowed_failed_rate form)
        is_new_src             source computer not in dev_train filtered rows
      StandardScaler and IsolationForest(n_estimators=200, max_samples=100000,
      max_features=1.0, random_state=42) fit on all dev_train filtered rows
      (contamination=0.4 as eval/phase2_baseline.fit_forest; it does not
      affect score_samples). Score = -score_samples.
  D2  1 if (user, src, dst) has not occurred earlier in the filtered stream.
  D3  distinct dst the user reached in [t - 86400, t] (up to and including
      the event) whose first-ever reach by the user is inside that window.
  User = src_user as written (LA3.2).

Stages (run from backend/):
  python -m eval.lanl_d maps                 frequency maps (dev_train)
  python -m eval.lanl_d features [--days]    per-day features, D2, D3, labels
  python -m eval.lanl_d fit                  scaler + forest; model SHA-256
  python -m eval.lanl_d score [--smoke N]    D1 on val_a and val_b
  python -m eval.lanl_d metrics              LA3.6 / LA3.7 on val_a, val_b
Per-day arrays and the model are written under <work>/d/ (outside the repo).
"""

import argparse
import hashlib
import json
import math
import os
import pickle
import sys
import time
from collections import Counter

import numpy as np
import pandas as pd
import pyarrow.compute as pc

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_la3 as L  # noqa: E402
from eval.lanl_a import Codes  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

COLS = ["time", "src_user", "src_computer", "dst_computer", "success"]
FEATURES = ["hour_sin", "hour_cos", "src_freq", "user_freq", "dst_freq", "fail_rate_30d", "is_new_src"]
WIN_DAYS = 30
DAY = 86400
K3 = 1 << 20


def ddir():
    d = L.wpath("d")
    os.makedirs(d, exist_ok=True)
    return d


def dpath(name):
    return os.path.join(ddir(), name)


def parse_days(s):
    a, _, b = s.partition("-")
    return list(range(int(a), int(b or a) + 1))


# ── maps ─────────────────────────────────────────────────────────────────────

def stage_maps(args):
    t0 = time.perf_counter()
    lo, hi = L.split_days()["dev_train"]
    days = [d for d in parse_days(args.days) if lo <= d < hi]
    smoke = days != list(range(lo, hi))
    cnt = {"src": Counter(), "user": Counter(), "dst": Counter()}
    n = 0
    for d in days:
        tbl = L.day_table(d, COLS)
        f = tbl.filter(L.filter_mask(tbl))
        n += f.num_rows
        for k, col in (("src", "src_computer"), ("user", "src_user"), ("dst", "dst_computer")):
            vc = pc.value_counts(pc.utf8_trim_whitespace(f.column(col)))
            for v in vc.to_pylist():
                cnt[k][v["values"]] += v["counts"]
        print(f"day {d:02d}: filtered {f.num_rows}", flush=True)
    maps = {k: {s: c / n for s, c in v.items()} for k, v in cnt.items()}
    out = {"days": days, "dev_train_filtered_rows": n, "distinct": {k: len(v) for k, v in maps.items()},
           "seconds": round(time.perf_counter() - t0, 1), "peak_working_set_bytes": peak_working_set()}
    if smoke:
        out["estimate_dev_train_seconds"] = round(out["seconds"] * (hi - lo) / len(days))
        L.save_json("lanl_d_maps_smoke.json", out)
        print(out)
        return 0
    with open(dpath("maps.pkl"), "wb") as fh:
        pickle.dump({"n": n, "maps": maps}, fh)
    L.save_json("lanl_d_maps.json", out)
    print(out)
    return 0


# ── features (causal, per day) ───────────────────────────────────────────────

class State:
    def __init__(self, maps):
        self.maps = maps
        self.uc, self.cc = Codes(lambda s: str(s).strip()), Codes(lambda s: str(s).strip())
        self.daily = {}                      # day -> (failures per computer code, events per code)
        self.seen3 = np.zeros(0, np.int64)   # D2: (user, src, dst) keys seen
        self.seen2 = np.zeros(0, np.int64)   # D3: (user, dst) keys reached
        self.fr = (np.zeros(0, np.int64),) * 3   # D3: first reaches (user, t, pos) of the last day


def day_features(S, d, offset):
    tbl = L.day_table(d, COLS)
    n = tbl.num_rows
    t = tbl.column("time").to_numpy().astype(np.int64)
    comp_all = S.cc.encode(tbl.column("src_computer"))
    fail_all = pc.equal(tbl.column("success"), "Fail").to_numpy(zero_copy_only=False).astype(np.int64)
    # 30-day windowed failure rate of the source computer (unfiltered stream)
    nc = len(S.cc.names)
    g = pd.DataFrame({"c": comp_all, "f": fail_all}).groupby("c", sort=False)
    cum_f = g["f"].cumsum().to_numpy()
    cum_n = g.cumcount().to_numpy() + 1
    pf, pn = np.zeros(nc, np.int64), np.zeros(nc, np.int64)
    for dd in range(d - (WIN_DAYS - 1), d):
        if dd in S.daily:
            f_, n_ = S.daily[dd]
            pf[:len(f_)] += f_
            pn[:len(n_)] += n_
    rate_all = (pf[comp_all] + cum_f) / (pn[comp_all] + cum_n)
    S.daily[d] = (np.bincount(comp_all, weights=fail_all, minlength=nc).astype(np.int64),
                  np.bincount(comp_all, minlength=nc).astype(np.int64))
    for dd in list(S.daily):
        if dd <= d - WIN_DAYS:
            del S.daily[dd]

    keep = L.filter_mask(tbl)
    rows = np.flatnonzero(keep)
    f = tbl.filter(keep)
    m = len(rows)
    tf = t[rows]
    pos = offset + rows.astype(np.int64)
    src_s = pc.utf8_trim_whitespace(f.column("src_computer"))
    usr_s = pc.utf8_trim_whitespace(f.column("src_user"))
    dst_s = pc.utf8_trim_whitespace(f.column("dst_computer"))
    h = L.offset_hour(tf).astype(np.float64)
    X = np.empty((m, len(FEATURES)), np.float64)
    X[:, 0] = np.sin(2 * np.pi * h / 24)
    X[:, 1] = np.cos(2 * np.pi * h / 24)
    for j, (k, col) in enumerate((("src", src_s), ("user", usr_s), ("dst", dst_s))):
        enc = pc.dictionary_encode(col).combine_chunks()
        vals = np.array([S.maps[k].get(v, 0.0) for v in enc.dictionary.to_pylist()], np.float64)
        X[:, 2 + j] = vals[enc.indices.to_numpy(zero_copy_only=False)]
    X[:, 5] = rate_all[rows]
    enc = pc.dictionary_encode(src_s).combine_chunks()
    newv = np.array([float(v not in S.maps["src"]) for v in enc.dictionary.to_pylist()])
    X[:, 6] = newv[enc.indices.to_numpy(zero_copy_only=False)]

    u = S.uc.encode(usr_s)
    sc = S.cc.encode(src_s)
    dc = S.cc.encode(dst_s)
    # D2 new edge
    k3 = (u << 40) | (sc << 20) | dc
    _, first_idx = np.unique(k3, return_index=True)
    is_first = np.zeros(m, bool)
    is_first[first_idx] = True
    seen = np.isin(k3, S.seen3, assume_unique=False)
    d2 = (is_first & ~seen).astype(np.float64)
    S.seen3 = np.union1d(S.seen3, k3)
    # D3 new destinations in the trailing 24 h
    k2 = (u << 20) | dc
    _, f2 = np.unique(k2, return_index=True)
    first2 = np.zeros(m, bool)
    first2[f2] = True
    reach = first2 & ~np.isin(k2, S.seen2)
    S.seen2 = np.union1d(S.seen2, k2)
    fu = np.concatenate([S.fr[0], u[reach]])
    ft = np.concatenate([S.fr[1], tf[reach]])
    fp = np.concatenate([S.fr[2], pos[reach]])
    o = np.lexsort((fp, fu))
    fu, ft, fp = fu[o], ft[o], fp[o]
    cp = (fu << 32) | fp
    ct = (fu << 32) | ft
    q_lo = np.maximum(tf - DAY, 0)
    d3 = (np.searchsorted(cp, (u << 32) | pos, "right")
          - np.searchsorted(ct, (u << 32) | q_lo, "left")).astype(np.float64)
    keepf = ft >= (tf[-1] if m else 0) - DAY
    S.fr = (fu[keepf], ft[keepf], fp[keepf])
    return {"rows": rows, "pos": pos, "user": u, "X": X, "d2": d2, "d3": d3, "n_day": n}


def stage_features(args):
    with open(dpath("maps.pkl"), "rb") as fh:
        maps = pickle.load(fh)["maps"]
    S = State(maps)
    days = parse_days(args.days)
    assert days[0] == 0, "state is causal from day 0"
    offs = L.day_offsets()
    rt = L.redteam_dev()
    t_all = time.perf_counter()
    per = {}
    for d in days:
        t = time.perf_counter()
        r = day_features(S, d, offs[d])
        tbl = L.day_table(d, ["time", "src_user", "src_computer", "dst_computer"])
        pos_mask, _, pairs = L.label_day(tbl, rt[rt["day"] == d])
        r["y"] = pos_mask[r["rows"]]
        r["pairs_row"] = pairs["row"].to_numpy().astype(np.int64)
        r["pairs_event"] = pairs["event"].to_numpy().astype(np.int64)
        np.savez(dpath(f"day={d:02d}.npz"), **r)
        per[f"{d:02d}"] = {"filtered_rows": int(len(r["rows"])), "positives": int(r["y"].sum()),
                           "seconds": round(time.perf_counter() - t, 1)}
        print(f"day {d:02d}: {per[f'{d:02d}']}", flush=True)
    out = {"days": days, "per_day": per, "seconds": round(time.perf_counter() - t_all, 1),
           "peak_working_set_bytes": peak_working_set(), "features": FEATURES}
    L.save_json("lanl_d_features.json" if len(days) > 1 else f"lanl_d_features_smoke_day{days[-1]}.json", out)
    return 0


# ── fit and score ────────────────────────────────────────────────────────────

def load_X(split):
    lo, hi = L.split_days()[split]
    return np.concatenate([np.load(dpath(f"day={d:02d}.npz"))["X"] for d in range(lo, hi)])


def stage_fit(args):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from eval import phase2_baseline as P2
    t0 = time.perf_counter()
    X = load_X("dev_train")
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    t1 = time.perf_counter()
    model = IsolationForest(contamination=0.4, random_state=42, **P2.FOREST).fit(Xs)
    fit_s = time.perf_counter() - t1
    path = dpath("d1_model.pkl")
    with open(path, "wb") as fh:
        pickle.dump({"scaler": scaler, "model": model, "features": FEATURES}, fh)
    with open(path, "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    out = {"fit_rows": int(len(X)), "features": FEATURES, "forest": {**P2.FOREST, "random_state": 42,
                                                                       "contamination": 0.4},
           "scaler_mean": scaler.mean_.tolist(), "scaler_scale": scaler.scale_.tolist(),
           "model_path": path, "model_sha256": sha, "fit_seconds": round(fit_s, 1),
           "seconds": round(time.perf_counter() - t0, 1), "peak_working_set_bytes": peak_working_set()}
    L.save_json("lanl_d_fit.json", out)
    print(json.dumps(out, indent=1))
    return 0


def stage_score(args):
    from eval import phase2_baseline as P2
    with open(dpath("d1_model.pkl"), "rb") as fh:
        b = pickle.load(fh)
    out = {}
    for split in ("val_a", "val_b"):
        lo, hi = L.split_days()[split]
        t0 = time.perf_counter()
        n_rows = 0
        for d in range(lo, hi):
            z = dict(np.load(dpath(f"day={d:02d}.npz")))
            X = z["X"][:args.smoke] if args.smoke else z["X"]
            s = -P2.score_samples(b["model"], b["scaler"].transform(X))
            n_rows += len(X)
            if args.smoke:
                secs = time.perf_counter() - t0
                n_split = sum(len(np.load(dpath(f"day={x:02d}.npz"))["rows"]) for x in range(lo, hi))
                out[split] = {"smoke_rows": int(len(X)), "seconds": round(secs, 1),
                              "estimate_split_seconds": round(secs * n_split / len(X)),
                              "split_rows": int(n_split)}
                break
            np.save(dpath(f"d1_day={d:02d}.npy"), s)
        if not args.smoke:
            out[split] = {"rows": int(n_rows), "seconds": round(time.perf_counter() - t0, 1)}
        print(split, out[split], flush=True)
    out["peak_working_set_bytes"] = peak_working_set()
    L.save_json("lanl_d_score_smoke.json" if args.smoke else "lanl_d_score.json", out)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["maps", "features", "fit", "score", "metrics"])
    ap.add_argument("--days", default="0-13")
    ap.add_argument("--smoke", type=int, default=0)
    args = ap.parse_args()
    if args.stage == "metrics":
        from eval import lanl_d_metrics
        return lanl_d_metrics.main()
    return {"maps": stage_maps, "features": stage_features, "fit": stage_fit,
            "score": stage_score}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
