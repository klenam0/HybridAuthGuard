# backend/eval/phase4b.py
"""
Phase 4b: the open ML questions from Phase 4, under eval/PROTOCOL.md
amendment 5. Rules frozen, thresholds and criterion as amendment 4; val_a
chooses among the new candidates C1 to C3, val_b confirms. The locked test
month is never read.

Stages (run from backend/, in order):
  python -m eval.phase4b diag        D1: the Phase 2 forest rebuilt with maps
                                     from all dev_train rows (b) and fully
                                     label-free (c); event metrics of (a) and
                                     (b) on both halves, (c) on val_a only.
                                     Also every candidate's dev_train
                                     thresholds. --check-a refits (a) and
                                     checks it against the cached decisions.
  python -m eval.phase4b select      C1 to C3 x thresholds on val_a; the choice.
                                     Never computes a val_b metric.
  python -m eval.phase4b confirm     val_b of the choice and of the best row
                                     of each family, read from disk; D1 (c)
                                     event metrics on val_b
  python -m eval.phase4b supervised  the cached HGB reference scores on cold
                                     IPs, new attackers, excluding the
                                     placeholder (measurement only)

Reuses results/phase4_cache/ (feature matrix, Freeman risks, HGB scores,
thresholds), results/phase3_cache/ml_decision_v3.npy (variant a) and the
frozen rule alerts. New scores go to results/phase4_cache/ (gitignored).
"""

import argparse
import contextlib
import io
import json
import os
import sys
import time
from collections import OrderedDict
from types import SimpleNamespace

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval import phase4 as P4  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402
from ml import features_v4 as F  # noqa: E402

RESULTS, CACHE, cache = P4.RESULTS, P4.CACHE, P4.cache
save_json, load_json = P4.save_json, P4.load_json
QUANTILES, THRESHOLD, MIN_INCIDENTS = P4.QUANTILES, P4.THRESHOLD, P4.MIN_INCIDENTS
D1_VARIANTS = OrderedDict([
    ("a", "maps and fit from non-attack dev_train rows (original, cached)"),
    ("b", "maps from all dev_train rows, fit on non-attack rows"),
    ("c", "maps and fit from all dev_train rows (label-free)"),
])
C3_SCORES = OrderedDict([("asn", ["d_asn_fail_ratio"]), ("ip", ["d_ip_fail_ratio"]),
                         ("max", ["d_asn_fail_ratio", "d_ip_fail_ratio"])])


# ── Candidates (amendment 5 order) ───────────────────────────────────────────

def candidates():
    out = [("C1:phase2_forest_labelfree", "C1", {"with_D": False})]
    for bi, b in enumerate(F.FREEMAN_BETAS):
        out.append((f"C2:freeman_no_placeholder[beta={b:g}]", "C2",
                    {"beta": b, "beta_index": bi, "with_D": False}))
    for k, feats in C3_SCORES.items():
        out.append((f"C3:reputation[{k}]", "C3", {"score": k, "features": feats, "with_D": True}))
    return out


def d1_score(S, v):
    """Variant v of the Phase 2 forest; higher = more suspicious."""
    if v == "a":
        return -np.asarray(np.load(P3B.ML_DECISION, mmap_mode="r")[:S.n], dtype=np.float64)
    return np.load(cache(f"score_p2var_{v}.npy"))


def score(S, name, family, meta):
    if family == "C1":
        return d1_score(S, "c")
    if family == "C2":
        fr = np.load(cache("freeman.npy"), mmap_mode="r")[:S.n, meta["beta_index"]].astype(np.float64)
        return np.where(S.unknown, fr.min(), fr)
    X = np.load(cache("X.npy"), mmap_mode="r")
    cols = [F.FEATURE_NAMES.index(f) for f in meta["features"]]
    return np.asarray(X[:S.n, cols], dtype=np.float64).max(axis=1)


# ── Stage: diag ──────────────────────────────────────────────────────────────

def frame(S, rows):
    """dev_train rows in the old pipeline's column shape (eval/phase3_rules.train_frame)."""
    import pandas as pd
    tr = S.df.iloc[:S.n_train][rows]
    return pd.DataFrame({
        "Login Timestamp": tr[P3.TS].to_numpy(),
        "User ID": tr["User ID"].to_numpy(),
        "IP Address": tr["IP Address"].astype(str).to_numpy(),
        "Country": tr["Country"].astype(str).replace("", np.nan).to_numpy(),
        "Device Type": tr["Device Type"].astype(str).replace("", np.nan).to_numpy(),
        "Login Successful": tr["Login Successful"].to_numpy(),
    })


def prepare(maps_df, fit_df):
    """eval/phase2_baseline.Prepared with the maps and the fit rows from
    separate frames (identical to Prepared when they are the same frame)."""
    from sklearn.preprocessing import StandardScaler
    sys.path.insert(0, os.path.join(BACKEND, "ml"))
    from train_from_dataset import extract_features_freq, fit_frequency_maps
    with contextlib.redirect_stdout(io.StringIO()):
        maps, kip, kc = fit_frequency_maps(maps_df)
        X = extract_features_freq(fit_df, maps, kip, kc)
    scaler = StandardScaler().fit(X)
    det = SimpleNamespace(ip_freq_map=maps["ip"], user_freq_map=maps["user"],
                          country_freq_map=maps["country"], device_freq_map=maps["device"],
                          known_ips_set=kip, known_countries_set=kc)
    return SimpleNamespace(scaler=scaler, X_train=scaler.transform(X), detector=lambda: det,
                           n_map_rows=len(maps_df), n_fit_rows=len(fit_df),
                           n_known_ips=len(kip))


def build_variant(S, v, fr_win):
    from eval import phase2_baseline as P2
    benign = ~S.truth[:S.n_train]
    allr = np.ones(S.n_train, bool)
    maps_rows, fit_rows = {"a": (benign, benign), "b": (allr, benign), "c": (allr, allr)}[v]
    maps_df = frame(S, maps_rows)
    fit_df = maps_df if maps_rows is fit_rows else frame(S, fit_rows)
    prep = prepare(maps_df, fit_df)
    X = P3.raw_features(S, prep, fr_win)
    model, s_train = P2.fit_forest(prep.X_train, P3.SEED)
    s = P2.score_samples(model, prep.scaler.transform(X))
    thr = np.percentile(s_train, 100.0 * P3.CONTAMINATION)
    info = {"map_rows": prep.n_map_rows, "fit_rows": prep.n_fit_rows,
            "known_ips": prep.n_known_ips, "offset_30pct": float(thr)}
    return -s, s - thr, info


def stage_diag(args):
    clk = Clock()
    t = time.time()
    S = P4.stream()
    clk.tick("load stream", t)
    out = load_json("phase4b_diag.json") if os.path.exists(os.path.join(RESULTS, "phase4b_diag.json")) else {}
    out.setdefault("variants", {})
    fr_win = None
    todo = (["a"] if args.check_a else []) + [v for v in args.variants.split(",") if v]
    for v in todo:
        t = time.time()
        if fr_win is None:
            fr_win = P3.windowed_failed_rate(S, P3.ML_WINDOW_DAYS)
        s, decision, info = build_variant(S, v, fr_win)
        if v == "a":
            cached = np.load(P3B.ML_DECISION)[:S.n]
            info["check_vs_cached"] = {"bit_identical": bool(np.array_equal(decision, cached)),
                                       "max_abs_diff": float(np.max(np.abs(decision - cached)))}
            print(f"  (a) refit vs cached decisions: {info['check_vs_cached']}")
        else:
            np.save(cache(f"score_p2var_{v}.npy"), s)
        out["variants"].setdefault(v, {})["build"] = info
        clk.tick(f"D1 variant ({v}): maps, fit, score every event", t)

    # Event metrics: (a), (b) on both halves; (c) on val_a only (amendment 5).
    t = time.time()
    for v in D1_VARIANTS:
        if v != "a" and not os.path.exists(cache(f"score_p2var_{v}.npy")):
            continue
        s = d1_score(S, v)
        halves = ("val_a",) if v == "c" else P3B.HALVES
        out["variants"].setdefault(v, {}).update(
            {"description": D1_VARIANTS[v],
             **{h: P4.event_metrics(S, s, S.halves[h]) for h in halves}})
    clk.tick("D1 event metrics", t)

    # Every candidate's dev_train thresholds (label-free, before select).
    t = time.time()
    thr = {}
    for name, family, meta in candidates():
        if family == "C1" and not os.path.exists(cache("score_p2var_c.npy")):
            continue
        thr[name] = P4.thresholds(score(S, name, family, meta)[:S.n_train])
    save_json("phase4b_thresholds.json", thr)
    clk.tick("candidate thresholds (dev_train quantiles)", t)
    out.setdefault("timings_seconds", {}).update(clk.total())
    save_json("phase4b_diag.json", out)
    for v, r in out["variants"].items():
        print(v, {h: {k: round(x, 4) for k, x in r[h].items()} for h in P3B.HALVES if h in r})


# ── Stage: select (val_a only) ───────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = P4.stream()
    rk = P4.rule_keys(S)
    thr = load_json("phase4b_thresholds.json")
    end = int(S.end_a)                     # never look past val_a
    part = S.val_a
    att = S.attacking_ips(part)
    clk.tick("load stream, frozen rule incidents, thresholds", t)

    t = time.time()
    rows, ev = [], {}
    for name, family, meta in candidates():
        s = score(S, name, family, meta)
        ev[name] = P4.event_metrics(S, s, part)
        for q, th in zip(QUANTILES, thr[name]):
            _, al = P4.ml_alerts(S, s, th, end)
            rows.append({"name": name, "family": family, "kind": "candidate", "meta": meta,
                         "quantile": q, "threshold": th, "order": len(rows),
                         "val_a": P4.ml_metrics(S, al, part, "val_a", rk, att)})
        print(f"  {name:40s} AUC {ev[name]['roc_auc']:.4f} PR {ev[name]['pr_auc']:.4f}", flush=True)
    clk.tick(f"{len(rows)} candidate rows on val_a", t)

    chosen, met = P4.choose(rows)
    best = {f: dict(zip(("row", "meets"), P4.choose([r for r in rows if r["family"] == f])))
            for f in ("C1", "C2", "C3")}
    deployment = {"candidate": {k: chosen[k] for k in ("name", "family", "meta", "quantile", "threshold")},
                  "meets_criterion": met, "alerting": met, "with_D": bool(chosen["meta"]["with_D"]),
                  "status": ("chosen: meets the amendment 4 criterion on val_a (amendment 5 candidates)"
                             if met else "no amendment 5 candidate meets the criterion; the Phase 4 "
                             "fallback stays in model_v4.pkl (alerting = False)")}
    out = {"protocol": "eval/PROTOCOL.md amendment 5", "thresholds_fixed": THRESHOLD,
           "min_incremental_incidents": MIN_INCIDENTS, "quantiles": QUANTILES,
           "base_rate_val_a": S.base["val_a"], "events_val_a": int(part.sum()),
           "attacking_ips_val_a": int(att.sum()), "deployment": deployment, "chosen_row": chosen,
           "best_per_family": best, "n_rows_meeting": int(sum(r["val_a"]["meets_primary"] for r in rows)),
           "event_metrics_val_a": ev, "rows": rows}
    save_json("phase4b_selection.json", out)
    save_json("phase4b_select_timings.json", {"timings_seconds": clk.total()})
    print(f"val_a base rate {S.base['val_a']:.5f}; bar {THRESHOLD['val_a']}; {out['n_rows_meeting']} rows meet")
    print(f"{'CHOSEN' if met else 'BEST LB':15s} {P4.short(chosen)}")
    for f, b in best.items():
        print(f"best {f:10s} {P4.short(b['row'])}")


# ── Stage: confirm (val_b, read from disk) ───────────────────────────────────

def stage_confirm(args):
    clk = Clock()
    t = time.time()
    S = P4.stream()
    rk = P4.rule_keys(S)
    sel = load_json("phase4b_selection.json")      # the choice is fixed on disk
    clk.tick("load stream and selection", t)
    t = time.time()
    rows = OrderedDict([("chosen" if sel["deployment"]["meets_criterion"] else "best_lower_bound",
                         sel["chosen_row"])])
    for f, b in sel["best_per_family"].items():
        rows[f"best_{f}"] = b["row"]
    out = {"protocol": "eval/PROTOCOL.md amendment 5", "base_rate": S.base,
           "thresholds_fixed": THRESHOLD, "deployment": sel["deployment"], "rows": {}}
    for label, r in rows.items():
        b, _, _ = _confirm(S, rk, r)
        out["rows"][label] = {"name": r["name"], "family": r["family"], "quantile": r["quantile"],
                              "threshold": r["threshold"], "with_D": r["meta"]["with_D"],
                              "val_a": r["val_a"], "val_b": b,
                              "event_val_a": sel["event_metrics_val_a"][r["name"]],
                              "event_val_b": P4.event_metrics(S, score(S, r["name"], r["family"], r["meta"]),
                                                              S.val_b)}
    out["d1_c_val_b"] = P4.event_metrics(S, d1_score(S, "c"), S.val_b)
    clk.tick("val_b rows", t)
    out["timings_seconds"] = clk.total()
    save_json("phase4b_confirm.json", out)
    for label, r in out["rows"].items():
        a, b = r["val_a"], r["val_b"]
        print(f"{label:18s} {r['name']:38s} q={r['quantile']:<6g} "
              f"A inc {a['incremental_incidents']:>6} {a['incremental_precision']:.3f} "
              f"[{a['incremental_ci_low']:.3f},{a['incremental_ci_high']:.3f}] att {a['attacking_ips_incremental']:>5} | "
              f"B inc {b['incremental_incidents']:>6} {b['incremental_precision']:.3f} "
              f"[{b['incremental_ci_low']:.3f},{b['incremental_ci_high']:.3f}] att {b['attacking_ips_incremental']:>5} "
              f"holds {b['holds']} (vs 0.2149: {b['meets_val_a_bar']})")
    print("D1 (c) val_b:", out["d1_c_val_b"])


def _confirm(S, rk, row):
    s = score(S, row["name"], row["family"], row["meta"])
    _, al = P4.ml_alerts(S, s, row["threshold"], S.n)
    m = P4.ml_metrics(S, al, S.val_b, "val_b", rk)
    m["holds"] = bool(m["incremental_incidents"] >= MIN_INCIDENTS
                      and m["incremental_ci_low"] >= THRESHOLD["val_b"])
    m["meets_val_a_bar"] = bool(m["incremental_incidents"] >= MIN_INCIDENTS
                                and m["incremental_ci_low"] >= THRESHOLD["val_a"])
    return m, s, al


# ── Stage: supervised (measurement only) ─────────────────────────────────────

def stage_supervised(args):
    clk = Clock()
    t = time.time()
    S = P4.stream()
    rk = P4.rule_keys(S)
    thr = load_json("phase4_thresholds.json")
    sel4 = load_json("phase4_selection.json")
    ref_q = {fs: h["best_row_by_criterion"]["quantile"] for fs, h in sel4["hgb_best"].items()}
    ref_name = {fs: h["name"] for fs, h in sel4["hgb_best"].items()}
    in_train = np.zeros(S.n_ip, bool)
    in_train[S.ip[:S.n_train]] = True
    att_train = np.zeros(S.n_ip, bool)
    att_train[S.ip[:S.n_train][S.truth[:S.n_train]]] = True
    subsets = OrderedDict([("all", np.ones(S.n, bool)), ("cold_ips", ~in_train[S.ip]),
                           ("new_attackers", ~att_train[S.ip]), ("excl_placeholder", ~S.unknown)])
    clk.tick("load stream, subsets", t)
    t = time.time()
    out = {"protocol": "eval/PROTOCOL.md amendment 5 (supervised generalisation, measurement only)",
           "reference_quantiles": ref_q, "reference_settings": ref_name, "subset_sizes": {}, "fits": {}}
    for h, hm in S.halves.items():
        out["subset_sizes"][h] = {}
        for k, m in subsets.items():
            pm = hm & m
            out["subset_sizes"][h][k] = {"events": int(pm.sum()), "attack_events": int(S.truth[pm].sum()),
                                         "base_rate": float(S.truth[pm].mean()),
                                         "attacking_ips": int(S.attacking_ips(pm).sum())}
    for name, _, meta in P4.references():
        fs = meta["feature_set"]
        q = ref_q[fs]
        th = thr[name][QUANTILES.index(q)]
        s = np.load(cache(f"score_{name}.npy"))
        _, al = P4.ml_alerts(S, s, th, S.n)
        res = {"feature_set": fs, "quantile": q, "threshold": th, "is_reference": name == ref_name[fs]}
        for h, hm in S.halves.items():
            res[h] = {k: {**P4.event_metrics(S, s, hm & m), **P4.ml_metrics(S, al, hm & m, h, rk)}
                      for k, m in subsets.items()}
        out["fits"][name] = res
        print(f"  {name:30s} " + " | ".join(
            f"{h} {k} AUC {res[h][k]['roc_auc']:.3f} prec {res[h][k]['ml_alert_precision']:.3f} "
            f"incr {res[h][k]['incremental_precision']:.3f}[{res[h][k]['incremental_ci_low']:.3f}]"
            for h in S.halves for k in ("cold_ips", "new_attackers")), flush=True)
    clk.tick("8 HGB fits x 2 halves x 4 subsets", t)
    out["timings_seconds"] = clk.total()
    save_json("phase4b_supervised.json", out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["diag", "select", "confirm", "supervised"])
    ap.add_argument("--variants", default="b,c", help="diag: D1 variants to build (b, c)")
    ap.add_argument("--check-a", action="store_true", help="diag: refit (a) and compare with the cache")
    args = ap.parse_args()
    os.makedirs(CACHE, exist_ok=True)
    return {"diag": stage_diag, "select": stage_select, "confirm": stage_confirm,
            "supervised": stage_supervised}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
