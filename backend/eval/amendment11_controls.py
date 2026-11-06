# backend/eval/amendment11_controls.py
"""
Amendment 11 (eval/PROTOCOL.md; post hoc, disclosed). Development data only:
the stream is datasets.load("dev") (February to April 2020 partitions). The
locked May month and every month from June 2020 onward are never read.

  python -m eval.amendment11_controls control   Task A: random persistent
                                                entity label (11.4)
  python -m eval.amendment11_controls real      Task B: interval on L for the
                                                real label from stored dev
                                                scores (11.2), val_b from
                                                phase4b_confirm.json (11.5)
                                                (writes --out, default
                                                amendment11_6_controls.json)
  python -m eval.amendment11_controls matched   amendment 11.6: the
                                                distribution-matched random
                                                label (Task C)
  python -m eval.amendment11_controls prev      Task E: point values of the
                                                11.4 run, copied, not
                                                recomputed

"control" writes results/amendment11_controls.json (key "control"); "real",
"matched" and "prev" write results/amendment11_6_controls.json.
Per-event scores of the rebuilt constructions go to
results/amendment11_cache/ (gitignored).

The constructions mirror eval/phase6_secondary.stage_s1 and
eval/phase4b.build_variant exactly (frame, prepare, raw_features,
phase2_baseline.fit_forest with the S1 forest settings), with the induced
label substituted for Stream.truth when choosing the label-selected rows.
"""

import argparse
import json
import os
import sys
import time
from collections import OrderedDict

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval import phase4b as P4B  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402

RESULTS = P3.RESULTS
OUT = "amendment11_controls.json"
CACHE = os.path.join(RESULTS, "amendment11_cache")
DRAW_SEEDS = (1, 2, 3)
MODEL_SEEDS = (42, 43, 44)
BOOT_SEED, BOOT_N = 42, 1000
HALVES = P3B.HALVES                    # ("val_a", "val_b")
FEATURES = ["hour_sin", "hour_cos", "is_failed", "ip_freq", "user_freq",
            "failed_rate", "country_freq", "device_freq", "is_new_ip", "is_new_country"]


def cpath(name):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, name)


def load_out(name=OUT):
    p = os.path.join(RESULTS, name)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=OrderedDict)
    return OrderedDict()


def save_out(out, name=OUT):
    with open(os.path.join(RESULTS, name), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


# ── Metrics ──────────────────────────────────────────────────────────────────

def metrics(y, x):
    """ROC-AUC and PR-AUC exactly as eval/phase4.event_metrics, any label."""
    from sklearn.metrics import average_precision_score, roc_auc_score
    if y.all() or not y.any():
        return {"roc_auc": None, "pr_auc": None}
    return {"roc_auc": float(roc_auc_score(y, x)), "pr_auc": float(average_precision_score(y, x))}


class WeightedAUC:
    """ROC-AUC (ties averaged, as sklearn) under integer event weights, for
    the cluster bootstrap. Scores are grouped once; each resample costs two
    weighted bincounts."""

    def __init__(self, y, x):
        self.g = np.unique(x, return_inverse=True)[1].ravel()
        self.k = int(self.g.max()) + 1
        self.y = y.astype(np.float64)

    def __call__(self, w):
        P = np.bincount(self.g, weights=w * self.y, minlength=self.k)
        N = np.bincount(self.g, weights=w * (1.0 - self.y), minlength=self.k)
        wp, wn = P.sum(), N.sum()
        if wp == 0 or wn == 0:
            return np.nan
        below = np.cumsum(N) - N
        return float(np.sum(P * (below + 0.5 * N)) / (wp * wn))


def cluster_bootstrap(clusters, y, scores, n=BOOT_N, seed=BOOT_SEED):
    """95% percentile bootstrap, resampling clusters (source addresses) with
    replacement, numpy Generator(PCG64(seed)). The same resamples are used
    for every score in `scores` (paired). Returns per-score arrays of AUC."""
    inv = np.unique(clusters, return_inverse=True)[1].ravel()
    K = int(inv.max()) + 1
    aucs = {k: WeightedAUC(y, x) for k, x in scores.items()}
    rng = np.random.Generator(np.random.PCG64(seed))
    res = {k: np.empty(n) for k in scores}
    for b in range(n):
        mult = np.bincount(rng.integers(0, K, size=K), minlength=K).astype(np.float64)
        w = mult[inv]
        for k, f in aucs.items():
            res[k][b] = f(w)
    return res, K


def pct_interval(v):
    v = v[~np.isnan(v)]
    return {"low": float(np.percentile(v, 2.5)), "high": float(np.percentile(v, 97.5)),
            "valid_resamples": int(len(v))}


def L_of(a, c):
    return (a - c) / (a - 0.5)


# ── Constructions (mirror of phase6_secondary.stage_s1) ──────────────────────

def build(S, maps_rows, fit_rows, fr_win, rows, seeds, clk, tag, check=None):
    """Maps on maps_rows, scaler and forest on fit_rows (dev_train positions);
    returns per-seed scores (higher = more suspicious) on `rows` and info."""
    from eval import phase2_baseline as P2
    t = time.time()
    maps_df = P4B.frame(S, maps_rows)
    fit_df = maps_df if maps_rows is fit_rows else P4B.frame(S, fit_rows)
    prep = P4B.prepare(maps_df, fit_df)
    X = P3.raw_features(S, prep, fr_win)
    Xs = prep.scaler.transform(X[rows])
    det = prep.detector()
    info = OrderedDict([
        ("map_rows", prep.n_map_rows), ("fit_rows", prep.n_fit_rows),
        ("fitted_artefacts", OrderedDict([
            ("ip_freq_map_keys", len(det.ip_freq_map)), ("user_freq_map_keys", len(det.user_freq_map)),
            ("country_freq_map_keys", len(det.country_freq_map)),
            ("device_freq_map_keys", len(det.device_freq_map)),
            ("known_ips_set", len(det.known_ips_set)),
            ("known_countries_set", len(det.known_countries_set)),
            ("standard_scaler", "fit on the fit rows (10 features)"),
            ("isolation_forest", "fit on the scaled fit rows; settings phase2_baseline.FOREST, contamination 0.4"),
        ])),
        ("constant_features_on_fit_rows", [f for f, v in zip(FEATURES, prep.scaler.var_) if v == 0.0]),
        ("fit_row_feature_variance", {f: float(v) for f, v in zip(FEATURES, prep.scaler.var_)}),
    ])
    del X
    clk.tick(f"{tag}: maps, scaler, features", t)
    out = OrderedDict()
    for seed in seeds:
        t = time.time()
        model, s_train = P2.fit_forest(prep.X_train, seed)
        s = -P2.score_samples(model, Xs)
        if check is not None and seed == 42:
            info["check_vs_stored"] = check(s, model, s_train)
        out[seed] = s
        clk.tick(f"{tag} seed {seed}: fit, score {len(rows):,} events", t)
    return out, info


# ── Task A: random persistent entity label ───────────────────────────────────

def stage_control(args):
    clk = Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    n_tr = S.n_train
    rows = np.flatnonzero(S.val)                     # val_a then val_b positions
    half_idx = {h: S.halves[h][rows] for h in HALVES}
    ip_val = S.ip[rows]

    # A1
    train = np.zeros(S.n, bool)
    train[:n_tr] = True
    present = np.zeros(S.n_ip, bool)
    present[S.ip[:n_tr]] = True
    A = S.attacking_ips(train)                       # per IP code
    Nset = present & ~A
    nA, nN = int(A.sum()), int(Nset.sum())
    a1 = OrderedDict([("dev_train_rows", int(n_tr)), ("distinct_addresses", int(present.sum())),
                      ("A_attack_labelled_addresses", nA), ("N_no_attack_labelled_row", nN),
                      ("share_A", nA / (nA + nN)),
                      ("label", "Is Attack IP or Is Account Takeover (Stream.truth)")])
    print("A1", dict(a1), flush=True)

    # A2: N ordered by address string, then Generator(PCG64(seed)).choice
    N_codes = np.flatnonzero(Nset)
    N_codes = N_codes[np.argsort(S.ip_names[N_codes].astype(str), kind="stable")]
    draws = OrderedDict()
    for d in DRAW_SEEDS:
        rng = np.random.Generator(np.random.PCG64(d))
        pick = rng.choice(N_codes, size=nA, replace=False)
        inS = np.zeros(S.n_ip, bool)
        inS[pick] = True
        draws[d] = inS
    a2 = OrderedDict()
    for d, inS in draws.items():
        y = inS[S.ip]
        a2[f"draw_{d}"] = OrderedDict([
            ("sampling_seed", d), ("S_size", int(inS.sum())),
            ("intersection_S_A", int((inS & A).sum())),
            ("S_subset_of_N", bool(not (inS & ~Nset).any())),
            ("induced_rows", {"dev_train": int(y[:n_tr].sum()),
                              **{h: int(y[S.halves[h]].sum()) for h in HALVES}}),
            ("S_addresses_seen", {h: int(np.unique(S.ip[S.halves[h] & y]).size) for h in HALVES}),
            ("first_10_sampled_addresses", [str(x) for x in S.ip_names[pick[:10]]]),
        ])
    print("A2", {k: (v["S_size"], v["intersection_S_A"]) for k, v in a2.items()}, flush=True)

    t = time.time()
    fr_win = P3.windowed_failed_rate(S, P3.ML_WINDOW_DAYS)
    clk.tick("30-day windowed failed_rate over the stream", t)
    allr = np.ones(n_tr, bool)

    # Real construction (a), seed 42: code-path check against the cached
    # Phase 3 decisions, and the real-label known-address count (A7).
    def check_a(s, model, s_train):
        from eval import phase2_baseline as P2
        thr = np.percentile(s_train, 100.0 * P3.CONTAMINATION)
        cached = np.load(P3B.ML_DECISION, mmap_mode="r")[rows]
        d = -s - thr
        return {"vs": "results/phase3_cache/ml_decision_v3.npy on val rows",
                "bit_identical": bool(np.array_equal(d, cached)),
                "max_abs_diff": float(np.max(np.abs(d - cached)))}
    benign = ~S.truth[:n_tr]
    _, info_real_a = build(S, benign, benign, fr_win, rows, (42,), clk, "real (a)", check_a)

    # (c'): label-free, so identical for every draw (and equal to real (c)).
    def check_c(s, model, s_train):
        stored = np.load(P4B.cache("score_p2var_c.npy"), mmap_mode="r")[rows]
        return {"vs": "results/phase4_cache/score_p2var_c.npy on val rows",
                "bit_identical": bool(np.array_equal(s, stored)),
                "max_abs_diff": float(np.max(np.abs(s - stored)))}
    sc_c, info_c = build(S, allr, allr, fr_win, rows, MODEL_SEEDS, clk, "(c')", check_c)
    for seed, s in sc_c.items():
        np.save(cpath(f"c_seed{seed}_val.npy"), s)

    res = OrderedDict()
    for d, inS in draws.items():
        y_all = inS[S.ip]
        y = y_all[rows]
        ind_benign = ~y_all[:n_tr]
        sc_a, info_a = build(S, ind_benign, ind_benign, fr_win, rows, MODEL_SEEDS, clk, f"(a') draw {d}")
        for seed, s in sc_a.items():
            np.save(cpath(f"a_prime_draw{d}_seed{seed}_val.npy"), s)
        r = OrderedDict([("construction_a_prime", info_a)])
        for h in HALVES:
            m = half_idx[h]
            yh = y[m]
            per = OrderedDict()
            for seed in MODEL_SEEDS:
                ma, mc = metrics(yh, sc_a[seed][m]), metrics(yh, sc_c[seed][m])
                per[f"seed_{seed}"] = OrderedDict([
                    ("a_prime", ma), ("c_prime", mc),
                    ("L", L_of(ma["roc_auc"], mc["roc_auc"]) if ma["roc_auc"] is not None else None)])
            Ls = [per[f"seed_{sd}"]["L"] for sd in MODEL_SEEDS]
            t = time.time()
            boot, K = cluster_bootstrap(ip_val[m], yh, {"a_prime": sc_a[42][m], "c_prime": sc_c[42][m]})
            clk.tick(f"draw {d} {h}: cluster bootstrap ({K:,} addresses, {BOOT_N} resamples)", t)
            ci = OrderedDict([("model_seed", 42), ("clusters", K),
                              ("a_prime_roc_auc", pct_interval(boot["a_prime"])),
                              ("c_prime_roc_auc", pct_interval(boot["c_prime"]))])
            # entity-lookup reference on the induced label
            look = inS[ip_val[m]]
            tp = int((look & yh).sum())
            lk = OrderedDict([*metrics(yh, look.astype(np.float64)).items(),
                              ("flagged_events", int(look.sum())), ("true_positives", tp),
                              ("precision_score_1", tp / int(look.sum()) if look.any() else None),
                              ("recall_score_1", tp / int(yh.sum()) if yh.any() else None)])
            r[h] = OrderedDict([
                ("events", int(m.sum())), ("induced_label_events", int(yh.sum())),
                ("induced_label_event_base_rate", float(yh.mean())),
                ("per_model_seed", per),
                ("L_mean_over_model_seeds", float(np.mean(Ls))),
                ("L_per_model_seed", Ls),
                ("interval_seed_42", ci),
                ("entity_lookup_reference", lk),
                ("predictions", OrderedDict([
                    ("1_a_prime_ci_low_gt_0.60", bool(ci["a_prime_roc_auc"]["low"] > 0.60)),
                    ("2_c_prime_ci_contains_0.50", bool(ci["c_prime_roc_auc"]["low"] <= 0.5 <= ci["c_prime_roc_auc"]["high"])),
                    ("3_L_seed_mean_gt_0.85", bool(np.mean(Ls) > 0.85)),
                ])),
            ])
            print(f"draw {d} {h}:", {s: (round(per[s]['a_prime']['roc_auc'], 4), round(per[s]['c_prime']['roc_auc'], 4),
                                         round(per[s]['L'], 4)) for s in per},
                  "CI a'", ci["a_prime_roc_auc"], "CI c'", ci["c_prime_roc_auc"], r[h]["predictions"], flush=True)
        r["fit_time_absence_count"] = OrderedDict([
            ("known_ips_all_dev_train_rows", info_c["fitted_artefacts"]["known_ips_set"]),
            ("known_ips_induced_label_0_rows", info_a["fitted_artefacts"]["known_ips_set"]),
            ("difference", info_c["fitted_artefacts"]["known_ips_set"] - info_a["fitted_artefacts"]["known_ips_set"])])
        res[f"draw_{d}"] = r

    over_draws = OrderedDict((h, {"L_mean_over_draws": float(np.mean(
        [res[f"draw_{d}"][h]["L_mean_over_model_seeds"] for d in DRAW_SEEDS]))}) for h in HALVES)
    preds = OrderedDict()
    for p in ("1_a_prime_ci_low_gt_0.60", "2_c_prime_ci_contains_0.50", "3_L_seed_mean_gt_0.85"):
        preds[p] = OrderedDict((h, OrderedDict((f"draw_{d}", res[f"draw_{d}"][h]["predictions"][p])
                                               for d in DRAW_SEEDS)) for h in HALVES)
        preds[p]["held_all_draws_both_splits"] = all(v for h in HALVES for v in preds[p][h].values())

    out = load_out()
    out["amendment"] = 11
    out["control"] = OrderedDict([
        ("protocol", "eval/PROTOCOL.md amendment 11.4"),
        ("data", "datasets.load('dev'): dev_train, val_a, val_b only"),
        ("sampling", "N ordered by address string; numpy Generator(PCG64(seed)).choice(N, |A|, replace=False)"),
        ("bootstrap", f"{BOOT_N} resamples of source addresses with replacement, Generator(PCG64({BOOT_SEED})), "
                      "same resamples for (a') and (c'); 2.5/97.5 percentiles; AUC ties averaged"),
        ("A1", a1), ("A2", a2),
        ("real_construction_a_seed42", info_real_a),
        ("construction_c_prime", info_c),
        ("draws", res), ("over_draws", over_draws), ("predictions", preds),
        ("real_label_fit_time_absence_count", OrderedDict([
            ("known_ips_all_dev_train_rows", info_c["fitted_artefacts"]["known_ips_set"]),
            ("known_ips_label_0_rows", info_real_a["fitted_artefacts"]["known_ips_set"]),
            ("difference", info_c["fitted_artefacts"]["known_ips_set"] - info_real_a["fitted_artefacts"]["known_ips_set"]),
            ("code_path", "phase4b.prepare -> train_from_dataset.fit_frequency_maps, len(known_ips_set)")])),
        ("timings_seconds", clk.total()),
    ])
    save_out(out)
    print("predictions", json.dumps(preds, indent=1))


# ── Task B: the real label ───────────────────────────────────────────────────

def stage_real(args):
    clk = Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    diag = P3B.load_json("phase4b_diag.json")["variants"]
    confirm = P3B.load_json("phase4b_confirm.json")
    stored = OrderedDict([
        ("a", ("results/phase3_cache/ml_decision_v3.npy", -np.asarray(np.load(P3B.ML_DECISION, mmap_mode="r")[:S.n], np.float64))),
        ("b", ("results/phase4_cache/score_p2var_b.npy", np.load(P4B.cache("score_p2var_b.npy")))),
        ("c", ("results/phase4_cache/score_p2var_c.npy", np.load(P4B.cache("score_p2var_c.npy")))),
    ])
    res = OrderedDict()
    for h in HALVES:
        m = S.halves[h]
        y = S.truth[m]
        recomputed = {v: metrics(y, x[m])["roc_auc"] for v, (_, x) in stored.items()}
        ref = {"a": (diag["a"][h]["roc_auc"], f"phase4b_diag.json variants/a/{h}/roc_auc"),
               "b": (diag["b"][h]["roc_auc"], f"phase4b_diag.json variants/b/{h}/roc_auc")}
        ref["c"] = ((diag["c"]["val_a"]["roc_auc"], "phase4b_diag.json variants/c/val_a/roc_auc") if h == "val_a"
                    else (confirm["d1_c_val_b"]["roc_auc"], "phase4b_confirm.json d1_c_val_b/roc_auc"))
        A = {v: ref[v][0] for v in ref}
        t = time.time()
        boot, K = cluster_bootstrap(S.ip[m], y, {v: x[m] for v, (_, x) in stored.items()})
        clk.tick(f"{h}: cluster bootstrap ({K:,} addresses, {BOOT_N} resamples)", t)
        Lb = L_of(boot["a"], boot["c"])
        ci_a = pct_interval(boot["a"])
        res[h] = OrderedDict([
            ("events", int(m.sum())), ("base_rate", float(y.mean())),
            ("roc_auc_stored", OrderedDict((v, {"value": A[v], "source": ref[v][1]}) for v in A)),
            ("roc_auc_recomputed_from_per_event_scores", recomputed),
            ("recomputed_equals_stored", {v: recomputed[v] == A[v] for v in A}),
            ("share_b", (A["b"] - 0.5) / (A["a"] - 0.5)),
            ("share_c", (A["c"] - 0.5) / (A["a"] - 0.5)),
            ("L", L_of(A["a"], A["c"])),
            ("model_seed", 42),
            ("interval", OrderedDict([
                ("clusters", K),
                ("roc_auc_a", ci_a), ("roc_auc_b", pct_interval(boot["b"])), ("roc_auc_c", pct_interval(boot["c"])),
                ("domain_condition_ci_low_a_gt_0.55", bool(ci_a["low"] > 0.55)),
                ("L", pct_interval(Lb) if ci_a["low"] > 0.55 else None)])),
        ])
        print(h, json.dumps(res[h], indent=1), flush=True)
    out = load_out(args.out)
    out.setdefault("amendment", 11)
    out["real"] = OrderedDict([
        ("protocol", "eval/PROTOCOL.md amendment 11.2 and 11.5"),
        ("per_event_scores", OrderedDict((v, p) for v, (p, _) in stored.items())),
        ("score_note", "(a) = -decision of the cached Phase 3 forest (seed 42); a constant shift of -score, "
                       "so the ranking equals -score_samples"),
        ("bootstrap", f"{BOOT_N} resamples of source addresses with replacement, Generator(PCG64({BOOT_SEED})), "
                      "same resamples for (a), (b), (c); L recomputed on each resample"),
        ("halves", res), ("timings_seconds", clk.total())])
    save_out(out, args.out)


# ── Amendment 11.6: distribution-matched random label ───────────────────────

OUT_116 = "amendment11_6_controls.json"
MATCHED_DRAW_SEEDS = (11, 12, 13)
BINS = [(1, 1), (2, 2), (3, 5), (6, 10), (11, 20), (21, 50), (51, 100), (101, 500), (501, None)]
STOP_C_LOW = 0.60


def bin_label(lo, hi):
    return f"{lo}" if hi == lo else (f"{lo}+" if hi is None else f"{lo}-{hi}")


def bin_of(rows_per_ip):
    """Bin index (0..8) per address code; -1 for addresses with no dev_train row."""
    b = np.full(len(rows_per_ip), -1, np.int64)
    for i, (lo, hi) in enumerate(BINS):
        b[(rows_per_ip >= lo) & ((rows_per_ip <= hi) if hi is not None else True)] = i
    return b


def distribution(codes, rows_per_ip, n_tr):
    r = rows_per_ip[codes]
    b = bin_of(rows_per_ip)[codes]
    return OrderedDict([
        ("addresses", int(len(codes))), ("dev_train_rows", int(r.sum())),
        ("share_of_dev_train_rows", float(r.sum() / n_tr)),
        ("addresses_per_bin", OrderedDict((bin_label(*BINS[i]), int((b == i).sum())) for i in range(len(BINS)))),
        ("rows_per_bin", OrderedDict((bin_label(*BINS[i]), int(r[b == i].sum())) for i in range(len(BINS)))),
        ("rows_per_address", OrderedDict([("min", int(r.min())), ("p25", float(np.percentile(r, 25))),
                                          ("median", float(np.median(r))), ("mean", float(r.mean())),
                                          ("p75", float(np.percentile(r, 75))), ("p99", float(np.percentile(r, 99))),
                                          ("max", int(r.max()))])),
    ])


def matched_draw(seed, need_per_bin, pools):
    """11.6 draw: bins from the highest down; a bin short of addresses gives
    all it has and its shortfall is added to the next lower bin. One
    Generator(PCG64(seed)) is used across the bins in that order. Pools are
    ordered by address string."""
    rng = np.random.Generator(np.random.PCG64(seed))
    picked, log, carry = [], [], 0
    for i in reversed(range(len(BINS))):
        need = int(need_per_bin[i]) + carry
        pool = pools[i]
        if need == 0:
            carry = 0
            continue
        if len(pool) < need:
            picked.append(pool)
            carry = need - len(pool)
            log.append({"bin": bin_label(*BINS[i]), "required": need, "available": int(len(pool)),
                        "shortfall_moved_to_next_lower_bin": carry})
        else:
            picked.append(rng.choice(pool, size=need, replace=False))
            carry = 0
    return np.concatenate(picked), log, carry


def artefact_info(prep, det):
    return OrderedDict([
        ("map_rows", prep.n_map_rows), ("fit_rows", prep.n_fit_rows),
        ("fitted_artefacts", OrderedDict([
            ("ip_freq_map_keys", len(det.ip_freq_map)), ("user_freq_map_keys", len(det.user_freq_map)),
            ("country_freq_map_keys", len(det.country_freq_map)),
            ("device_freq_map_keys", len(det.device_freq_map)),
            ("known_ips_set", len(det.known_ips_set)),
            ("known_countries_set", len(det.known_countries_set)),
            ("standard_scaler", "fit on the fit rows (10 features)"),
            ("isolation_forest", "fit on the scaled fit rows; settings phase2_baseline.FOREST, contamination 0.4"),
        ])),
        ("constant_features_on_fit_rows", [f for f, v in zip(FEATURES, prep.scaler.var_) if v == 0.0]),
        ("fit_row_feature_variance", {f: float(v) for f, v in zip(FEATURES, prep.scaler.var_)}),
    ])


def score_split(m, y_rows, ip_val, sc_a, sc_c):
    """Per-seed metrics, L, and the 11.4 interval (model seed 42) on one split."""
    yh = y_rows[m]
    per = OrderedDict()
    for seed in MODEL_SEEDS:
        ma, mc = metrics(yh, sc_a[seed][m]), metrics(yh, sc_c[seed][m])
        per[f"seed_{seed}"] = OrderedDict([("a_prime", ma), ("c_prime", mc),
                                           ("L", L_of(ma["roc_auc"], mc["roc_auc"]))])
    Ls = [per[f"seed_{sd}"]["L"] for sd in MODEL_SEEDS]
    boot, K = cluster_bootstrap(ip_val[m], yh, {"a_prime": sc_a[42][m], "c_prime": sc_c[42][m]})
    ci = OrderedDict([("model_seed", 42), ("clusters", K),
                      ("a_prime_roc_auc", pct_interval(boot["a_prime"])),
                      ("c_prime_roc_auc", pct_interval(boot["c_prime"]))])
    return OrderedDict([
        ("events", int(m.sum())), ("induced_label_events", int(yh.sum())),
        ("induced_label_event_base_rate", float(yh.mean())),
        ("per_model_seed", per), ("L_per_model_seed", Ls),
        ("L_mean_over_model_seeds", float(np.mean(Ls))),
        ("interval_seed_42", ci),
        ("predictions", OrderedDict([
            ("1_a_prime_ci_low_gt_0.70", bool(ci["a_prime_roc_auc"]["low"] > 0.70)),
            ("2_L_seed_mean_gt_0.85", bool(np.mean(Ls) > 0.85))])),
        ("stop_condition_c_prime_ci_low_gt_0.60", bool(ci["c_prime_roc_auc"]["low"] > STOP_C_LOW)),
    ])


def stage_matched(args):
    from eval import phase2_baseline as P2
    clk = Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    n_tr = S.n_train
    rows = np.flatnonzero(S.val)
    half_idx = {h: S.halves[h][rows] for h in HALVES}
    ip_val = S.ip[rows]

    # C1
    rows_per_ip = np.bincount(S.ip[:n_tr], minlength=S.n_ip)
    present = rows_per_ip > 0
    train = np.zeros(S.n, bool)
    train[:n_tr] = True
    A = S.attacking_ips(train)
    pool_mask = present & ~A
    real = distribution(np.flatnonzero(A), rows_per_ip, n_tr)
    real["attack_labelled_rows"] = int(S.truth[:n_tr].sum())
    real["share_of_dev_train_rows_attack_labelled"] = float(S.truth[:n_tr].mean())
    pool = distribution(np.flatnonzero(pool_mask), rows_per_ip, n_tr)
    p = real["share_of_dev_train_rows"]
    c1 = OrderedDict([("bins", [bin_label(*b) for b in BINS]), ("dev_train_rows", int(n_tr)),
                      ("real_attack_set", real), ("non_attack_pool", pool), ("p", p),
                      ("p_definition", "dev_train rows (all, labelled or not) of the real attack-labelled "
                                       "addresses / dev_train rows")])
    print("C1", json.dumps(c1, indent=1), flush=True)

    # C2
    b = bin_of(rows_per_ip)
    order = np.argsort(S.ip_names.astype(str), kind="stable")          # address-string order
    pools = [order[(b[order] == i) & pool_mask[order]] for i in range(len(BINS))]
    need = [int(((b == i) & A).sum()) for i in range(len(BINS))]
    draws, c2 = OrderedDict(), OrderedDict()
    for d in MATCHED_DRAW_SEEDS:
        pick, log, unmet = matched_draw(d, need, pools)
        inS = np.zeros(S.n_ip, bool)
        inS[pick] = True
        assert inS.sum() == len(pick)
        draws[d] = inS
        y = inS[S.ip]
        dist = distribution(np.flatnonzero(inS), rows_per_ip, n_tr)
        c2[f"draw_{d}"] = OrderedDict([
            ("sampling_seed", d), ("shortfalls", log), ("shortfall_unmet_below_lowest_bin", int(unmet)),
            ("achieved_addresses", int(inS.sum())), ("target_addresses", int(A.sum())),
            ("achieved_row_share", dist["share_of_dev_train_rows"]), ("p", p),
            ("induced_distribution", dist),
            ("intersection_with_real_attack_set", int((inS & A).sum())),
            ("subset_of_non_attack_pool", bool(not (inS & ~pool_mask).any())),
            ("induced_rows", {"dev_train": int(y[:n_tr].sum()), **{h: int(y[S.halves[h]].sum()) for h in HALVES}}),
            ("addresses_seen", {h: int(np.unique(S.ip[S.halves[h] & y]).size) for h in HALVES}),
        ])
        print("C2", d, {k: c2[f"draw_{d}"][k] for k in ("shortfalls", "achieved_addresses", "achieved_row_share",
                                                        "intersection_with_real_attack_set")}, flush=True)

    out = load_out(OUT_116)
    for k, v in (("amendment", "11.6"), ("protocol", "eval/PROTOCOL.md amendment 11.6"),
                 ("data", "datasets.load('dev'): dev_train, val_a, val_b only"),
                 ("sampling", "bins from the highest down; pools ordered by address string; one numpy "
                              "Generator(PCG64(seed)) per draw, .choice(pool, need, replace=False) per bin; "
                              "a short bin gives all its addresses and the shortfall moves to the next lower bin"),
                 ("bootstrap", f"as 11.4: {BOOT_N} resamples of source addresses, Generator(PCG64({BOOT_SEED})), "
                               "same resamples for (a') and (c'), model seed 42"),
                 ("C1", c1), ("C2", c2)):
        out[k] = v
    save_out(out, OUT_116)

    t = time.time()
    fr_win = P3.windowed_failed_rate(S, P3.ML_WINDOW_DAYS)
    clk.tick("30-day windowed failed_rate over the stream", t)
    allr = np.ones(n_tr, bool)

    # (c'): label-free, the same for every draw; each seed checked against the
    # stored label-free scores (11.4 run, and score_p2var_c.npy for seed 42).
    t = time.time()
    maps_df = P4B.frame(S, allr)
    prep = P4B.prepare(maps_df, maps_df)
    X = P3.raw_features(S, prep, fr_win)
    Xs = prep.scaler.transform(X[rows])
    info_c = artefact_info(prep, prep.detector())
    del X, maps_df
    clk.tick("(c'): maps, scaler, features", t)
    info_c["check_vs_stored"] = OrderedDict()
    sc_c = {}
    for seed in MODEL_SEEDS:
        t = time.time()
        model, _ = P2.fit_forest(prep.X_train, seed)
        s = -P2.score_samples(model, Xs)
        chk = OrderedDict()
        f = cpath(f"c_seed{seed}_val.npy")
        if os.path.exists(f):
            chk["vs_amendment11_4_run"] = {"file": f"results/amendment11_cache/c_seed{seed}_val.npy",
                                           "bit_identical": bool(np.array_equal(s, np.load(f)))}
        if seed == 42:
            st = np.load(P4B.cache("score_p2var_c.npy"), mmap_mode="r")[rows]
            chk["vs_score_p2var_c"] = {"file": "results/phase4_cache/score_p2var_c.npy",
                                       "bit_identical": bool(np.array_equal(s, st))}
        info_c["check_vs_stored"][f"seed_{seed}"] = chk
        sc_c[seed] = s
        clk.tick(f"(c') seed {seed}: fit, score {len(rows):,} events", t)
        print("(c') check", seed, chk, flush=True)
    del Xs, prep
    out["construction_c_prime"] = info_c

    res, stopped = OrderedDict(), None
    for d, inS in draws.items():
        y_all = inS[S.ip]
        ind_benign = ~y_all[:n_tr]
        sc_a, info_a = build(S, ind_benign, ind_benign, fr_win, rows, MODEL_SEEDS, clk, f"(a') draw {d}")
        for seed, s in sc_a.items():
            np.save(cpath(f"matched_a_prime_draw{d}_seed{seed}_val.npy"), s)
        r = OrderedDict([("construction_a_prime", info_a)])
        for h in HALVES:
            t = time.time()
            r[h] = x = score_split(half_idx[h], y_all[rows], ip_val, sc_a, sc_c)
            clk.tick(f"draw {d} {h}: metrics and cluster bootstrap", t)
            print(f"draw {d} {h}:", {s: (round(v['a_prime']['roc_auc'], 4), round(v['c_prime']['roc_auc'], 4),
                                         round(v['L'], 4)) for s, v in x["per_model_seed"].items()},
                  "CI a'", x["interval_seed_42"]["a_prime_roc_auc"], "CI c'", x["interval_seed_42"]["c_prime_roc_auc"],
                  dict(x["predictions"]), "STOP" if x["stop_condition_c_prime_ci_low_gt_0.60"] else "", flush=True)
            if x["stop_condition_c_prime_ci_low_gt_0.60"] and stopped is None:
                stopped = f"draw_{d} {h}"
        r["fit_time_absence_count"] = OrderedDict([
            ("known_ips_all_dev_train_rows", info_c["fitted_artefacts"]["known_ips_set"]),
            ("known_ips_induced_label_0_rows", info_a["fitted_artefacts"]["known_ips_set"]),
            ("difference", info_c["fitted_artefacts"]["known_ips_set"] - info_a["fitted_artefacts"]["known_ips_set"])])
        res[f"draw_{d}"] = r
        out["draws"] = res
        save_out(out, OUT_116)
        if stopped:
            break

    done = list(res)
    preds = OrderedDict()
    for pk in ("1_a_prime_ci_low_gt_0.70", "2_L_seed_mean_gt_0.85"):
        preds[pk] = OrderedDict((h, OrderedDict((k, res[k][h]["predictions"][pk]) for k in done)) for h in HALVES)
        preds[pk]["held_all_draws_both_splits"] = (len(done) == len(MATCHED_DRAW_SEEDS) and
                                                   all(v for h in HALVES for v in preds[pk][h].values()))
    out["predictions"] = preds
    out["c_prime_intervals_no_prediction"] = OrderedDict(
        (h, OrderedDict((k, res[k][h]["interval_seed_42"]["c_prime_roc_auc"]) for k in done)) for h in HALVES)
    out["over_draws"] = OrderedDict((h, {"L_mean_over_draws": float(np.mean(
        [res[k][h]["L_mean_over_model_seeds"] for k in done]))}) for h in HALVES)
    out["stop_condition"] = {"rule": "lower bound of the AUC_c' interval > 0.60 (11.6)",
                             "triggered": stopped is not None, "where": stopped}
    out["timings_seconds"] = clk.total()
    save_out(out, OUT_116)
    print("predictions", json.dumps(preds, indent=1), "\nstop", out["stop_condition"])


def stage_prev(args):
    """Task E: point values of the 11.4 run, copied from amendment11_controls.json (no recomputation)."""
    src = load_out(OUT)["control"]["draws"]
    e = OrderedDict([("source", f"results/{OUT}"), ("recomputed", False)])
    for d, r in src.items():
        e[d] = OrderedDict()
        for h in HALVES:
            x = r[h]
            e[d][h] = OrderedDict([("induced_label_event_base_rate", {
                "value": x["induced_label_event_base_rate"],
                "path": f"control/draws/{d}/{h}/induced_label_event_base_rate"})])
            for s, v in x["per_model_seed"].items():
                e[d][h][s] = OrderedDict([
                    ("a_prime_roc_auc", {"value": v["a_prime"]["roc_auc"],
                                         "path": f"control/draws/{d}/{h}/per_model_seed/{s}/a_prime/roc_auc"}),
                    ("c_prime_roc_auc", {"value": v["c_prime"]["roc_auc"],
                                         "path": f"control/draws/{d}/{h}/per_model_seed/{s}/c_prime/roc_auc"})])
    out = load_out(OUT_116)
    out["E"] = e
    save_out(out, OUT_116)
    print(json.dumps(e, indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["control", "real", "matched", "prev"])
    ap.add_argument("--out", default=OUT_116, help="real: output file under results/")
    args = ap.parse_args()
    {"control": stage_control, "real": stage_real, "matched": stage_matched, "prev": stage_prev}[args.stage](args)


if __name__ == "__main__":
    main()
