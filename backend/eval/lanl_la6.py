# backend/eval/lanl_la6.py
"""
LANL amendment LA6 (eval/PROTOCOL_LANL.md; post hoc, disclosed): the
second-dataset controls for the entity-label leakage diagnostic of RBA
amendment 11. Development days 0 to 13 only: every auth read goes through
eval.lanl_la3.day_table, which refuses day 14 onward, and the red-team rows
come from eval.lanl_la3.redteam_dev (dev splits only).

  python -m eval.lanl_la6 codes     per-day source user / source computer /
                                    destination computer codes of the LA3.3
                                    filtered rows (aligned with the stored D
                                    feature files)
  python -m eval.lanl_la6 fit       constructions (a) and (c) for LA6.1 and
                                    LA6.2, model seeds 42, 43, 44; scores on
                                    days 8 to 13 (LA6.3 runtime contingency)
  python -m eval.lanl_la6 metrics   LA6.1 / LA6.2 quantities, L, intervals

Constructions mirror the D1 construction of LA3.5 (itself RBA S1 variant
(c)), which already maps the RBA artefacts onto LANL fields:
  frequency maps    source computer (RBA: IP), source user (RBA: user),
                    destination computer (added in LA3.5)
  known-value set   source computer (RBA: known IPs) -> is_new_src
  dropped           RBA country and device maps, known countries,
                    is_failed (constant: the LA3.3 filter keeps only
                    successful logons)
  label-free        hour_sin, hour_cos, fail_rate_30d (taken unchanged from
                    the stored per-day D feature files)
  model             StandardScaler + IsolationForest(n_estimators=200,
                    max_samples=100000, max_features=1.0, contamination=0.4)
                    fit on the fitting rows; score = -score_samples.
(a) builds the maps, the known set, the scaler and the forest from the
fitting rows whose label is 0; (c) from all fitting rows (= D1). Known-value
sets for source user and destination computer are not model inputs; their
(a)/(c) differences are reported as perturbation counts.

Writes results/lanl_la6_controls.json. Per-day codes and scores go to
<LANL work>/la6/ (outside the repository).
"""

import argparse
import json
import os
import pickle
import sys
import time
from collections import OrderedDict

import numpy as np
import pyarrow.compute as pc

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_d as D  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402
from eval.lanl_a_metrics import B, MIN_USERS, boot_weights  # noqa: E402

OUT = "lanl_la6_controls.json"
FIT_DAYS = list(range(0, 8))
SCORE_DAYS = list(range(8, 14))
SCOPES = OrderedDict([("days_8_11", list(range(8, 12))), ("days_12_13", [12, 13]),
                      ("days_8_13", list(range(8, 14)))])
SCOPE_SPLITS = {"days_8_11": ("val_a",), "days_12_13": ("val_b",), "days_8_13": ("val_a", "val_b")}
SEEDS = (42, 43, 44)
FIELDS = (("src", "src_computer", 2), ("user", "src_user", 3), ("dst", "dst_computer", 4))
CONTINGENCY_SECONDS = 90 * 60
CONSTRUCTIONS = ("F_a", "G_a", "c")      # (c) is label-free: shared by LA6.1 and LA6.2


def wdir():
    d = L.wpath("la6")
    os.makedirs(d, exist_ok=True)
    return d


def wp(name):
    return os.path.join(wdir(), name)


def load_out():
    p = os.path.join(L.RESULTS, OUT)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=OrderedDict)
    return OrderedDict()


def save_out(out):
    return L.save_json(OUT, out)


# ── codes ────────────────────────────────────────────────────────────────────

def stage_codes(args):
    t0 = time.perf_counter()
    vocab = {k: {} for k, _, _ in FIELDS}
    per = OrderedDict()
    for d in FIT_DAYS + SCORE_DAYS:
        tbl = L.day_table(d, D.COLS)
        keep = L.filter_mask(tbl)
        rows = np.flatnonzero(keep)
        z = np.load(D.dpath(f"day={d:02d}.npz"))
        assert np.array_equal(rows, z["rows"]), f"day {d}: filtered rows differ from the D feature file"
        f = tbl.filter(keep)
        codes = {}
        for k, col, _ in FIELDS:
            enc = pc.dictionary_encode(pc.utf8_trim_whitespace(f.column(col))).combine_chunks()
            voc = vocab[k]
            m = np.array([voc.setdefault(v, len(voc)) for v in enc.dictionary.to_pylist()], np.int64)
            codes[k] = m[enc.indices.to_numpy(zero_copy_only=False)].astype(np.int32)
        np.savez(wp(f"codes_day={d:02d}.npz"), **codes)
        per[f"{d:02d}"] = int(len(rows))
        print(f"day {d:02d}: {len(rows):,} filtered rows", flush=True)
    with open(wp("vocab.pkl"), "wb") as fh:
        pickle.dump({k: list(v) for k, v in vocab.items()}, fh)
    out = load_out()
    out["codes"] = {"filtered_rows_per_day": per, "vocab_sizes": {k: len(v) for k, v in vocab.items()},
                    "seconds": round(time.perf_counter() - t0, 1)}
    save_out(out)
    return 0


def vocab():
    with open(wp("vocab.pkl"), "rb") as fh:
        return pickle.load(fh)


def day_arrays(d):
    z = np.load(D.dpath(f"day={d:02d}.npz"))
    c = np.load(wp(f"codes_day={d:02d}.npz"))
    return z, {k: c[k] for k, _, _ in FIELDS}


# ── labels ───────────────────────────────────────────────────────────────────

def induced_users(V):
    """LA6.1: source users of any red-team event in days 0 to 13 (dev splits)."""
    rt = L.redteam_dev()
    names = sorted(set(rt["user"].astype(str).str.strip()))
    uix = {u: j for j, u in enumerate(V["user"])}
    lab = np.zeros(len(V["user"]), bool)
    present = [u for u in names if u in uix]
    lab[[uix[u] for u in present]] = True
    return names, lab


def labels(kind, z, codes, lab_users):
    if kind == "F":
        return lab_users[codes["user"]]
    return z["y"].astype(bool)


# ── artefacts ────────────────────────────────────────────────────────────────

def fit_counts(V, kind, lab_users):
    """Per-field counts over the fitting rows (all, and label 0) and the row counts."""
    cnt = {s: {k: np.zeros(len(V[k]), np.int64) for k, _, _ in FIELDS} for s in ("all", "label0")}
    n = {"all": 0, "label0": 0}
    for d in FIT_DAYS:
        z, c = day_arrays(d)
        y = labels(kind, z, c, lab_users)
        for k, _, _ in FIELDS:
            cnt["all"][k] += np.bincount(c[k], minlength=len(V[k]))
            cnt["label0"][k] += np.bincount(c[k][~y], minlength=len(V[k]))
        n["all"] += len(y)
        n["label0"] += int((~y).sum())
    return cnt, n


def artefacts(cnt, n):
    """Frequency maps (count / n, the fit_frequency_maps form) and known sets."""
    return {"n": n, "freq": {k: cnt[k].astype(np.float64) / n for k in cnt},
            "known": {k: cnt[k] > 0 for k in cnt}}


def features(art, X, codes):
    X = X.copy()
    for k, _, j in FIELDS:
        X[:, j] = art["freq"][k][codes[k]]
    X[:, 6] = (~art["known"]["src"][codes["src"]]).astype(np.float64)
    return X


def perturbation(art_a, art_c, cnt_a, cnt_c):
    out = OrderedDict([("fitting_rows_a", int(art_a["n"])), ("fitting_rows_c", int(art_c["n"])),
                       ("rows_removed", int(art_c["n"] - art_a["n"]))])
    for k, _, _ in FIELDS:
        ka, kc = art_a["known"][k], art_c["known"][k]
        both = ka & kc
        out[k] = OrderedDict([
            ("map_keys_a", int(ka.sum())), ("map_keys_c", int(kc.sum())),
            ("keys_only_in_c", int((kc & ~ka).sum())), ("keys_only_in_a", int((ka & ~kc).sum())),
            ("shared_keys_count_differs", int((both & (cnt_a[k] != cnt_c[k])).sum())),
            ("shared_keys_frequency_differs", int((both & (art_a["freq"][k] != art_c["freq"][k])).sum())),
            ("known_set_size_a", int(ka.sum())), ("known_set_size_c", int(kc.sum())),
            ("known_set_symmetric_difference", int((ka ^ kc).sum())),
        ])
    out["note"] = ("frequency = count / fitting rows, so removing any row changes the frequency of every "
                   "shared key; shared_keys_count_differs counts keys whose underlying count changed")
    return out


# ── fit and score ────────────────────────────────────────────────────────────

def stage_fit(args):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from eval import phase2_baseline as P2
    V = vocab()
    names, lab_users = induced_users(V)
    out = load_out()
    fitlog = out.setdefault("fit", OrderedDict())
    arts = {}
    cnt_F, n_F = fit_counts(V, "F", lab_users)
    cnt_G, n_G = fit_counts(V, "G", lab_users)
    assert n_F["all"] == n_G["all"]
    for k in cnt_F["all"]:
        assert np.array_equal(cnt_F["all"][k], cnt_G["all"][k])
    arts["c"] = artefacts(cnt_F["all"], n_F["all"])
    arts["F_a"] = artefacts(cnt_F["label0"], n_F["label0"])
    arts["G_a"] = artefacts(cnt_G["label0"], n_G["label0"])
    fit_masks = {"c": None, "F_a": "F", "G_a": "G"}

    # (c) must reproduce the stored D1 features and maps
    with open(D.dpath("maps.pkl"), "rb") as fh:
        stored = pickle.load(fh)
    chk = OrderedDict([("n_equals_stored", int(stored["n"]) == int(arts["c"]["n"]))])
    for k, _, _ in FIELDS:
        sm = stored["maps"][k]
        mine = {V[k][i]: arts["c"]["freq"][k][i] for i in np.flatnonzero(arts["c"]["known"][k])}
        chk[f"{k}_map_equals_stored"] = (mine == sm)
    bad = 0
    for d in FIT_DAYS + SCORE_DAYS:
        z, c = day_arrays(d)
        bad += int(not np.array_equal(features(arts["c"], z["X"], c), z["X"]))
    chk["features_equal_stored_all_days"] = bad == 0
    print("(c) vs stored D1:", dict(chk), flush=True)
    out["check_c_vs_stored_d1"] = chk
    save_out(out)

    def fit_rows(name):
        Xs, ys = [], []
        for d in FIT_DAYS:
            z, c = day_arrays(d)
            X = features(arts[name], z["X"], c)
            if fit_masks[name] is not None:
                y = labels(fit_masks[name], z, c, lab_users)
                X = X[~y]
            Xs.append(X)
        return np.concatenate(Xs)

    seeds = list(SEEDS)
    contingency = None
    for seed in seeds:
        if contingency:
            break
        for name in CONSTRUCTIONS:
            key = f"{name}/seed_{seed}"
            if key in fitlog and all(os.path.exists(wp(f"score_{name}_s{seed}_day={d:02d}.npy")) for d in SCORE_DAYS):
                print("done:", key, flush=True)
                continue
            t0 = time.perf_counter()
            X = fit_rows(name)
            scaler = StandardScaler().fit(X)
            Xs = scaler.transform(X)
            const = [D.FEATURES[j] for j in range(X.shape[1]) if scaler.var_[j] == 0.0]
            del X
            t1 = time.perf_counter()
            model = IsolationForest(contamination=0.4, random_state=seed, **P2.FOREST).fit(Xs)
            fit_s = time.perf_counter() - t1
            n_fit = len(Xs)
            del Xs
            t2 = time.perf_counter()
            same = []
            for d in SCORE_DAYS:
                z, c = day_arrays(d)
                s = -P2.score_samples(model, scaler.transform(features(arts[name], z["X"], c)))
                np.save(wp(f"score_{name}_s{seed}_day={d:02d}.npy"), s)
                if name == "c" and seed == 42:
                    same.append(bool(np.array_equal(s, np.load(D.dpath(f"d1_day={d:02d}.npy")))))
            score_s = time.perf_counter() - t2
            total = time.perf_counter() - t0
            rec = OrderedDict([("fit_rows", int(n_fit)), ("constant_features_on_fit_rows", const),
                               ("scaler_var", [float(v) for v in scaler.var_]),
                               ("fit_seconds", round(fit_s, 1)), ("score_seconds", round(score_s, 1)),
                               ("fit_and_score_wall_seconds", round(total, 1))])
            if same:
                rec["scores_bit_identical_to_stored_d1_days_8_13"] = all(same)
            fitlog[key] = rec
            save_out(out)
            print(key, dict((k, v) for k, v in rec.items() if k != "scaler_var"), flush=True)
            if total > CONTINGENCY_SECONDS and contingency is None:
                # finish this seed for every construction, then run no further seed
                contingency = {"invoked": True, "trigger": key, "wall_seconds": round(total, 1),
                               "rule": "LA6.3: reduce both controls to model seed 42"}
    out["la6_3_contingency"] = contingency or {"invoked": False,
                                               "max_fit_and_score_wall_seconds":
                                                   max(r["fit_and_score_wall_seconds"] for r in fitlog.values())}
    # artefact summaries (needed by metrics)
    out["artefacts"] = OrderedDict([
        ("F", perturbation(arts["F_a"], arts["c"], cnt_F["label0"], cnt_F["all"])),
        ("G", perturbation(arts["G_a"], arts["c"], cnt_G["label0"], cnt_G["all"])),
    ])
    save_out(out)
    return 0


# ── metrics ──────────────────────────────────────────────────────────────────

def strict_neg_above(score, y):
    """Negatives ranked above each positive under (score desc, index asc),
    returned for the positives in ascending rank order, with their indices."""
    o = np.lexsort((np.arange(len(score)), -score))
    r = np.empty(len(score), np.int64)
    r[o] = np.arange(len(score))
    pi = np.flatnonzero(y)
    rp = r[pi]
    srt = np.argsort(rp)
    return pi[srt], rp[srt] - np.arange(len(pi))


def auc_parts(score, y, ent, U):
    """Point ROC-AUC and PR-AUC (strict ranking, lanl_d_metrics definitions)
    and per-entity sums for the clustered bootstrap."""
    N = int(len(y) - y.sum())
    pi, na = strict_neg_above(score, y)
    P = len(pi)
    contrib = (N - na).astype(np.float64)
    e = ent[pi]
    agg = np.bincount(e, weights=contrib, minlength=U)
    cnt = np.bincount(e, minlength=U).astype(np.float64)
    roc = float(contrib.sum() / (N * P))
    ap = float(np.mean((np.arange(P) + 1) / (na + np.arange(P) + 1)))
    return {"roc_auc": roc, "pr_auc": ap, "N": N, "agg": agg, "cnt": cnt}


def pct(v):
    v = v[~np.isnan(v)]
    return {"low": float(np.percentile(v, 2.5)), "high": float(np.percentile(v, 97.5)), "valid_resamples": int(len(v))}


def L_of(a, c):
    return (a - c) / (a - 0.5)


def load_scope(days, names):
    zs = {"y_true": [], "user": [], "src": [], "dst": []}
    sc = {n: [] for n in names}
    for d in days:
        z, c = day_arrays(d)
        zs["y_true"].append(z["y"].astype(bool))
        for k in ("user", "src", "dst"):
            zs[k].append(c[k])
        for n in names:
            sc[n].append(np.load(wp(f"score_{n}.npy".replace(".npy", f"_day={d:02d}.npy"))))
    return {k: np.concatenate(v) for k, v in zs.items()}, {n: np.concatenate(v) for n, v in sc.items()}


def stage_metrics(args):
    from sklearn.metrics import average_precision_score, roc_auc_score
    t_all = time.perf_counter()
    V = vocab()
    names, lab_users = induced_users(V)
    out = load_out()
    seeds = [s for s in SEEDS if all(f"{c}/seed_{s}" in out["fit"] for c in CONSTRUCTIONS)]
    rt = L.redteam_dev()
    rt["user"] = rt["user"].astype(str).str.strip()
    uix = {u: j for j, u in enumerate(V["user"])}

    # ── F1 ──
    fit_user_rows = np.zeros(len(V["user"]), np.int64)
    score_user_rows = np.zeros(len(V["user"]), np.int64)
    n_fit = 0
    for d in FIT_DAYS:
        _, c = day_arrays(d)
        fit_user_rows += np.bincount(c["user"], minlength=len(V["user"]))
        n_fit += len(c["user"])
    for d in SCORE_DAYS:
        _, c = day_arrays(d)
        score_user_rows += np.bincount(c["user"], minlength=len(V["user"]))
    lab_fit = lab_users & (fit_user_rows > 0)
    lab_score = lab_users & (score_user_rows > 0)
    r = fit_user_rows[lab_fit]

    def dist(x):
        return OrderedDict([("users", int(len(x))), ("rows", int(x.sum())), ("min", int(x.min())),
                            ("p25", float(np.percentile(x, 25))), ("median", float(np.median(x))),
                            ("mean", float(x.mean())), ("p75", float(np.percentile(x, 75))), ("max", int(x.max()))]) \
            if len(x) else {"users": 0}
    F1 = OrderedDict([
        ("redteam_source_users_days_0_13", len(names)),
        ("labelled_users_present_in_filtered_rows_days_0_13", int((lab_users & ((fit_user_rows + score_user_rows) > 0)).sum())),
        ("labelled_users_in_days_0_7_filtered", int(lab_fit.sum())),
        ("labelled_users_in_days_8_13_filtered", int(lab_score.sum())),
        ("labelled_users_in_both", int((lab_fit & lab_score).sum())),
        ("labelled_users_only_in_days_8_13", int((lab_score & ~lab_fit).sum())),
        ("fitting_rows", int(n_fit)),
        ("labelled_fitting_rows", int(r.sum())),
        ("labelled_share_of_fitting_rows", float(r.sum() / n_fit)),
        ("rows_per_labelled_user_days_0_7", dist(r)),
        ("rows_per_labelled_user_days_8_13", dist(score_user_rows[lab_score])),
    ])
    out["F1"] = F1
    print("F1", json.dumps(F1, indent=1), flush=True)

    res = OrderedDict([("F", OrderedDict()), ("G", OrderedDict())])
    for scope, days in SCOPES.items():
        t = time.perf_counter()
        names_s = [f"{c}_s{s}" for c in CONSTRUCTIONS for s in seeds]
        Z, S = load_scope(days, names_s)
        n = len(Z["y_true"])
        for ctl in ("F", "G"):
            if ctl == "F":
                y = lab_users[Z["user"]]
                ent_users = sorted(set(np.unique(Z["user"][y]).tolist()), key=lambda j: V["user"][j])
                ent_desc = "labelled source users with an induced-positive row in the scope"
            else:
                y = Z["y_true"]
                ev = rt[rt["split"].isin(SCOPE_SPLITS[scope])]
                ent_users = [uix[u] for u in sorted(set(ev["user"])) if u in uix]   # name order, as lanl_d_metrics
                missing = sorted({u for u in ev["user"] if u not in uix})
                ent_desc = "red-team users of the scope's red-team events (lanl_d_metrics)"
                assert set(np.unique(Z["user"][y]).tolist()) <= set(ent_users)
            U = len(ent_users)
            remap = np.full(len(V["user"]), -1, np.int64)
            remap[np.array(ent_users, np.int64)] = np.arange(U)   # bootstrap columns in user-name order
            ent = remap[Z["user"]]
            W = boot_weights(ent_users).astype(np.float64) if U >= MIN_USERS else None
            a_name = f"{ctl}_a"
            blk = OrderedDict([("rows", int(n)), ("positive_rows", int(y.sum())),
                               ("base_rate", float(y.mean())), ("cluster_entities", U),
                               ("cluster_entity_definition", ent_desc),
                               ("mode", "bootstrap" if W is not None else "exact counts (fewer than 20 entities)")])
            if ctl == "G" and missing:
                blk["redteam_users_absent_from_filtered_rows"] = len(missing)
            per = OrderedDict()
            for s in seeds:
                pa_ = auc_parts(S[f"{a_name}_s{s}"], y, ent, U)
                pc_ = auc_parts(S[f"c_s{s}"], y, ent, U)
                Lp = L_of(pa_["roc_auc"], pc_["roc_auc"])
                rec = OrderedDict([("a", {"roc_auc": pa_["roc_auc"], "pr_auc": pa_["pr_auc"]}),
                                   ("c", {"roc_auc": pc_["roc_auc"], "pr_auc": pc_["pr_auc"]}),
                                   ("auc_c_below_0.5", pc_["roc_auc"] < 0.5)])
                if W is not None:
                    wa = (W @ pa_["agg"]) / (pa_["N"] * (W @ pa_["cnt"]))
                    wc = (W @ pc_["agg"]) / (pc_["N"] * (W @ pc_["cnt"]))
                    ci_a = pct(wa)
                    rec["a"]["roc_auc_ci95"] = ci_a
                    rec["c"]["roc_auc_ci95"] = pct(wc)
                    dom = ci_a["low"] > 0.55
                    rec["domain_condition_ci_low_a_gt_0.55"] = dom
                    if dom:
                        rec["L"] = Lp
                        rec["L_ci95"] = pct(L_of(wa, wc))
                        rec["L_above_1_flag"] = Lp > 1
                    else:
                        rec["L"] = None
                        rec["L_not_reported"] = "domain condition of 11.2 not met"
                else:
                    rec["domain_condition_ci_low_a_gt_0.55"] = None
                    rec["L"] = Lp
                    rec["L_note"] = "no interval: fewer than 20 entities (LA2.6)"
                per[f"seed_{s}"] = rec
            blk["per_seed"] = per
            Ls = [per[f"seed_{s}"]["L"] for s in seeds if per[f"seed_{s}"]["L"] is not None]
            blk["L_mean_over_seeds"] = float(np.mean(Ls)) if len(Ls) == len(seeds) else None
            ma = np.mean([per[f"seed_{s}"]["a"]["roc_auc"] for s in seeds])
            mc = np.mean([per[f"seed_{s}"]["c"]["roc_auc"] for s in seeds])
            blk["L_of_seed_mean_aucs_secondary"] = float(L_of(ma, mc))
            if ctl == "F":
                # entity-lookup reference (11.1 step 1): user in any induced-positive row of days 0-7
                look = lab_fit[Z["user"]]
                tp = int((look & y).sum())
                blk["entity_lookup_reference"] = OrderedDict([
                    ("roc_auc_ties_averaged", float(roc_auc_score(y, look))),
                    ("pr_auc", float(average_precision_score(y, look))),
                    ("flagged_rows", int(look.sum())), ("true_positive_rows", tp),
                    ("precision_score_1", tp / int(look.sum()) if look.any() else None),
                    ("recall_score_1", tp / int(y.sum()) if y.any() else None),
                    ("positive_users_in_scope", U),
                    ("positive_users_seen_in_days_0_7", int(lab_fit[np.array(ent_users, np.int64)].sum())),
                ])
            res[ctl][scope] = blk
            print(scope, ctl, {s: (round(v["a"]["roc_auc"], 4), round(v["c"]["roc_auc"], 4),
                                   None if v["L"] is None else round(v["L"], 4),
                                   v.get("L_ci95")) for s, v in per.items()}, flush=True)
        del Z, S
        print(f"[{time.perf_counter() - t:.1f} s] {scope}", flush=True)

    # fit-time absence counts (11.4 definition, same code path for both labels)
    arts = out["artefacts"]
    for ctl in ("F", "G"):
        res[ctl]["fit_time_absence_count"] = OrderedDict(
            (k, arts[ctl][k]["known_set_size_c"] - arts[ctl][k]["known_set_size_a"]) for k, _, _ in FIELDS)

    # predictions
    split_scopes = ("days_8_11", "days_12_13")
    p1 = OrderedDict()
    for sc in split_scopes:
        p1[sc] = OrderedDict((f"seed_{s}", (res["F"][sc]["per_seed"][f"seed_{s}"]["L"] is not None and
                                            res["F"][sc]["per_seed"][f"seed_{s}"]["L"] > 0.85)) for s in seeds)
        p1[sc]["lookup_roc_auc_gt_0.90"] = res["F"][sc]["entity_lookup_reference"]["roc_auc_ties_averaged"] > 0.90
    p1["held"] = all(v for sc in split_scopes for v in p1[sc].values()) and len(seeds) == 3
    p2 = OrderedDict()
    for sc in split_scopes:
        p2[sc] = OrderedDict()
        for s in seeds:
            rec = res["G"][sc]["per_seed"][f"seed_{s}"]
            ci_ = rec.get("L_ci95")
            p2[sc][f"seed_{s}"] = OrderedDict([
                ("L_reported", rec["L"] is not None),
                ("ci_contains_0", None if ci_ is None else bool(ci_["low"] <= 0 <= ci_["high"])),
                ("ci_upper_below_0.30", None if ci_ is None else bool(ci_["high"] < 0.30)),
            ])
    p2["held"] = all(v["ci_contains_0"] and v["ci_upper_below_0.30"]
                     for sc in split_scopes for v in p2[sc].values()) and len(seeds) == 3
    out["F"], out["G"] = res["F"], res["G"]
    out["predictions"] = OrderedDict([("LA6.1", p1), ("LA6.2", p2)])
    out["seeds_used"] = seeds
    out["metric_definitions"] = (
        "ROC-AUC and PR-AUC on the strict ranking (score descending, stream order ascending), as "
        "eval/lanl_d_metrics. Intervals: 95% percentile bootstrap, 1,000 resamples of the cluster "
        "entities (eval/lanl_a_metrics.boot_weights, numpy default_rng(42)); positives weighted by "
        "their entity's multiplicity, negatives fixed (LA3.7); the same resamples for (a), (c) and "
        "every seed; L recomputed per resample. Entity-lookup reference: sklearn, ties averaged.")
    out["metrics_seconds"] = round(time.perf_counter() - t_all, 1)
    save_out(out)
    print(json.dumps(out["predictions"], indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["codes", "fit", "metrics"])
    args = ap.parse_args()
    return {"codes": stage_codes, "fit": stage_fit, "metrics": stage_metrics}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
