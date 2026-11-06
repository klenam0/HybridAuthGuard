# backend/eval/amendment11_7_la7.py
"""
Amendment 11.7 (eval/PROTOCOL.md; post hoc, disclosed), Task H of
CLAUDE_CODE_PROMPT_D.md, and Task J (the consolidated table of every L).

  python -m eval.amendment11_7_la7 contrast   Task H: AUC_a (real label, real
                                              construction (a)) minus AUC_a'
                                              (matched random label of 11.6,
                                              construction (a')), seed 42,
                                              paired cluster bootstrap (11.7.2)
  python -m eval.amendment11_7_la7 table      Task J: every L, copied from the
                                              stored JSONs (no recomputation)

RBA development data only: the stream is datasets.load("dev") through
eval.phase3b.stream(). The locked May month and every month from June 2020
onward are never read. Task H reads stored per-event scores only and fits
nothing:
  (a)  real label, seed 42: -results/phase3_cache/ml_decision_v3.npy, as in
       amendment11_controls.stage_real
  (a') draw d, seed 42: results/amendment11_cache/matched_a_prime_draw{d}_seed42_val.npy
The 11.6 induced labels are rebuilt with the 11.6 code
(amendment11_controls.matched_draw) and checked against the stored row counts.

Writes results/amendment11_7_la7.json (keys "H" and "J").
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

from eval import amendment11_controls as A11  # noqa: E402

RESULTS = A11.RESULTS
OUT = "amendment11_7_la7.json"
BOOT_SEED, BOOT_N = A11.BOOT_SEED, A11.BOOT_N
HALVES = A11.HALVES


def load_json(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=OrderedDict)


def load_out():
    p = os.path.join(RESULTS, OUT)
    return load_json(OUT) if os.path.exists(p) else OrderedDict()


def save_out(out):
    with open(os.path.join(RESULTS, OUT), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def paired_bootstrap(clusters, pairs, n=BOOT_N, seed=BOOT_SEED):
    """As A11.cluster_bootstrap (same Generator, same resample sequence), but
    each scorer carries its own label: pairs = {name: (y, x)}. Every scorer is
    evaluated on the same resampled rows."""
    inv = np.unique(clusters, return_inverse=True)[1].ravel()
    K = int(inv.max()) + 1
    aucs = {k: A11.WeightedAUC(y, x) for k, (y, x) in pairs.items()}
    rng = np.random.Generator(np.random.PCG64(seed))
    res = {k: np.empty(n) for k in pairs}
    for b in range(n):
        w = np.bincount(rng.integers(0, K, size=K), minlength=K).astype(np.float64)[inv]
        for k, f in aucs.items():
            res[k][b] = f(w)
    return res, K


def matched_labels(S):
    """The three 11.6 induced address sets, rebuilt exactly as stage_matched."""
    n_tr = S.n_train
    rows_per_ip = np.bincount(S.ip[:n_tr], minlength=S.n_ip)
    train = np.zeros(S.n, bool)
    train[:n_tr] = True
    A = S.attacking_ips(train)
    pool_mask = (rows_per_ip > 0) & ~A
    b = A11.bin_of(rows_per_ip)
    order = np.argsort(S.ip_names.astype(str), kind="stable")
    pools = [order[(b[order] == i) & pool_mask[order]] for i in range(len(A11.BINS))]
    need = [int(((b == i) & A).sum()) for i in range(len(A11.BINS))]
    draws = OrderedDict()
    for d in A11.MATCHED_DRAW_SEEDS:
        pick, _, _ = A11.matched_draw(d, need, pools)
        inS = np.zeros(S.n_ip, bool)
        inS[pick] = True
        draws[d] = inS
    return draws


def stage_contrast(args):
    from eval import phase3b as P3B
    clk = A11.Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    s116 = load_json(A11.OUT_116)
    diag = P3B.load_json("phase4b_diag.json")["variants"]
    rows = np.flatnonzero(S.val)
    a_real = -np.asarray(np.load(P3B.ML_DECISION, mmap_mode="r")[:S.n], np.float64)[rows]
    y_real = S.truth[rows]
    ip_val = S.ip[rows]
    draws = matched_labels(S)

    checks = OrderedDict()
    for d, inS in draws.items():
        y = inS[S.ip]
        got = {"dev_train": int(y[:S.n_train].sum()), **{h: int(y[S.halves[h]].sum()) for h in HALVES}}
        want = dict(s116["C2"][f"draw_{d}"]["induced_rows"])
        checks[f"draw_{d}_induced_rows"] = {"rebuilt": got, "stored": want,
                                            "stored_path": f"amendment11_6_controls.json C2/draw_{d}/induced_rows",
                                            "equal": got == want}
    assert all(c["equal"] for c in checks.values()), checks

    res = OrderedDict()
    for h in HALVES:
        m = S.halves[h][rows]
        yr, xa, ipm = y_real[m], a_real[m], ip_val[m]
        stored_a = s116["real"]["halves"][h]["roc_auc_stored"]["a"]
        pt_a = A11.metrics(yr, xa)["roc_auc"]
        pairs = OrderedDict([("a", (yr, xa))])
        pts = OrderedDict()
        for d, inS in draws.items():
            yd = inS[S.ip][rows][m]
            xd = np.load(A11.cpath(f"matched_a_prime_draw{d}_seed42_val.npy"))[m]
            pairs[f"draw_{d}"] = (yd, xd)
            pts[d] = A11.metrics(yd, xd)["roc_auc"]
        t = time.time()
        boot, K = paired_bootstrap(ipm, pairs)
        clk.tick(f"{h}: paired cluster bootstrap ({K:,} addresses, {BOOT_N} resamples, 4 scorers)", t)
        ci_a = A11.pct_interval(boot["a"])
        stored_ci_a = s116["real"]["halves"][h]["interval"]["roc_auc_a"]
        blk = OrderedDict([
            ("events", int(m.sum())), ("clusters", K), ("model_seed", 42),
            ("auc_a", OrderedDict([
                ("value", stored_a["value"]), ("source", "amendment11_6_controls.json "
                                                         f"real/halves/{h}/roc_auc_stored/a (= {stored_a['source']})"),
                ("recomputed_from_per_event_scores", pt_a),
                ("recomputed_equals_stored", pt_a == stored_a["value"]),
                ("interval", ci_a),
                ("interval_equals_stored_11_6", ci_a == dict(stored_ci_a)),
                ("stored_interval_path", f"amendment11_6_controls.json real/halves/{h}/interval/roc_auc_a")])),
        ])
        for d in draws:
            k = f"draw_{d}"
            src = s116["draws"][k][h]
            stored_ap = src["per_model_seed"]["seed_42"]["a_prime"]["roc_auc"]
            ci_ap = A11.pct_interval(boot[k])
            diff = boot["a"] - boot[k]
            blk[k] = OrderedDict([
                ("auc_a_prime", OrderedDict([
                    ("value", stored_ap),
                    ("source", f"amendment11_6_controls.json draws/{k}/{h}/per_model_seed/seed_42/a_prime/roc_auc"),
                    ("recomputed_from_per_event_scores", pts[d]),
                    ("recomputed_equals_stored", pts[d] == stored_ap),
                    ("interval", ci_ap),
                    ("interval_equals_stored_11_6", ci_ap == dict(src["interval_seed_42"]["a_prime_roc_auc"])),
                ])),
                ("difference_a_minus_a_prime", stored_a["value"] - stored_ap),
                ("difference_interval", A11.pct_interval(diff)),
                ("prediction", None),
            ])
            print(h, k, round(stored_a["value"], 4), round(stored_ap, 4),
                  round(stored_a["value"] - stored_ap, 4), blk[k]["difference_interval"], flush=True)
        res[h] = blk

    out = load_out()
    out["H"] = OrderedDict([
        ("protocol", "eval/PROTOCOL.md amendment 11.7.2 (declared after the 11.6 controls were seen; "
                     "no prediction declared)"),
        ("data", "datasets.load('dev'): val_a and val_b; no fitting"),
        ("per_event_scores", OrderedDict([
            ("a", "-results/phase3_cache/ml_decision_v3.npy (Phase 3 forest, seed 42), val rows"),
            ("a_prime", "results/amendment11_cache/matched_a_prime_draw{11,12,13}_seed42_val.npy")])),
        ("labels", OrderedDict([("a", "Stream.truth (Is Attack IP or Is Account Takeover)"),
                                ("a_prime", "11.6 distribution-matched induced address set, rebuilt with "
                                            "amendment11_controls.matched_draw")])),
        ("bootstrap", f"{BOOT_N} resamples of source addresses with replacement, numpy Generator(PCG64({BOOT_SEED})), "
                      "the same resampled rows for (a) and every (a'); each scored against its own label; "
                      "AUC ties averaged; difference AUC_a - AUC_a' recomputed per resample; 2.5/97.5 percentiles"),
        ("label_rebuild_checks", checks),
        ("splits", res),
        ("timings_seconds", clk.total()),
    ])
    save_out(out)
    return 0


# ── Task I1 ──────────────────────────────────────────────────────────────────

def stage_label(args):
    """I1: rebuild the LA6.1 induced label from the per-day codes (days 0-13
    through eval.lanl_la6, which reads via lanl_la3.day_table) and the dev
    red-team rows; count the users and the users present in both periods.
    Also records which source-user artefacts the LA6.1 construction already
    used as model inputs (eval.lanl_la6.FIELDS, lanl_d.FEATURES)."""
    from eval import lanl_d as D
    from eval import lanl_la6 as LA6
    V = LA6.vocab()
    names, lab = LA6.induced_users(V)
    fit = np.zeros(len(V["user"]), np.int64)
    sco = np.zeros(len(V["user"]), np.int64)
    for d in LA6.FIT_DAYS:
        fit += np.bincount(LA6.day_arrays(d)[1]["user"], minlength=len(V["user"]))
    for d in LA6.SCORE_DAYS:
        sco += np.bincount(LA6.day_arrays(d)[1]["user"], minlength=len(V["user"]))
    lf, ls = lab & (fit > 0), lab & (sco > 0)
    stored = load_json(LA6.OUT)["F1"]
    i1 = OrderedDict([
        ("labelled_users", len(names)), ("labelled_users_in_vocab", int(lab.sum())),
        ("labelled_users_in_fitting_rows_days_0_7", int(lf.sum())),
        ("labelled_users_in_scoring_rows_days_8_13", int(ls.sum())),
        ("labelled_users_in_both_periods", int((lf & ls).sum())),
        ("labelled_fitting_rows", int(fit[lf].sum())),
        ("reproduces_LA6_1", OrderedDict([
            ("86_users", len(names) == 86 == stored["redteam_source_users_days_0_13"]),
            ("75_in_both", int((lf & ls).sum()) == 75 == stored["labelled_users_in_both"]),
            ("76_in_fitting_rows", int(lf.sum()) == stored["labelled_users_in_days_0_7_filtered"]),
            ("fitting_rows", int(fit[lf].sum()) == stored["labelled_fitting_rows"]),
            ("stored_path", "lanl_la6_controls.json F1")])),
        ("la6_1_model_inputs", list(D.FEATURES)),
        ("la6_1_frequency_maps", [f"{k} ({col}) -> {D.FEATURES[j]}, column {j}" for k, col, j in LA6.FIELDS]),
        ("la6_1_user_map_keys_absent_from_a", load_json(LA6.OUT)["artefacts"]["F"]["user"]["keys_only_in_c"]),
    ])
    out = load_out()
    out.setdefault("I", OrderedDict())["I1"] = i1
    save_out(out)
    print(json.dumps(i1, indent=1))
    return 0


# ── Task J ───────────────────────────────────────────────────────────────────

def get(o, path):
    for k in path.split("/"):
        o = o[k]
    return o


def flag_1171(L, auc_c=None, ci=None):
    """11.7.1: AUC_c below 0.5, or L (or an interval bound on L) above 1."""
    why = []
    if auc_c is not None and auc_c < 0.5:
        why.append("AUC_c < 0.5")
    if L is not None and L > 1:
        why.append("L > 1")
    if ci is not None and ci["high"] > 1:
        why.append("interval upper bound > 1")
    return why or None


def row(label, dataset, split, seed, L, ci, auc_a, auc_c, domain, src, path, note=None, derived=False):
    return OrderedDict([("label", label), ("dataset", dataset), ("split", split), ("model_seed", seed),
                        ("L", L), ("L_interval", None if ci is None else {"low": ci["low"], "high": ci["high"]}),
                        ("auc_a", auc_a), ("auc_c", auc_c),
                        ("flag_11_7_1", flag_1171(L, auc_c, ci)),
                        ("domain_condition_11_2", domain),
                        ("valid_share", domain == "satisfied"),
                        ("derived_from_stored_aucs_not_a_stored_L", derived),
                        ("source_file", f"results/{src}"), ("json_path", path), ("note", note)])


def stage_table(args):
    rows = []
    # 1. real RBA label, val_a / val_b (seed 42, 11.2 interval)
    s116 = load_json(A11.OUT_116)
    for h in HALVES:
        b = s116["real"]["halves"][h]
        iv = b["interval"]
        dom = "satisfied" if iv["domain_condition_ci_low_a_gt_0.55"] else "not satisfied"
        rows.append(row("real attack label", "RBA", h, 42, b["L"], iv["L"], b["roc_auc_stored"]["a"]["value"],
                        b["roc_auc_stored"]["c"]["value"], dom, A11.OUT_116, f"real/halves/{h}/L (interval: "
                        f"real/halves/{h}/interval/L; domain: real/halves/{h}/interval/domain_condition_ci_low_a_gt_0.55)"))
    # 2. real RBA label, May: no stored L; L from the stored per-seed AUCs
    s1 = load_json("phase6_s1.json")
    for stratum in ("all", "new_attackers"):
        Ls = []
        for seed in A11.MODEL_SEEDS:
            pa, pc_ = (f"variants/{v}/seed_{seed}/{stratum}/roc_auc" for v in "ac")
            a, c = get(s1, pa), get(s1, pc_)
            Ls.append(A11.L_of(a, c))
            rows.append(row("real attack label", "RBA", f"May ({stratum})", seed, Ls[-1], None, a, c,
                            "not evaluable (no interval: no stored May per-event scores)", "phase6_s1.json",
                            f"{pa} and {pc_}", derived=True))
        rows.append(row("real attack label", "RBA", f"May ({stratum})", "mean of per-seed L", float(np.mean(Ls)),
                        None, None, None, "not evaluable (no interval)", "phase6_s1.json",
                        f"variants/{{a,c}}/seed_{{42,43,44}}/{stratum}/roc_auc", derived=True))
        pa, pc_ = (f"variants/{v}/over_seeds/{stratum}/roc_auc/mean" for v in "ac")
        rows.append(row("real attack label", "RBA", f"May ({stratum})", "L of seed-mean AUCs",
                        A11.L_of(get(s1, pa), get(s1, pc_)), None, get(s1, pa), get(s1, pc_),
                        "not evaluable (no interval)", "phase6_s1.json", f"{pa} and {pc_}", derived=True))

    # 3 and 4. random-label controls (11.4 count-matched, 11.6 distribution-matched)
    def control(label, src, base, prefix):
        o = load_json(src)
        blk = get(o, base) if base else o
        for k, r in blk["draws"].items():
            for h in HALVES:
                x = r[h]
                ci_ap = x["interval_seed_42"]["a_prime_roc_auc"]
                for seed in A11.MODEL_SEEDS:
                    v = x["per_model_seed"][f"seed_{seed}"]
                    dom = (("satisfied" if ci_ap["low"] > 0.55 else "not satisfied") if seed == 42
                           else "not evaluable (interval computed at model seed 42 only)")
                    rows.append(row(label, "RBA", h, f"{seed} ({k})", v["L"], None, v["a_prime"]["roc_auc"],
                                    v["c_prime"]["roc_auc"], dom, src,
                                    f"{prefix}draws/{k}/{h}/per_model_seed/seed_{seed}/L"
                                    + (f" (domain: {prefix}draws/{k}/{h}/interval_seed_42/a_prime_roc_auc/low)"
                                       if seed == 42 else ""),
                                    note="no interval on L was declared for this control"))
                rows.append(row(label, "RBA", h, f"mean over seeds ({k})", x["L_mean_over_model_seeds"], None,
                                None, None, "not evaluable (no interval on the aggregate)", src,
                                f"{prefix}draws/{k}/{h}/L_mean_over_model_seeds"))
        for h in HALVES:
            rows.append(row(label, "RBA", h, "mean over draws and seeds", blk["over_draws"][h]["L_mean_over_draws"],
                            None, None, None, "not evaluable (no interval on the aggregate)", src,
                            f"{prefix}over_draws/{h}/L_mean_over_draws"))
    control("11.4 count-matched random persistent address label", A11.OUT, "control", "control/")
    control("11.6 distribution-matched random persistent address label", A11.OUT_116, None, "")

    # 5. LANL LA6.1 (F) and LA6.2 (G)
    la6 = load_json("lanl_la6_controls.json")
    for ctl, label in (("F", "LA6.1 induced persistent source-user label (86 red-team users)"),
                       ("G", "LA6.2 true red-team label (negative control)")):
        for scope, blk in la6[ctl].items():
            if scope == "fit_time_absence_count":
                continue
            for s, v in blk["per_seed"].items():
                dom = v.get("domain_condition_ci_low_a_gt_0.55")
                dom = "not evaluable" if dom is None else ("satisfied" if dom else "not satisfied")
                rows.append(row(label, "LANL", scope, int(s.split("_")[1]), v["L"], v.get("L_ci95"),
                                v["a"]["roc_auc"], v["c"]["roc_auc"], dom, "lanl_la6_controls.json",
                                f"{ctl}/{scope}/per_seed/{s}/L (interval: .../L_ci95)"))
            for agg in ("L_mean_over_seeds", "L_of_seed_mean_aucs_secondary"):
                rows.append(row(label, "LANL", scope, agg, blk[agg], None, None, None,
                                "not evaluable (no interval on the aggregate)", "lanl_la6_controls.json",
                                f"{ctl}/{scope}/{agg}"))

    # 6. LA7
    o = load_out()
    la7 = o.get("I", {}).get("L_rows")
    if la7:
        rows.extend(la7)
    else:
        rows.append(OrderedDict([("label", "LA7 (induced source-user label, source-user map added)"),
                                 ("dataset", "LANL"), ("L", "MISSING"),
                                 ("note", "Task I not run: see AMENDMENT11_7_LA7_REPORT.md, Task I")]))

    o["J"] = OrderedDict([
        ("rule", "copied from stored JSONs; no refit, no rescoring. RBA May rows are L = (AUC_a - AUC_c) / "
                 "(AUC_a - 0.5) applied to stored AUCs, because no JSON stores May L"),
        ("flag_11_7_1", "AUC_c < 0.5, or L > 1, or an interval bound on L > 1"),
        ("domain_condition_11_2", "lower bound of the 95% interval on AUC_a (AUC_a' for the controls) > 0.55; "
                                  "'valid_share' is true only where it is satisfied"),
        ("rows", rows)])
    save_out(o)
    for r in rows:
        print(r["label"][:28], r["dataset"], r.get("split"), r.get("model_seed"), r["L"],
              r.get("flag_11_7_1"), r.get("domain_condition_11_2"), sep=" | ")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["contrast", "label", "table"])
    args = ap.parse_args()
    return {"contrast": stage_contrast, "label": stage_label, "table": stage_table}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
