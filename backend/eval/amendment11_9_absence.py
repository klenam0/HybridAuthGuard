# backend/eval/amendment11_9_absence.py
"""
Amendment 11.9.4 (eval/PROTOCOL.md) and LANL LA8: the artefact-absence
measurement, descriptive (no prediction). Task M of CLAUDE_CODE_PROMPT_E_REV2.md:
the share (AUC_a - AUC_a') / (AUC_a - 0.5) of the Task H contrast.

  python -m eval.amendment11_9_absence rba     Task K (RBA dev: val_a, val_b)
  python -m eval.amendment11_9_absence lanl    Task L (LANL dev: days 0-13)
  python -m eval.amendment11_9_absence share   Task M (rerun of the Task H
                                               bootstrap; stored scores only)

No model is fitted: only frequency maps and known-value sets are rebuilt.
No scaler is fitted and no forest is trained.

RBA: datasets.load("dev") through eval.phase3b.stream(). The construction (a)
maps and known sets are ml/train_from_dataset.fit_frequency_maps on the
non-attack dev_train rows (eval.phase4b.frame), as eval.phase4b.prepare does,
without its scaler. Scored-row keys are derived exactly as
eval.phase3_rules.raw_features derives them for the model features.
LANL: the LA6.1 construction (a) counts are rebuilt with
eval.lanl_la6.fit_counts from the per-day codes of days 0-7 and checked
against the stored key counts before any indicator is computed; scored rows
are days 8-13 through eval.lanl_la6.day_arrays. No day from 14 is read.

Writes results/amendment11_9_absence.json (keys "K", "L", "M").
"""

import argparse
import contextlib
import io
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
OUT = "amendment11_9_absence.json"
HALVES = A11.HALVES


def load_json(name):
    with open(os.path.join(RESULTS, name), encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=OrderedDict)


def load_out():
    return load_json(OUT) if os.path.exists(os.path.join(RESULTS, OUT)) else OrderedDict()


def save_out(out):
    with open(os.path.join(RESULTS, OUT), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def indicator_metrics(y, ind):
    """11.9.4 quantities for one binary absence indicator against label y.
    ROC-AUC and PR-AUC by sklearn (ties averaged), as the entity-lookup
    references of amendment 10, 11.4 and LA6."""
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.asarray(y, bool)
    ind = np.asarray(ind, bool)
    tp = int((ind & y).sum())
    n_set = int(ind.sum())
    both = y.any() and not y.all()
    return OrderedDict([
        ("rows", int(len(y))), ("positive_rows", int(y.sum())), ("base_rate", float(y.mean())),
        ("roc_auc", float(roc_auc_score(y, ind.astype(np.float64))) if both else None),
        ("pr_auc", float(average_precision_score(y, ind.astype(np.float64))) if both else None),
        ("indicator_set_rows", n_set), ("share_of_rows_indicator_set", n_set / len(y)),
        ("true_positive_rows", tp),
        ("precision_indicator_set", tp / n_set if n_set else None),
        ("recall_indicator_set", tp / int(y.sum()) if y.any() else None),
    ])


# ── Task K: RBA ──────────────────────────────────────────────────────────────

def stage_rba(args):
    from eval import phase3b as P3B
    from eval import phase4b as P4B
    clk = A11.Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    t = time.time()
    sys.path.insert(0, os.path.join(BACKEND, "ml"))
    from train_from_dataset import fit_frequency_maps
    benign = ~S.truth[:S.n_train]
    maps_df = P4B.frame(S, benign)
    with contextlib.redirect_stdout(io.StringIO()):
        maps, kip, kc = fit_frequency_maps(maps_df)
    n_map_rows = len(maps_df)
    del maps_df
    clk.tick("construction (a) maps and known sets (no scaler, no forest)", t)

    # key counts against the stored construction (a) artefact record
    st = load_json(A11.OUT)["control"]["real_construction_a_seed42"]
    sfa = st["fitted_artefacts"]
    mine = OrderedDict([("map_rows", n_map_rows), ("ip_freq_map_keys", len(maps["ip"])),
                        ("user_freq_map_keys", len(maps["user"])), ("country_freq_map_keys", len(maps["country"])),
                        ("device_freq_map_keys", len(maps["device"])), ("known_ips_set", len(kip)),
                        ("known_countries_set", len(kc))])
    stored = OrderedDict([("map_rows", st["map_rows"])] + [(k, sfa[k]) for k in list(mine)[1:]])
    check = OrderedDict([("rebuilt", mine), ("stored", stored),
                         ("stored_path", "amendment11_controls.json control/real_construction_a_seed42"
                                         "/{map_rows,fitted_artefacts/*}"),
                         ("equal", mine == stored)])
    print("key counts", dict(check), flush=True)
    if not check["equal"]:
        raise SystemExit("construction (a) key counts differ from the stored record; stopping")

    # per-row absence, keys derived exactly as phase3_rules.raw_features
    df = S.df
    absent = OrderedDict()
    absent["ip_freq_map"] = np.array([x not in maps["ip"] for x in S.ip_names])[S.ip]
    absent["known_ips_set"] = np.array([x not in kip for x in S.ip_names])[S.ip]
    absent["user_freq_map"] = np.array([str(u) not in maps["user"] for u in S.user_ids])[S.user]
    for col, missing, names_of in (("Country", "XX", ("country_freq_map", "known_countries_set")),
                                   ("Device Type", "Unknown", ("device_freq_map",))):
        cat = df[col].astype("category")
        names = cat.cat.categories.astype(str).to_numpy(dtype=object)
        names = np.where((names == "") | (names == "nan"), missing, names)
        names = np.array([str(x).strip() for x in names], dtype=object)
        codes = cat.cat.codes.to_numpy()
        idx = np.where(codes < 0, len(names), codes)
        allnames = list(names) + [missing]
        if col == "Country":
            absent["country_freq_map"] = np.array([x not in maps["country"] for x in allnames])[idx]
            absent["known_countries_set"] = np.array([x not in kc for x in allnames])[idx]
        else:
            absent["device_freq_map"] = np.array([x not in maps["device"] for x in allnames])[idx]

    artefacts = OrderedDict([
        ("ip_freq_map", ("source address (IP Address, stripped)", "ip_freq", True)),
        ("known_ips_set", ("source address (IP Address)", "is_new_ip", True)),
        ("user_freq_map", ("account (User ID)", "user_freq", False)),
        ("country_freq_map", ("country (Country, missing -> 'XX', stripped)", "country_freq", True)),
        ("known_countries_set", ("country (Country, missing -> 'XX')", "is_new_country", False)),
        ("device_freq_map", ("device type (Device Type, missing -> 'Unknown', stripped)", "device_freq", True)),
    ])
    k1 = OrderedDict((a, OrderedDict([("key_field", f), ("model_input", m),
                                      ("listed_in_11_9_4", listed)]))
                     for a, (f, m, listed) in artefacts.items())

    # groups: artefacts whose indicator is identical on every scored row
    val = S.val
    groups, seen = [], set()
    for a in absent:
        if a in seen:
            continue
        g = [b for b in absent if b not in seen and np.array_equal(absent[a][val], absent[b][val])]
        seen.update(g)
        groups.append(g)
    print("groups", groups, flush=True)

    res = OrderedDict()
    for g in groups:
        name = " + ".join(g)
        res[name] = OrderedDict([("artefacts", g), ("key_fields", [k1[a]["key_field"] for a in g]),
                                 ("listed_in_11_9_4", [k1[a]["listed_in_11_9_4"] for a in g])])
        for h in HALVES:
            m = S.halves[h]
            res[name][h] = indicator_metrics(S.truth[m], absent[g[0]][m])
            print(name, h, {k: res[name][h][k] for k in ("roc_auc", "pr_auc", "share_of_rows_indicator_set",
                                                          "precision_indicator_set", "recall_indicator_set")},
                  flush=True)
    out = load_out()
    out["K"] = OrderedDict([
        ("protocol", "eval/PROTOCOL.md amendment 11.9.4 (descriptive; no prediction)"),
        ("data", "datasets.load('dev'): maps from non-attack dev_train rows; indicators on val_a and val_b"),
        ("label", "Stream.truth (Is Attack IP or Is Account Takeover)"),
        ("construction_a", "ml/train_from_dataset.fit_frequency_maps on eval.phase4b.frame(S, ~truth[:n_train]); "
                           "no scaler, no forest"),
        ("key_count_check", check),
        ("K1_artefacts", k1),
        ("indicator_groups_identical_on_scored_rows", groups),
        ("K2", res),
        ("timings_seconds", clk.total()),
    ])
    save_out(out)
    return 0


# ── Task L: LANL ─────────────────────────────────────────────────────────────

def stage_lanl(args):
    from eval import lanl_la6 as LA6
    t0 = time.perf_counter()
    V = LA6.vocab()
    names, lab_users = LA6.induced_users(V)
    cnt, n = LA6.fit_counts(V, "F", lab_users)
    known_a = {k: cnt["label0"][k] > 0 for k in cnt["label0"]}
    known_c = {k: cnt["all"][k] > 0 for k in cnt["all"]}
    stored = load_json(LA6.OUT)["artefacts"]["F"]
    chk = OrderedDict()
    for k, want in (("src", 298), ("user", 76), ("dst", 280)):
        got = int((known_c[k] & ~known_a[k]).sum())
        chk[k] = OrderedDict([
            ("keys_only_in_c_rebuilt", got), ("declared", want),
            ("stored", stored[k]["keys_only_in_c"]),
            ("stored_path", f"lanl_la6_controls.json artefacts/F/{k}/keys_only_in_c"),
            ("map_keys_a_rebuilt", int(known_a[k].sum())), ("map_keys_a_stored", stored[k]["map_keys_a"]),
            ("equal", got == want == stored[k]["keys_only_in_c"] and int(known_a[k].sum()) == stored[k]["map_keys_a"])])
    chk["fitting_rows_a"] = {"rebuilt": int(n["label0"]), "stored": stored["fitting_rows_a"],
                             "equal": int(n["label0"]) == stored["fitting_rows_a"]}
    print("L1", json.dumps(chk, indent=1), flush=True)
    out = load_out()
    out["L"] = OrderedDict([("L1_key_count_check", chk)])
    if not all(v["equal"] for v in chk.values()):
        out["L"]["status"] = "STOPPED: rebuilt key counts differ from the stored LA6.1 counts"
        save_out(out)
        raise SystemExit(out["L"]["status"])
    t_fit = time.perf_counter() - t0

    fields = OrderedDict([("src", "source-computer frequency map (src_computer) -> src_freq; "
                                  "also the known-source-computer set -> is_new_src (same keys)"),
                          ("user", "source-user frequency map (src_user) -> user_freq"),
                          ("dst", "destination-computer frequency map (dst_computer) -> dst_freq")])
    scopes = OrderedDict([("days_8_11", list(range(8, 12))), ("days_12_13", [12, 13])])
    res = OrderedDict()
    for scope, days in scopes.items():
        ys, yi, ab = [], [], {k: [] for k in fields}
        for d in days:
            z, c = LA6.day_arrays(d)
            ys.append(z["y"].astype(bool))
            yi.append(lab_users[c["user"]])
            for k in fields:
                ab[k].append(~known_a[k][c[k]])
        y_true, y_ind = np.concatenate(ys), np.concatenate(yi)
        res[scope] = OrderedDict()
        for k, desc in fields.items():
            a = np.concatenate(ab[k])
            res[scope][k] = OrderedDict([("artefact", desc),
                                         ("induced_label_primary", indicator_metrics(y_ind, a)),
                                         ("true_redteam_label", indicator_metrics(y_true, a))])
            print(scope, k, "induced", round(res[scope][k]["induced_label_primary"]["roc_auc"], 6),
                  "true", round(res[scope][k]["true_redteam_label"]["roc_auc"], 6), flush=True)
    out["L"].update([
        ("protocol", "eval/PROTOCOL_LANL.md LA8 under eval/PROTOCOL.md amendment 11.9.4 (descriptive)"),
        ("data", "LANL dev: maps rebuilt from days 0-7 per-day codes (eval.lanl_la6.fit_counts, label 'F'); "
                 "indicators on days 8-11 and 12-13; no day from 14 read; no model fitted"),
        ("labels", OrderedDict([("induced_label_primary", "LA6.1: every row of the 86 red-team source users"),
                                ("true_redteam_label", "event-level red-team label (D feature files, y)")])),
        ("artefact_note", "is_new_src is built from the known-source-computer set, which has the same keys as the "
                          "source-computer frequency map, so its indicator is identical and is reported once"),
        ("L2", res),
        ("seconds", OrderedDict([("rebuild_and_check", round(t_fit, 1)),
                                 ("total", round(time.perf_counter() - t0, 1))])),
    ])
    save_out(out)
    return 0


# ── Task M: share of the Task H contrast ─────────────────────────────────────

def stage_share(args):
    from eval import amendment11_7_la7 as H
    from eval import phase3b as P3B
    clk = A11.Clock()
    t = time.time()
    S = P3B.stream()
    clk.tick("load dev stream (datasets.load('dev'))", t)
    stored_H = load_json(H.OUT)["H"]["splits"]
    rows = np.flatnonzero(S.val)
    a_real = -np.asarray(np.load(P3B.ML_DECISION, mmap_mode="r")[:S.n], np.float64)[rows]
    y_real = S.truth[rows]
    ip_val = S.ip[rows]
    draws = H.matched_labels(S)
    res = OrderedDict()
    for h in HALVES:
        m = S.halves[h][rows]
        pairs = OrderedDict([("a", (y_real[m], a_real[m]))])
        for d, inS in draws.items():
            pairs[f"draw_{d}"] = (inS[S.ip][rows][m],
                                  np.load(A11.cpath(f"matched_a_prime_draw{d}_seed42_val.npy"))[m])
        t = time.time()
        boot, K = H.paired_bootstrap(ip_val[m], pairs)
        clk.tick(f"{h}: paired cluster bootstrap rerun ({K:,} addresses)", t)
        sh = stored_H[h]
        auc_a = sh["auc_a"]["value"]
        res[h] = OrderedDict([("clusters", K), ("auc_a", {"value": auc_a, "source":
                              f"amendment11_7_la7.json H/splits/{h}/auc_a/value"})])
        for d in draws:
            k = f"draw_{d}"
            auc_ap = sh[k]["auc_a_prime"]["value"]
            diff_iv = A11.pct_interval(boot["a"] - boot[k])
            share_b = (boot["a"] - boot[k]) / (boot["a"] - 0.5)
            res[h][k] = OrderedDict([
                ("auc_a_prime", {"value": auc_ap, "source": f"amendment11_7_la7.json H/splits/{h}/{k}/auc_a_prime/value"}),
                ("difference", {"value": sh[k]["difference_a_minus_a_prime"],
                                "source": f"amendment11_7_la7.json H/splits/{h}/{k}/difference_a_minus_a_prime"}),
                ("difference_interval_rerun", diff_iv),
                ("difference_interval_task_H", sh[k]["difference_interval"]),
                ("difference_interval_reproduces", diff_iv == dict(sh[k]["difference_interval"])),
                ("share", (auc_a - auc_ap) / (auc_a - 0.5)),
                ("share_interval", A11.pct_interval(share_b)),
                ("prediction", None),
            ])
            print(h, k, res[h][k]["difference_interval_reproduces"], res[h][k]["share"], res[h][k]["share_interval"],
                  flush=True)
    if not all(res[h][f"draw_{d}"]["difference_interval_reproduces"] for h in HALVES for d in draws):
        raise SystemExit("Task H differences did not reproduce; share not reported")
    out = load_out()
    out["M"] = OrderedDict([
        ("quantity", "(AUC_a - AUC_a') / (AUC_a - 0.5); descriptive, not declared in advance, no pass or fail"),
        ("bootstrap", "rerun of the Task H specification (eval.amendment11_7_la7.paired_bootstrap): 1,000 "
                      "resamples of source addresses, Generator(PCG64(42)), the same resampled rows for numerator "
                      "and denominator; share recomputed per resample; 2.5/97.5 percentiles"),
        ("splits", res), ("timings_seconds", clk.total())])
    save_out(out)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["rba", "lanl", "share"])
    args = ap.parse_args()
    return {"rba": stage_rba, "lanl": stage_lanl, "share": stage_share}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
