# backend/eval/lanl_final.py
"""
LANL phase L3: the one test evaluation (LA3.9), running exactly LA3.4 to LA3.8
as corrected by LA4, with state carried from val_b.

The L2 code is imported, not copied:
  A    eval.lanl_a.Twin (rules, triage, step-up, email), carried from day 0
  D    eval.lanl_d.State / day_features (D2, D3, D1 features), carried from
       day 0; D1 = the saved L2 model (SHA-256 checked), scored with
       eval.phase2_baseline.score_samples
  labels  eval.lanl_la3.label_day (LA3.1), filter_mask (LA3.3)
  metrics eval.lanl_a_metrics.main (A, LA3.6/LA3.7) and
          eval.lanl_d_metrics.main (D, LA3.6/LA3.7)
They read days through eval.lanl_la3.day_table, the red-team frame through
lanl_la3.redteam_dev, splits through lanl_la3.split_days, and write through
lanl_la3.save_json. This script points those four at the run's target split:
every auth day comes from eval.lanl_data.load_lanl(<split>, "auth",
by_day=True), so test days are read only through the guarded loader, with
this run's ID in every access-log line.

  python -m eval.lanl_final --dry-run        target val_b, FINAL_EVAL unset;
                                             must reproduce the saved L2 val_b
                                             results exactly
  FINAL_EVAL=1 python -m eval.lanl_final     target test (days 14 to the test
                                             end), the one evaluation run
  python -m eval.lanl_final --estimate       runtime / memory estimate for the
                                             test from saved L2 throughput

Outputs: results/lanl_final_*.json (test) or results/lanl_final_dryrun_check.json;
per-day arrays and score arrays under <work>/final_<tag>/ (outside the repo).
"""

import argparse
import datetime as _dt
import gc
import hashlib
import json
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

from eval import lanl_a as A  # noqa: E402
from eval import lanl_a_metrics as AM  # noqa: E402
from eval import lanl_d as D  # noqa: E402
from eval import lanl_d_metrics as DM  # noqa: E402
from eval import lanl_data  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402
from eval import lanl_split  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

ALL_COLS = ["time", "src_user", "src_computer", "dst_computer", "success"]
LABEL_COLS = ["time", "src_user", "src_computer", "dst_computer"]
SCORERS = ("D1", "D2", "D3")

# originals, captured before any redirection
ORIG = {"day_table": L.day_table, "split_days": L.split_days, "redteam_dev": L.redteam_dev,
        "save_json": L.save_json, "adir": A.adir, "ddir": D.ddir}
L2_D_DIR = D.ddir()


def c3_day():
    with open(lanl_data.LOCK_FILE, encoding="utf-8") as f:
        return json.load(f)["c3"]["day"]


def test_end_day():
    with open(lanl_data.LOCK_FILE, encoding="utf-8") as f:
        return json.load(f)["l1_auth_test"]["test_end_day"]


def split_of(d):
    if d >= c3_day():
        return "test"
    for s, (lo, hi) in ORIG["split_days"]().items():
        if lo <= d < hi:
            return s
    raise ValueError(d)


class Days:
    """Day tables in day order, one iterator per split per pass, all through
    load_lanl(..., by_day=True). Only the current day is held in memory."""

    def __init__(self, run_id):
        self.run_id = run_id
        self.test_opens = 0
        self.reset()

    def reset(self):
        self.it, self.split, self.cur, self.last = None, None, (None, None), None

    def get(self, d):
        if self.cur[0] == d:
            return self.cur[1]
        sp = split_of(d)
        if self.it is None or self.split != sp or (self.last is not None and d <= self.last):
            self.it = lanl_data.load_lanl(sp, "auth", columns=ALL_COLS, by_day=True,
                                          run_id=self.run_id if sp == "test" else None)
            self.split, self.last = sp, None
            self.test_opens += sp == "test"
        self.cur = (None, None)
        for dd, tbl in self.it:
            self.last = dd
            if dd == d:
                self.cur = (dd, tbl)
                return tbl
            if dd > d:
                break
        raise KeyError(f"day {d} not found in split {sp}")

    def table(self, d, columns=None):
        t = self.get(d)
        return t if columns is None else t.select(columns)


def redteam_frame(target, run_id):
    rt = ORIG["redteam_dev"]()
    if target != "test":
        return rt
    t0 = lanl_split.load_t0()
    rows = lanl_data.load_lanl("test", "redteam", run_id=run_id)
    te = pd.DataFrame(rows, columns=["time", "user", "src_computer", "dst_computer"])
    te["split"] = "test"
    te["event"] = len(rt) + np.arange(len(te))
    te["day"] = lanl_split.day(te["time"].to_numpy(), t0)
    seen = set(rt.loc[rt["day"] < c3_day(), "user"])          # LA1.5: before the test starts
    te["returning_user"] = te["user"].isin(seen).to_numpy()
    return pd.concat([rt, te], ignore_index=True)


def writer(out_dir, names):
    def save(name, obj):
        path = os.path.join(out_dir, names.get(name, name))
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2, default=L._jsonable)
            f.write("\n")
        return path
    return save


def load_model():
    with open(os.path.join(L.RESULTS, "lanl_d_fit.json"), encoding="utf-8") as f:
        fit = json.load(f)
    path = os.path.join(L2_D_DIR, "d1_model.pkl")
    with open(path, "rb") as fh:
        raw = fh.read()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != fit["model_sha256"]:
        raise RuntimeError("D1 model SHA-256 differs from L2")
    return pickle.loads(raw), sha


def verdict(dres):
    """LA3.8 on the test's all-users block of the D metrics."""
    out = OrderedDict()
    for s in SCORERS:
        x = dres["test"]["all"][s]
        t = x["top1000"]
        auc_lo = (x.get("roc_auc_ci95") or [None])[0]
        lift_lo = (t.get("lift_ci95") or [None])[0]
        share = t["all_redteam"]["users_caught"] / t["all_redteam"]["users"]
        c1 = auc_lo is not None and auc_lo > 0.50
        c2 = lift_lo is not None and lift_lo >= 10
        c3 = share >= 0.20
        out[s] = OrderedDict([
            ("roc_auc_ci95_lower", auc_lo), ("cond1_roc_auc_lower_gt_0.50", bool(c1)),
            ("k1000_lift_ci95_lower", lift_lo), ("cond2_k1000_lift_lower_ge_10", bool(c2)),
            ("k1000_users_caught", t["all_redteam"]["users_caught"]),
            ("test_redteam_users", t["all_redteam"]["users"]),
            ("k1000_users_caught_share", share), ("cond3_k1000_users_share_ge_0.20", bool(c3)),
            ("verdict", "works" if (c1 and c2 and c3) else "does not work")])
    return out


def run(target, run_id, tag, results_names, out_dir):
    from eval import phase2_baseline as P2
    t_all = time.perf_counter()
    if target == "test":
        lo, hi = c3_day(), test_end_day() + 1
    else:
        lo, hi = ORIG["split_days"]()[target]
    work = L.wpath(f"final_{tag}")
    a_dir, d_dir = os.path.join(work, "a"), os.path.join(work, "d")
    os.makedirs(a_dir, exist_ok=True)
    os.makedirs(d_dir, exist_ok=True)
    (model_b, sha) = load_model()
    with open(os.path.join(L2_D_DIR, "maps.pkl"), "rb") as fh:
        maps = pickle.load(fh)["maps"]

    days = Days(run_id)
    rt = redteam_frame(target, run_id)
    L.day_table = lambda d, columns=None: days.table(d, columns)
    L.split_days = lambda: {target: (lo, hi)}
    L.redteam_dev = lambda: rt
    L.save_json = writer(out_dir, results_names)
    A.adir = lambda tag_: a_dir
    D.ddir = lambda: d_dir

    tw = A.Twin()
    S = D.State(maps)
    clk = Counter()
    offset = 0
    facts = {"positive_rows": 0, "matched_events": set(), "events_passing_filter": set()}
    stepup = OrderedDict()
    timing = Counter()
    for d in range(0, hi):
        t = time.perf_counter()
        tbl = days.get(d)
        timing["read"] += time.perf_counter() - t
        t = time.perf_counter()
        r = tw.day_pass(d, offset, clk)
        timing["A_twin"] += time.perf_counter() - t
        t = time.perf_counter()
        fz = D.day_features(S, d, offset)
        timing["D_features"] += time.perf_counter() - t
        if lo <= d < hi:
            np.savez(os.path.join(a_dir, f"day={d:02d}.npz"), **r)
            lt = tbl.select(LABEL_COLS)
            pos_mask, per_event, pairs = L.label_day(lt, rt[rt["day"] == d])
            keep = L.filter_mask(tbl)
            z = {k: fz[k] for k in ("rows", "pos", "user", "d2", "d3", "n_day")}
            z["y"] = pos_mask[fz["rows"]]
            z["pairs_row"] = pairs["row"].to_numpy().astype(np.int64)
            z["pairs_event"] = pairs["event"].to_numpy().astype(np.int64)
            np.savez(os.path.join(d_dir, f"day={d:02d}.npz"), **z)
            t = time.perf_counter()
            s1 = -P2.score_samples(model_b["model"], model_b["scaler"].transform(fz["X"]))
            np.save(os.path.join(d_dir, f"d1_day={d:02d}.npy"), s1)
            timing["D1_score"] += time.perf_counter() - t
            facts["positive_rows"] += int(pos_mask.sum())
            facts["matched_events"].update(int(e) for e in per_event)
            if len(pairs):
                ok = keep[pairs["row"].to_numpy()]
                facts["events_passing_filter"].update(int(e) for e in pairs["event"].to_numpy()[ok])
            comp = np.asarray(tbl.column("src_computer").take(r["a_pos"]).to_numpy(zero_copy_only=False),
                              dtype=object)
            last_tier = pd.Series(r["tier_ev"]).groupby(comp, sort=False).last()
            stepup[f"{d:02d}"] = int((last_tier.to_numpy() == 1).sum())
        offset += tbl.num_rows
        del tbl, r, fz
        print(f"day {d:02d} done ({time.perf_counter() - t_all:.0f} s)", flush=True)
    tw.notifier.flush()
    del tw, S
    days.reset()
    gc.collect()
    peak_pass1 = peak_working_set()

    ev = rt[rt["split"] == target]
    labels = OrderedDict([
        ("redteam_events", int(len(ev))), ("redteam_users", int(ev["user"].nunique())),
        ("matched_events", len(facts["matched_events"])),
        ("unmatched_events", int(len(ev)) - len(facts["matched_events"])),
        ("positive_rows", facts["positive_rows"]),
        ("events_passing_filter", len(facts["events_passing_filter"])),
        ("users_passing_filter", int(ev.loc[ev["event"].isin(facts["events_passing_filter"]), "user"].nunique()))])

    t = time.perf_counter()
    AM.main()
    timing["A_metrics"] += time.perf_counter() - t
    t = time.perf_counter()
    DM.main(splits=(target,))
    timing["D_metrics"] += time.perf_counter() - t
    return {"target": target, "days": [lo, hi], "run_id": run_id, "d1_model_sha256": sha,
            "labels": labels, "step_up_incidents_per_day": stepup,
            "test_iterator_opens": days.test_opens,
            "seconds": {k: round(v, 1) for k, v in timing.items()},
            "seconds_total": round(time.perf_counter() - t_all, 1),
            "peak_working_set_bytes_pass1": peak_pass1,
            "peak_working_set_bytes": peak_working_set(), "work_dir": work}


def same(a, b, path=""):
    """Exact equality of two JSON values; returns the first differing path."""
    if type(a) is not type(b):
        return path or "/"
    if isinstance(a, dict):
        if set(a) != set(b):
            return path + f" keys {sorted(set(a) ^ set(b))}"
        for k in a:
            r = same(a[k], b[k], f"{path}/{k}")
            if r:
                return r
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return path + " length"
        for i, (x, y) in enumerate(zip(a, b)):
            r = same(x, y, f"{path}[{i}]")
            if r:
                return r
        return None
    return None if a == b else path


def dry_run():
    assert os.environ.get("FINAL_EVAL") != "1", "the dry run must not open the test"
    out_dir = L.wpath("final_dryrun_out")
    os.makedirs(out_dir, exist_ok=True)
    names = {"lanl_a_dev.json": "a.json", "lanl_d_dev.json": "d.json"}
    info = run("val_b", None, "dryrun", names, out_dir)
    with open(os.path.join(out_dir, "a.json")) as f:
        a_new = json.load(f)
    with open(os.path.join(out_dir, "d.json")) as f:
        d_new = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_a_dev.json")) as f:
        a_old = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_d_dev.json")) as f:
        d_old = json.load(f)
    chk = OrderedDict()
    chk["A_val_b_first_difference"] = same(a_new["val_b"], a_old["val_b"])
    chk["D_val_b_first_difference"] = same(d_new["val_b"], d_old["val_b"])
    chk["D_sklearn_checks_first_difference"] = same(
        {k: v for k, v in d_new["check_strict_ranking_vs_sklearn"].items()},
        {k: v for k, v in d_old["check_strict_ranking_vs_sklearn"].items() if k.startswith("val_b:")})
    arrays = {}
    l2a = os.path.join(L.wpath("a_causal"))
    for d in range(*ORIG["split_days"]()["val_b"]):
        za = np.load(os.path.join(info["work_dir"], "a", f"day={d:02d}.npz"))
        zo = np.load(os.path.join(l2a, f"day={d:02d}.npz"))
        arrays[f"A_day{d}"] = all(np.array_equal(za[k], zo[k]) for k in zo.files)
        zd = np.load(os.path.join(info["work_dir"], "d", f"day={d:02d}.npz"))
        zdo = np.load(os.path.join(L2_D_DIR, f"day={d:02d}.npz"))
        arrays[f"D_day{d}"] = all(np.array_equal(zd[k], zdo[k]) for k in zd.files)
        arrays[f"D1_day{d}"] = bool(np.array_equal(
            np.load(os.path.join(info["work_dir"], "d", f"d1_day={d:02d}.npy")),
            np.load(os.path.join(L2_D_DIR, f"d1_day={d:02d}.npy"))))
    chk["arrays_equal_L2"] = arrays
    chk["reproduces_L2_exactly"] = (chk["A_val_b_first_difference"] is None
                                   and chk["D_val_b_first_difference"] is None
                                   and chk["D_sklearn_checks_first_difference"] is None
                                   and all(arrays.values()))
    chk["run"] = {k: v for k, v in info.items() if k != "work_dir"}
    ORIG["save_json"]("lanl_final_dryrun_check.json", chk)
    print(json.dumps({k: v for k, v in chk.items() if k != "run"}, indent=1))
    return 0 if chk["reproduces_L2_exactly"] else 1


def final():
    assert os.environ.get("FINAL_EVAL") == "1", "set FINAL_EVAL=1 for the evaluation run"
    run_id = f"L3-{_dt.datetime.now().strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    print("run_id", run_id, flush=True)
    names = {"lanl_a_dev.json": "lanl_final_a.json", "lanl_d_dev.json": "lanl_final_d.json"}
    info = run("test", run_id, "test", names, L.RESULTS)
    with open(os.path.join(L.RESULTS, "lanl_final_d.json")) as f:
        dres = json.load(f)
    info["verdict_la3_8"] = verdict(dres)
    ORIG["save_json"]("lanl_final_run.json", info)
    print(json.dumps(info["verdict_la3_8"], indent=1))
    return 0


def estimate():
    R = L.RESULTS
    ld = lambda n: json.load(open(os.path.join(R, n), encoding="utf-8"))   # noqa: E731
    twin = ld("lanl_a_twin_causal.json")
    feat = ld("lanl_d_features.json")
    score = ld("lanl_d_score.json")
    checks = ld("lanl_l2_checks.json")
    dmet = ld("lanl_d_dev.json")
    amet = ld("lanl_a_dev.json")
    with open(lanl_data.LOCK_FILE, encoding="utf-8") as f:
        test_rows = json.load(f)["l1_auth_test"]["test_rows_total"]
    dev_rows = twin["events"]
    share = max(v["filtered_share"] for v in checks["splits"].values())
    filt_test = test_rows * share
    twin_rps = dev_rows / twin["seconds"]
    feat_rps = dev_rows / feat["seconds"]
    d1_rps = score["val_a"]["rows"] / score["val_a"]["seconds"]
    val_rows = dmet["val_a"]["filtered_rows"] + dmet["val_b"]["filtered_rows"]
    dmet_rps = val_rows / dmet["seconds"]
    amet_rps = sum(c["rows"] for k, c in checks["splits"].items()) / amet["seconds"]
    dm_bytes_per_row = (dmet["peak_working_set_bytes"]) / dmet["val_a"]["filtered_rows"]
    out = OrderedDict([
        ("test_rows_from_lock", test_rows), ("dev_rows", dev_rows),
        ("dev_max_filtered_share", share), ("assumed_test_filtered_rows", round(filt_test)),
        ("twin_rows_per_s_L2", twin_rps), ("d_features_rows_per_s_L2", feat_rps),
        ("d1_score_rows_per_s_L2", d1_rps), ("d_metrics_rows_per_s_L2", dmet_rps),
        ("a_metrics_rows_per_s_L2", amet_rps),
        ("est_seconds", OrderedDict([
            ("dev_days_rerun_twin_and_features", round(dev_rows / twin_rps + dev_rows / feat_rps)),
            ("test_twin", round(test_rows / twin_rps)),
            ("test_d_features", round(test_rows / feat_rps)),
            ("test_d1_scoring", round(filt_test / d1_rps)),
            ("test_a_metrics", round(test_rows / amet_rps)),
            ("test_d_metrics", round(filt_test / dmet_rps))])),
        ("d1_scoring_over_3h", filt_test / d1_rps > 3 * 3600),
        ("peak_twin_L2_bytes", twin["peak_working_set_bytes"]),
        ("d_metrics_L2_peak_bytes_per_val_a_row", dm_bytes_per_row),
        ("est_d_metrics_peak_bytes_linear", round(dm_bytes_per_row * filt_test)),
    ])
    out["est_seconds_total"] = sum(out["est_seconds"].values())
    ORIG["save_json"]("lanl_final_estimate.json", out)
    print(json.dumps(out, indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--estimate", action="store_true")
    args = ap.parse_args()
    if args.estimate:
        return estimate()
    if args.dry_run:
        return dry_run()
    return final()


if __name__ == "__main__":
    sys.exit(main())
