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
    if target == DEV_ALL:                 # memory measurement only: all dev days as one split
        rt = rt.copy()
        rt.loc[rt["day"] < c3_day(), "split"] = DEV_ALL
        return rt
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


def _strip(s):
    """Same as lanl_a's / lanl_d's lambda s: str(s).strip(), but picklable."""
    return str(s).strip()


def mem():
    """Process memory now: private commit, its peak, working set, its peak."""
    import ctypes
    import ctypes.wintypes as wt
    from eval.lanl_convert import _PMC
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.K32GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(_PMC), wt.DWORD]
    k32.K32GetProcessMemoryInfo.restype = wt.BOOL
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(pmc)
    if not k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        raise OSError("K32GetProcessMemoryInfo failed")
    return {"private": pmc.PagefileUsage, "peak_private": pmc.PeakPagefileUsage,
            "ws": pmc.WorkingSetSize, "peak_ws": pmc.PeakWorkingSetSize}


class ForcedStop(SystemExit):
    pass


def target_days(target):
    if target == "test":
        return c3_day(), test_end_day() + 1
    if target == DEV_ALL:
        return 0, c3_day()
    return ORIG["split_days"]()[target]


def out_of(target, tag):
    """(directory, file names) for a run's A and D metric JSON."""
    if target == "test":
        return L.RESULTS, {"lanl_a_dev.json": "lanl_final_a.json", "lanl_d_dev.json": "lanl_final_d.json"}
    return L.wpath(f"final_{tag}_out"), DRY_NAMES


def p1_main(target, tag, run_id, resume=False, stop_after=None):
    """Process 1 entry point: run() and its info to <work>/p1.json."""
    if target == "test":
        assert os.environ.get("FINAL_EVAL") == "1"
    else:
        assert os.environ.get("FINAL_EVAL") != "1", "the dry run must not open the test"
    out_dir, names = out_of(target, tag)
    os.makedirs(out_dir, exist_ok=True)
    info = run(target, run_id, tag, names, out_dir, resume=resume, stop_after=stop_after)
    with open(os.path.join(info["work_dir"], "p1.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2, default=L._jsonable)
    return 0


def d_process(target, tag, run_id, scorer, crosscheck=True):
    """Process 2 (one scorer): the D metrics in a fresh process, reading the
    arrays process 1 left in <work>/d. Output <work>/d_<scorer>.json and its
    memory to <work>/p2_<scorer>.json. On the test the red-team frame is read
    through load_lanl("test", "redteam") with the run's ID. crosscheck=False
    (dev memory measurement only): the sklearn cross-check is off, as it is on
    the test, and the outputs go to d_<scorer>_nocheck.json / p2_<scorer>_nocheck.json."""
    sfx = "" if crosscheck else "_nocheck"
    if not crosscheck:
        assert target != "test"
        DM.CHECK_MAX_ROWS = 0
    if target == "test":
        assert os.environ.get("FINAL_EVAL") == "1"
    else:
        assert os.environ.get("FINAL_EVAL") != "1", "the dry run must not open the test"
    t = time.perf_counter()
    m0 = mem()
    work = L.wpath(f"final_{tag}")
    lo, hi = target_days(target)
    rt = redteam_frame(target, run_id)
    L.split_days = lambda: {target: (lo, hi)}
    L.redteam_dev = lambda: rt
    L.day_table = None                     # process 2 reads no auth day
    L.save_json = writer(work, {"lanl_d_dev.json": f"d_{scorer}{sfx}.json"})
    D.ddir = lambda: os.path.join(work, "d")
    m1 = mem()
    DM.main(splits=(target,), scorers=(scorer,))
    info = {"target": target, "scorer": scorer, "run_id": run_id, "memory_start": m0,
            "memory_before_d_metrics": m1, "memory_end": mem(),
            "seconds": round(time.perf_counter() - t, 1)}
    with open(os.path.join(work, f"p2_{scorer}{sfx}.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=2)
    return 0


def merge_d(work, target):
    """The per-scorer D JSON merged into the single-process layout of
    lanl_d_metrics.main (same keys, same order); the scorer-independent fields
    must agree across the three."""
    parts = {}
    for s in SCORERS:
        with open(os.path.join(work, f"d_{s}.json"), encoding="utf-8") as f:
            parts[s] = json.load(f, object_pairs_hook=OrderedDict)
    first = parts[SCORERS[0]]
    sp = OrderedDict()
    for k, v in first[target].items():
        if isinstance(v, dict):
            shared = OrderedDict((kk, vv) for kk, vv in v.items() if kk not in SCORERS)
            blk = OrderedDict(shared)
            for s in SCORERS:
                assert same(OrderedDict((kk, vv) for kk, vv in parts[s][target][k].items()
                                        if kk not in SCORERS), shared) is None, (s, k)
                blk[s] = parts[s][target][k][s]
            sp[k] = blk
        else:
            for s in SCORERS:
                assert parts[s][target][k] == v, (s, k)
            sp[k] = v
    res = OrderedDict([(target, sp)])
    res["check_strict_ranking_vs_sklearn"] = OrderedDict(
        (f"{target}:{s}", parts[s]["check_strict_ranking_vs_sklearn"][f"{target}:{s}"]) for s in SCORERS)
    for s in SCORERS:
        assert parts[s]["definitions"] == first["definitions"]
    res["definitions"] = first["definitions"]
    res["seconds"] = round(sum(parts[s]["seconds"] for s in SCORERS), 1)
    res["peak_working_set_bytes"] = max(parts[s]["peak_working_set_bytes"] for s in SCORERS)
    return res


def _child(args):
    import subprocess
    cmd = [sys.executable, "-m", "eval.lanl_final", *args]
    print(">>", " ".join(args), flush=True)
    return subprocess.run(cmd, cwd=BACKEND, env=os.environ.copy()).returncode


PROJ_FILE = "lanl_final_projection_devall.json"
DEV_ALL = "dev_all"


def bar_check(process):
    """The memory bar for one process, now: its committed projected peak
    against 80% of free commit and 80% of free physical RAM."""
    with open(os.path.join(L.RESULTS, PROJ_FILE), encoding="utf-8") as f:
        proj = json.load(f)["projected_peak_bytes"][process]
    fc = free_commit()
    out = OrderedDict([("process", process), ("time", _dt.datetime.now().isoformat(timespec="seconds")),
                       ("projected_peak_bytes", proj), *fc.items(),
                       ("limit_80pct_free_commit_bytes", 0.8 * fc["free_commit_bytes"]),
                       ("limit_80pct_free_physical_bytes", 0.8 * fc["free_physical_bytes"])])
    out["passes"] = bool(proj <= out["limit_80pct_free_commit_bytes"]
                         and proj <= out["limit_80pct_free_physical_bytes"])
    print("bar", json.dumps(out), flush=True)
    return out


def orchestrate(target, tag, run_id, resume=False, stop_after=None, skip_p1=False, gate=False):
    """One run: process 1, then one process 2 per scorer, sequentially, each a
    fresh Python process with the same run ID. gate=True checks the memory bar
    immediately before each process and stops (exit 4) without starting it if
    the bar fails. Scorers whose output already exists for this run ID are not
    rerun. Returns (exit code, record)."""
    work = L.wpath(f"final_{tag}")
    rec = OrderedDict([("run_id", run_id), ("bar_checks", [])])
    rid = [] if run_id is None else ["--run-id", run_id]
    if not skip_p1:
        if gate:
            b = bar_check("p1")
            rec["bar_checks"].append(b)
            if not b["passes"]:
                return 4, rec
        args = ["--p1", "--target", target, "--tag", tag, *rid]
        if resume:
            args.append("--resume")
        if stop_after is not None:
            args += ["--stop-after", str(stop_after)]
        rc = _child(args)
        if rc:
            return rc, rec
    with open(os.path.join(work, "p1.json"), encoding="utf-8") as f:
        p1 = json.load(f)
    if target == "test" and not resume:
        assert p1["run_id"] == run_id, "process 1 ran under another run ID"
    rec["p1"] = p1
    rec["p2"] = OrderedDict()
    for s in SCORERS:
        done = os.path.join(work, f"p2_{s}.json")
        if os.path.exists(done):
            with open(done, encoding="utf-8") as f:
                prev = json.load(f)
            if prev["run_id"] == run_id and run_id is not None:
                rec["p2"][s] = prev
                continue
        if gate:
            b = bar_check(f"p2_{s}")
            rec["bar_checks"].append(b)
            if not b["passes"]:
                return 4, rec
        rc = _child(["--p2", "--target", target, "--tag", tag, "--scorer", s, *rid])
        if rc:
            return rc, rec
        with open(done, encoding="utf-8") as f:
            rec["p2"][s] = json.load(f)
    out_dir, names = out_of(target, tag)
    d = merge_d(work, target)
    with open(os.path.join(out_dir, names["lanl_d_dev.json"]), "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, indent=2, default=L._jsonable)
        f.write("\n")
    return 0, rec


def run(target, run_id, tag, results_names, out_dir, resume=False, stop_after=None):
    """Process 1: pass 1 over days 0 .. last target day (state carried from
    day 0), with a checkpoint of the whole state after every day; then the A
    metrics. The D score arrays and per-day outputs stay on disk for process 2
    (d_process). resume=True continues from the checkpoint's next day."""
    from eval import phase2_baseline as P2
    t_all = time.perf_counter()
    mem_start = mem()
    lo, hi = target_days(target)
    work = L.wpath(f"final_{tag}")
    a_dir, d_dir = os.path.join(work, "a"), os.path.join(work, "d")
    os.makedirs(a_dir, exist_ok=True)
    os.makedirs(d_dir, exist_ok=True)
    ckpt = os.path.join(work, "checkpoint.pkl")
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

    resumed = None
    if resume:
        with open(ckpt, "rb") as fh:
            st = pickle.load(fh)
        assert st["target"] == target
        tw, S, offset, facts, stepup = st["tw"], st["S"], st["offset"], st["facts"], st["stepup"]
        timing, curve, start = st["timing"], st["curve"], st["next_day"]
        resumed = {"from_day": start, "previous_run_id": st["run_id"]}
    else:
        tw = A.Twin()
        S = D.State(maps)
        tw.ipc.norm = S.uc.norm = S.cc.norm = _strip
        offset, start = 0, 0
        facts = {"positive_rows": 0, "matched_events": set(), "events_passing_filter": set()}
        stepup = OrderedDict()
        timing, curve = Counter(), []
    clk = Counter()
    for d in range(start, hi):
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
        days.cur = (None, None)
        gc.collect()
        curve.append({"day": d, **mem()})
        t = time.perf_counter()
        with open(ckpt + ".tmp", "wb") as fh:
            pickle.dump({"target": target, "run_id": run_id, "next_day": d + 1, "tw": tw, "S": S,
                         "offset": offset, "facts": facts, "stepup": stepup, "timing": timing,
                         "curve": curve}, fh, protocol=5)
        os.replace(ckpt + ".tmp", ckpt)
        timing["checkpoint"] += time.perf_counter() - t
        print(f"day {d:02d} done ({time.perf_counter() - t_all:.0f} s; "
              f"private {curve[-1]['private'] / 2**30:.2f} GiB; checkpoint "
              f"{os.path.getsize(ckpt) / 2**30:.2f} GiB)", flush=True)
        if stop_after is not None and d == stop_after:
            print(f"forced stop after day {d:02d}", flush=True)
            raise ForcedStop(3)
    tw.notifier.flush()
    ckpt_bytes = os.path.getsize(ckpt)
    del tw, S
    days.reset()
    gc.collect()
    peak_pass1 = peak_working_set()
    mem_released = mem()          # right after pass 1's state is released

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
    mem_after_a = mem()           # after the A metrics; process 1 ends here
    return {"target": target, "days": [lo, hi], "run_id": run_id, "d1_model_sha256": sha,
            "resumed": resumed, "memory_start": mem_start, "memory_curve_pass1": curve,
            "checkpoint_bytes": ckpt_bytes, "memory_after_pass1_release": mem_released,
            "memory_after_a_metrics": mem_after_a, "memory_end": mem(),
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


DRY_NAMES = {"lanl_a_dev.json": "a.json", "lanl_d_dev.json": "d.json"}


def dry_run(tag="dryrun", stop_after=None, resume=False):
    """val_b with FINAL_EVAL unset. tag "dryrun" (uninterrupted) is checked
    against L2; other tags are checked against the "dryrun" outputs."""
    assert os.environ.get("FINAL_EVAL") != "1", "the dry run must not open the test"
    out_dir = L.wpath(f"final_{tag}_out")
    os.makedirs(out_dir, exist_ok=True)
    work = L.wpath(f"final_{tag}")
    for s in SCORERS:                       # no stale per-scorer outputs
        for name in (f"p2_{s}.json", f"d_{s}.json"):
            if os.path.exists(os.path.join(work, name)):
                os.remove(os.path.join(work, name))
    rc, rec = orchestrate("val_b", tag, None, resume=resume, stop_after=stop_after)
    if rc:
        return rc
    info = rec["p1"]
    info["p2"] = rec["p2"]
    with open(os.path.join(out_dir, "d.json")) as f:
        info["p2_rows"] = json.load(f)["val_b"]["filtered_rows"]
    with open(os.path.join(out_dir, "run.json"), "w") as f:
        json.dump(info, f, indent=2, default=L._jsonable)
    if tag != "dryrun":
        return compare_resume(tag)
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


def compare_resume(tag):
    """Outputs of a stopped-and-resumed val_b run (tag) against the
    uninterrupted dry run: per-day arrays and files, metric JSON, labels,
    step-up incidents."""
    base, other = L.wpath("final_dryrun"), L.wpath(f"final_{tag}")
    bo, oo = L.wpath("final_dryrun_out"), L.wpath(f"final_{tag}_out")
    chk = OrderedDict()
    files = {}
    for sub in ("a", "d"):
        for name in sorted(os.listdir(os.path.join(base, sub))):
            pa_, pb_ = os.path.join(base, sub, name), os.path.join(other, sub, name)
            if name.endswith(".npz"):
                x, y = np.load(pa_), np.load(pb_)
                eq = set(x.files) == set(y.files) and all(np.array_equal(x[k], y[k]) for k in x.files)
            else:
                eq = bool(np.array_equal(np.load(pa_), np.load(pb_)))
            with open(pa_, "rb") as f1, open(pb_, "rb") as f2:
                files[f"{sub}/{name}"] = {"arrays_equal": bool(eq), "bytes_equal": f1.read() == f2.read()}
    chk["per_day_files"] = files
    skip = {"seconds", "peak_working_set_bytes"}
    for name in ("a.json", "d.json"):
        with open(os.path.join(bo, name)) as f1, open(os.path.join(oo, name)) as f2:
            x, y = json.load(f1), json.load(f2)
        chk[f"{name}_first_difference"] = same({k: v for k, v in x.items() if k not in skip},
                                               {k: v for k, v in y.items() if k not in skip})
    with open(os.path.join(bo, "run.json")) as f1, open(os.path.join(oo, "run.json")) as f2:
        x, y = json.load(f1), json.load(f2)
    for k in ("labels", "step_up_incidents_per_day"):
        chk[f"run_{k}_first_difference"] = same(x[k], y[k])
    chk["resumed"] = y["resumed"]
    chk["identical"] = (all(v["arrays_equal"] and v["bytes_equal"] for v in files.values())
                        and chk["a.json_first_difference"] is None
                        and chk["d.json_first_difference"] is None
                        and chk["run_labels_first_difference"] is None
                        and chk["run_step_up_incidents_per_day_first_difference"] is None)
    ORIG["save_json"]("lanl_final_resume_check.json", chk)
    print(json.dumps({k: v for k, v in chk.items() if k != "per_day_files"}, indent=1))
    print("per-day files identical:", all(v["arrays_equal"] and v["bytes_equal"] for v in files.values()))
    return 0 if chk["identical"] else 1


def final(resume=False, run_id=None, skip_p1=False):
    """The one evaluation run: process 1 then one process 2 per scorer, each
    gated by the memory bar measured just before it starts. resume=True is the
    one infrastructure recovery (process 1 resumes from its checkpoint under a
    new run ID). skip_p1 with run_id continues a run stopped at a bar check,
    under the same run ID, from the process-1 outputs on disk."""
    assert os.environ.get("FINAL_EVAL") == "1", "set FINAL_EVAL=1 for the evaluation run"
    if skip_p1:
        assert run_id, "continuing needs the run's ID"
    else:
        run_id = f"L3-{_dt.datetime.now().strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    print("run_id", run_id, flush=True)
    rc, rec = orchestrate("test", "test", run_id, resume=resume, skip_p1=skip_p1, gate=True)
    log = os.path.join(L.RESULTS, "lanl_final_bar_checks.json")
    prev = []
    if os.path.exists(log):
        with open(log, encoding="utf-8") as f:
            prev = json.load(f)
    with open(log, "w", encoding="utf-8", newline="\n") as f:
        json.dump(prev + [{"run_id": run_id, "exit": rc, "checks": rec["bar_checks"]}], f, indent=2)
        f.write("\n")
    if rc:
        print(f"stopped (exit {rc}); process-1 outputs stay on disk", flush=True)
        return rc
    info = {k: v for k, v in rec["p1"].items() if k != "work_dir"}
    info["p2"] = rec["p2"]
    info["bar_checks"] = rec["bar_checks"]
    with open(os.path.join(L.RESULTS, "lanl_final_d.json")) as f:
        dres = json.load(f)
    info["verdict_la3_8"] = verdict(dres)
    ORIG["save_json"]("lanl_final_run.json", info)
    print(json.dumps(info["verdict_la3_8"], indent=1))
    return 0


def measure_lean(scorer=None):
    """Peak private commit of the lean D metrics on val_a with the sklearn
    cross-check off (as it will be on the test); measurement only. scorer:
    one scorer only, output to <work>/final_leanmem_out/mem_<scorer>.json."""
    assert os.environ.get("FINAL_EVAL") != "1"
    out_dir = L.wpath("final_leanmem_out")
    os.makedirs(out_dir, exist_ok=True)
    dname = "d.json" if scorer is None else f"d_{scorer}.json"
    L.save_json = writer(out_dir, {"lanl_d_dev.json": dname})
    DM.CHECK_MAX_ROWS = 0
    before = mem()
    DM.main(splits=("val_a",), scorers=SCORERS if scorer is None else (scorer,))
    after = mem()
    with open(os.path.join(out_dir, dname)) as f:
        rows = json.load(f)["val_a"]["filtered_rows"]
    out = {"split": "val_a", "scorer": scorer, "filtered_rows": rows, "private_before": before["private"],
           "peak_private": after["peak_private"],
           "bytes_per_row": (after["peak_private"] - before["private"]) / rows}
    if scorer is None:
        ORIG["save_json"]("lanl_final_lean_memory.json", out)
    else:
        with open(os.path.join(out_dir, f"mem_{scorer}.json"), "w") as f:
            json.dump(out, f, indent=2)
    print(out)
    return 0


def measure_lean_scorers():
    """measure_lean per scorer, each in a fresh process; saved together."""
    out_dir = L.wpath("final_leanmem_out")
    res = OrderedDict()
    for s in SCORERS:
        rc = _child(["--measure-lean", "--scorer", s])
        if rc:
            return rc
        with open(os.path.join(out_dir, f"mem_{s}.json")) as f:
            res[s] = json.load(f)
    ORIG["save_json"]("lanl_final_lean_memory_scorers.json", res)
    print(json.dumps(res, indent=1))
    return 0


def project_split():
    """Memory bar per process (approved process split). Each process is
    projected from the val_b dry run of that same process (final_dryrun_out/
    run.json, written by the split dry run).
    p1 (pass 1 + A metrics): max of
      pass 1: linear fit of end-of-day private over dev days 0-13 extrapolated
        to the last test day, plus the largest within-day rise (as before);
      A metrics: the private right after pass 1's release, scaled by the
        projected end-of-pass private at the last test day over the dry run's,
        plus the dry run's largest rise above that release level up to the
        end of the A metrics (process lifetime peak minus released private).
    p2_<scorer>: the process's private before the D metrics, plus bytes per
      filtered row x the assumed test filtered rows; bytes per row is the
      larger of the val_a measurement and the val_b dry-run process, both with
      the sklearn cross-check off, as on the test (127M rows > CHECK_MAX_ROWS).
      The val_b dry-run process with the cross-check on (used for the equality
      check) is recorded but not used: that step does not run on the test.
    Bar (per process, rechecked before each starts): projected peak <= 80% of
    free commit and <= 80% of free physical RAM."""
    with open(os.path.join(L.wpath("final_dryrun_out"), "run.json")) as f:
        run_ = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_lean_memory_scorers.json")) as f:
        lean = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_estimate.json")) as f:
        est = json.load(f)
    rows_test = est["assumed_test_filtered_rows"]
    curve = run_["memory_curve_pass1"]
    dd = np.array([c["day"] for c in curve], float)
    priv = np.array([c["private"] for c in curve], float)
    peak = np.array([c["peak_private"] for c in curve], float)
    slope, icpt = np.polyfit(dd, priv, 1)
    rise = float(max(np.max(peak[1:] - priv[:-1]), peak[0]))
    last = test_end_day()
    end_test = float(icpt + slope * last)
    pass1 = end_test + rise
    scale = end_test / float(icpt + slope * dd[-1])
    rel = run_["memory_after_pass1_release"]["private"]
    a_rise = run_["memory_after_a_metrics"]["peak_private"] - rel
    a_proj = rel * scale + a_rise
    p1 = OrderedDict([
        ("dryrun_memory_start", run_["memory_start"]),
        ("dryrun_end_of_day_private", [c["private"] for c in curve]),
        ("dryrun_peak_private_pass1", curve[-1]["peak_private"]),
        ("dryrun_private_after_pass1_release", rel),
        ("dryrun_after_a_metrics", run_["memory_after_a_metrics"]),
        ("end_of_day_private_slope_bytes_per_day", float(slope)),
        ("projected_end_of_pass1_private_last_test_day", end_test),
        ("largest_within_day_rise", rise),
        ("projected_pass1_peak", pass1),
        ("residual_scale", scale),
        ("dryrun_rise_above_release_through_a_metrics", a_rise),
        ("projected_a_metrics_peak", a_proj),
        ("projected_peak", max(pass1, a_proj))])
    p2 = OrderedDict()
    for s in SCORERS:
        r = run_["p2"][s]
        vb_rows = run_["p2_rows"]
        on_bpr = (r["memory_end"]["peak_private"] - r["memory_before_d_metrics"]["private"]) / vb_rows
        with open(os.path.join(L.wpath("final_dryrun"), f"p2_{s}_nocheck.json")) as f:
            r = json.load(f)
        start = r["memory_before_d_metrics"]["private"]
        vb_bpr = (r["memory_end"]["peak_private"] - start) / vb_rows
        va_bpr = lean[s]["bytes_per_row"]
        bpr = max(vb_bpr, va_bpr)
        p2[s] = OrderedDict([
            ("dryrun_private_before_d_metrics", start),
            ("dryrun_peak_private", r["memory_end"]["peak_private"]),
            ("val_b_filtered_rows", vb_rows),
            ("val_b_bytes_per_row_crosscheck_on_not_used", on_bpr),
            ("val_b_bytes_per_row_crosscheck_off", vb_bpr),
            ("val_a_bytes_per_row_crosscheck_off", va_bpr),
            ("val_a_private_before", lean[s]["private_before"]),
            ("bytes_per_row_used", bpr),
            ("assumed_test_filtered_rows", rows_test),
            ("projected_peak", max(start, lean[s]["private_before"]) + bpr * rows_test)])
    fc = free_commit()
    lim_c, lim_p = 0.8 * fc["free_commit_bytes"], 0.8 * fc["free_physical_bytes"]
    peaks = OrderedDict([("p1", p1["projected_peak"])] + [(f"p2_{s}", p2[s]["projected_peak"]) for s in SCORERS])
    out = OrderedDict([
        ("method", project_split.__doc__.strip()),
        ("p1", p1), ("p2", p2),
        ("projected_peak_bytes", peaks),
        ("at_projection", OrderedDict([*fc.items(), ("limit_80pct_free_commit_bytes", lim_c),
                                       ("limit_80pct_free_physical_bytes", lim_p)])),
        ("passes_at_projection", OrderedDict((k, bool(v <= lim_c and v <= lim_p)) for k, v in peaks.items())),
    ])
    ORIG["save_json"](PROJ_FILE, out)
    print(json.dumps(out, indent=1))
    return 0 if all(out["passes_at_projection"].values()) else 1


def prep_dev_all():
    """Work directory final_devall/d for the dev_all memory measurement: L2's
    per-day D files for days 0-13 (hard links, unchanged) and the D1 scores,
    L2's for days 8-13 (hard links) and, for days 0-7 (L2 scored only val),
    scored here exactly as run() scores them. Measurement only."""
    from eval import phase2_baseline as P2
    assert os.environ.get("FINAL_EVAL") != "1"
    d_dir = os.path.join(L.wpath("final_devall"), "d")
    os.makedirs(d_dir, exist_ok=True)
    (model_b, sha) = load_model()
    lo, hi = target_days(DEV_ALL)
    for d in range(lo, hi):
        for name in (f"day={d:02d}.npz", f"d1_day={d:02d}.npy"):
            src, dst = os.path.join(L2_D_DIR, name), os.path.join(d_dir, name)
            if os.path.exists(src) and not os.path.exists(dst):
                os.link(src, dst)
        dst = os.path.join(d_dir, f"d1_day={d:02d}.npy")
        if not os.path.exists(dst):
            X = np.load(os.path.join(d_dir, f"day={d:02d}.npz"))["X"]
            np.save(dst, -P2.score_samples(model_b["model"], model_b["scaler"].transform(X)))
            del X
            print(f"scored D1 day {d:02d}", flush=True)
    return sha


def measure_dev_all():
    """Process 2 on all dev days 0-13 as one population, one fresh process per
    scorer, sklearn cross-check off (as on the test). Memory measurement only;
    the metric output (d_<s>_nocheck.json in the work directory) is not a
    reported result and is not looked at."""
    sha = prep_dev_all()
    work = L.wpath("final_devall")
    res = OrderedDict([("d1_model_sha256", sha)])
    for s in SCORERS:
        rc = _child(["--p2", "--target", DEV_ALL, "--tag", "devall", "--scorer", s, "--no-crosscheck"])
        if rc:
            return rc
        with open(os.path.join(work, f"p2_{s}_nocheck.json")) as f:
            r = json.load(f)
        with open(os.path.join(work, f"d_{s}_nocheck.json")) as f:
            rows = json.load(f)[DEV_ALL]["filtered_rows"]
        res[s] = OrderedDict([("filtered_rows", rows), ("private_before", r["memory_before_d_metrics"]["private"]),
                              ("peak_private", r["memory_end"]["peak_private"]), ("seconds", r["seconds"])])
    ORIG["save_json"]("lanl_final_memory_devall.json", res)
    print(json.dumps(res, indent=1))
    return 0


def project_devall():
    """Memory bar per process, process 2 re-projected from three measured
    populations per scorer (each a fresh process, sklearn cross-check off, as
    on the test): val_b (split dry run, p2_<s>_nocheck.json), val_a
    (lanl_final_lean_memory_scorers.json) and dev_all (days 0-13,
    lanl_final_memory_devall.json).
      fit: least-squares line peak private = fixed + per_row x filtered rows
        through the three points, evaluated at the assumed test filtered rows;
      ratio: dev_all peak private / dev_all rows x test rows;
      projected peak = the larger of the two.
    p1 (pass 1 + A metrics) is unchanged: taken from
    lanl_final_projection_split.json.
    Bar (per process, rechecked before each starts): projected peak <= 80% of
    free commit and <= 80% of free physical RAM."""
    with open(os.path.join(L.RESULTS, "lanl_final_projection_split.json")) as f:
        split = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_lean_memory_scorers.json")) as f:
        lean = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_memory_devall.json")) as f:
        dall = json.load(f)
    with open(os.path.join(L.wpath("final_dryrun_out"), "run.json")) as f:
        vb_rows = json.load(f)["p2_rows"]
    with open(os.path.join(L.RESULTS, "lanl_final_estimate.json")) as f:
        rows_test = json.load(f)["assumed_test_filtered_rows"]
    p2 = OrderedDict()
    for s in SCORERS:
        with open(os.path.join(L.wpath("final_dryrun"), f"p2_{s}_nocheck.json")) as f:
            vb = json.load(f)
        pts = OrderedDict([
            ("val_b", OrderedDict([("filtered_rows", vb_rows), ("peak_private", vb["memory_end"]["peak_private"])])),
            ("val_a", OrderedDict([("filtered_rows", lean[s]["filtered_rows"]),
                                   ("peak_private", lean[s]["peak_private"])])),
            (DEV_ALL, OrderedDict([("filtered_rows", dall[s]["filtered_rows"]),
                                   ("peak_private", dall[s]["peak_private"])]))])
        x = np.array([p["filtered_rows"] for p in pts.values()], float)
        y = np.array([p["peak_private"] for p in pts.values()], float)
        per_row, fixed = np.polyfit(x, y, 1)
        fit = float(fixed + per_row * rows_test)
        ratio = float(dall[s]["peak_private"] / dall[s]["filtered_rows"] * rows_test)
        p2[s] = OrderedDict([
            ("points", pts),
            ("fit_fixed_bytes", float(fixed)), ("fit_bytes_per_row", float(per_row)),
            ("fit_residuals_bytes", (y - (fixed + per_row * x)).tolist()),
            ("projection_fit_bytes", fit),
            ("dev_all_peak_per_row_bytes", dall[s]["peak_private"] / dall[s]["filtered_rows"]),
            ("projection_dev_all_ratio_bytes", ratio),
            ("assumed_test_filtered_rows", rows_test),
            ("projected_peak", max(fit, ratio))])
    fc = free_commit()
    lim_c, lim_p = 0.8 * fc["free_commit_bytes"], 0.8 * fc["free_physical_bytes"]
    peaks = OrderedDict([("p1", split["projected_peak_bytes"]["p1"])]
                        + [(f"p2_{s}", p2[s]["projected_peak"]) for s in SCORERS])
    out = OrderedDict([
        ("method", project_devall.__doc__.strip()),
        ("p1_from", "lanl_final_projection_split.json"),
        ("p2", p2),
        ("projected_peak_bytes", peaks),
        ("at_projection", OrderedDict([*fc.items(), ("limit_80pct_free_commit_bytes", lim_c),
                                       ("limit_80pct_free_physical_bytes", lim_p)])),
        ("passes_at_projection", OrderedDict((k, bool(v <= lim_c and v <= lim_p)) for k, v in peaks.items())),
    ])
    ORIG["save_json"](PROJ_FILE, out)
    print(json.dumps(out, indent=1))
    return 0 if all(out["passes_at_projection"].values()) else 1


def check_outside_filter():
    """Deviation check (dev only): a copy of val_b's D inputs with one positive
    row moved outside the filter (removed from the filtered population of its
    day, its label pair kept, as process 1 writes a positive outside the filter
    on the test). The fixed D metrics on that copy must equal, field by field,
    the D metrics on a reference copy where the row is removed and its pair is
    also removed (its event unmatched for D): LA3.3 treats a filter-excluded
    event as missed, like an unmatched one. Also: population and positives one
    lower than L2's val_b, event and user denominators unchanged, events caught
    never above L2's; and a population with zero positives evaluates without
    error."""
    assert os.environ.get("FINAL_EVAL") != "1"
    lo, hi = ORIG["split_days"]()["val_b"]
    # the row: first positive (day order) whose event matches only it and which matches one event
    pick = None
    for d in range(lo, hi):
        z = np.load(os.path.join(L2_D_DIR, f"day={d:02d}.npz"))
        pr_, pe_ = z["pairs_row"], z["pairs_event"]
        for r, e in zip(pr_.tolist(), pe_.tolist()):
            if (pr_ == r).sum() == 1 and (pe_ == e).sum() == 1:
                pick = (d, r, e)
                break
        if pick:
            break
    d0, r0, e0 = pick
    dirs = {}
    for name, keep_pair in (("keep", True), ("ref", False)):
        dd = os.path.join(L.wpath(f"final_synth_{name}"), "d")
        os.makedirs(dd, exist_ok=True)
        for d in range(lo, hi):
            for f in (f"day={d:02d}.npz", f"d1_day={d:02d}.npy"):
                dst = os.path.join(dd, f)
                if os.path.exists(dst):
                    os.remove(dst)
                if d != d0:
                    os.link(os.path.join(L2_D_DIR, f), dst)
        z = dict(np.load(os.path.join(L2_D_DIR, f"day={d0:02d}.npz")))
        j = int(np.flatnonzero(z["rows"] == r0)[0])
        assert z["y"][j]
        for k in ("rows", "pos", "user", "X", "d2", "d3", "y"):
            z[k] = np.delete(z[k], j, axis=0)
        if not keep_pair:
            m = z["pairs_row"] != r0
            z["pairs_row"], z["pairs_event"] = z["pairs_row"][m], z["pairs_event"][m]
        np.savez(os.path.join(dd, f"day={d0:02d}.npz"), **z)
        s1 = np.load(os.path.join(L2_D_DIR, f"d1_day={d0:02d}.npy"))
        np.save(os.path.join(dd, f"d1_day={d0:02d}.npy"), np.delete(s1, j))
        dirs[name] = dd
    res = {}
    for name, dd in dirs.items():
        out_dir = os.path.dirname(dd)
        L.save_json = writer(out_dir, {"lanl_d_dev.json": "d.json"})
        D.ddir = lambda dd=dd: dd
        DM.main(splits=("val_b",))
        with open(os.path.join(out_dir, "d.json")) as f:
            res[name] = json.load(f)
    L.save_json, D.ddir = ORIG["save_json"], ORIG["ddir"]
    with open(os.path.join(L.RESULTS, "lanl_d_dev.json")) as f:
        l2 = json.load(f)["val_b"]
    zk = np.load(os.path.join(dirs["keep"], f"day={d0:02d}.npz"))
    idx = np.full(int(zk["n_day"]), -1, np.int64)
    idx[zk["rows"]] = np.arange(len(zk["rows"]))
    chk = OrderedDict()
    chk["moved_row"] = {"day": d0, "day_row": r0, "event": e0}
    chk["pairs_outside_filter_in_copy"] = int((idx[zk["pairs_row"]] < 0).sum())
    skip = {"seconds", "peak_working_set_bytes"}
    chk["fixed_vs_reference_first_difference"] = same(
        {k: v for k, v in res["keep"].items() if k not in skip},
        {k: v for k, v in res["ref"].items() if k not in skip})
    vb = res["keep"]["val_b"]
    facts = OrderedDict()
    facts["filtered_rows_minus_1"] = vb["filtered_rows"] == l2["filtered_rows"] - 1
    facts["positive_rows_minus_1"] = vb["positive_rows"] == l2["positive_rows"] - 1
    facts["redteam_events_and_users_unchanged"] = (vb["redteam_events"] == l2["redteam_events"]
                                                   and vb["redteam_users"] == l2["redteam_users"])
    per = OrderedDict()
    for s in SCORERS:
        a, b = vb["all"][s], l2["all"][s]
        per[s] = OrderedDict([
            ("population_rows_minus_1", a["population_rows"] == b["population_rows"] - 1),
            ("positives_minus_1", a["positives"] == b["positives"] - 1)])
        for k in DM.KS:
            ta, tb = a[f"top{k}"]["all_redteam"], b[f"top{k}"]["all_redteam"]
            per[s][f"top{k}_all_redteam_denominators_unchanged"] = (
                ta["events"] == tb["events"] and ta["users"] == tb["users"])
            per[s][f"top{k}_events_caught_not_above_L2"] = ta["events_caught"] <= tb["events_caught"]
            per[s][f"top{k}_events_caught_L2_vs_copy"] = [tb["events_caught"], ta["events_caught"]]
    facts["per_scorer"] = per
    chk["facts"] = facts
    # zero positives: one val_b day with every positive dropped
    zz = np.load(os.path.join(L2_D_DIR, f"day={lo:02d}.npz"))
    n0 = len(zz["rows"])
    try:
        e = DM.evaluate(zz["d2"], zz["pos"], np.full(n0, lo, np.int64), np.zeros(n0, bool),
                        np.zeros(0, np.int64), np.zeros(0, np.int64), ["u"] * 25, np.zeros(3, np.int64),
                        None)
        chk["zero_positive_population"] = {"error": None, "roc_auc": e["roc_auc"], "pr_auc": e["pr_auc"],
                                           "top1000_rows_caught": e["top1000"]["rows_caught"],
                                           "top1000_lift": repr(e["top1000"]["lift"]),
                                           "top1000_all_redteam": e["top1000"]["all_redteam"],
                                           "mode": e["mode"]}
    except Exception as ex:          # recorded, not raised
        chk["zero_positive_population"] = {"error": repr(ex)}

    def flat(x):
        return all(flat(v) for v in x.values()) if isinstance(x, dict) else (x is True or isinstance(x, list))
    chk["passes"] = (chk["pairs_outside_filter_in_copy"] == 1
                     and chk["fixed_vs_reference_first_difference"] is None and flat(facts)
                     and chk["zero_positive_population"].get("error") is None)
    ORIG["save_json"]("lanl_final_outside_filter_check.json", chk)
    print(json.dumps(chk, indent=1))
    return 0 if chk["passes"] else 1



def free_commit():
    import ctypes
    from eval.lanl_convert import _MemStatus
    ms = _MemStatus()
    ms.dwLength = ctypes.sizeof(ms)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    return {"free_commit_bytes": ms.ullAvailPageFile, "total_commit_bytes": ms.ullTotalPageFile,
            "free_physical_bytes": ms.ullAvailPhys}


def project():
    """Pass 1 peak over the test days from the dry run's per-day memory
    curve (linear trend of end-of-day private commit, extrapolated, plus the
    largest within-day rise) and the lean D metrics peak at the assumed test
    size, against 80% of the free commit now."""
    with open(os.path.join(L.wpath("final_dryrun_out"), "run.json")) as f:
        curve = json.load(f)["memory_curve_pass1"]
    with open(os.path.join(L.RESULTS, "lanl_final_lean_memory.json")) as f:
        lean = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_estimate.json")) as f:
        est = json.load(f)
    dd = np.array([c["day"] for c in curve], float)
    priv = np.array([c["private"] for c in curve], float)
    peak = np.array([c["peak_private"] for c in curve], float)
    slope, icpt = np.polyfit(dd, priv, 1)
    rise = float(max(np.max(peak[1:] - priv[:-1]), peak[0]))
    last = test_end_day()
    pass1 = float(icpt + slope * last + rise)
    dmet = lean["private_before"] + lean["bytes_per_row"] * est["assumed_test_filtered_rows"]
    fc = free_commit()
    out = OrderedDict([
        ("method", "pass 1: linear fit of end-of-day private commit over dev days 0-13, "
                   "extrapolated to the last test day, plus the largest within-day rise "
                   "(peak private minus the previous end-of-day private); D metrics: "
                   "private before + lean bytes per row x assumed test filtered rows"),
        ("end_of_day_private_slope_bytes_per_day", float(slope)),
        ("largest_within_day_rise_bytes", rise),
        ("projected_pass1_peak_bytes", pass1),
        ("projected_d_metrics_peak_bytes", dmet),
        ("projected_sum_bytes", pass1 + dmet),
        *fc.items(),
        ("limit_80pct_free_commit_bytes", 0.8 * fc["free_commit_bytes"]),
        ("within_limit", bool(pass1 + dmet <= 0.8 * fc["free_commit_bytes"])),
    ])
    ORIG["save_json"]("lanl_final_projection.json", out)
    print(json.dumps(out, indent=1))
    return 0 if out["within_limit"] else 1


def project_cond4():
    """(Historical: produced lanl_final_projection_cond4.json from the
    single-process dry run's run.json; the split dry run's run.json has no
    memory_before_d_metrics.) Revised condition 4, from the instrumented val_b dry run.
    4a: private commit right after pass 1's state is released (and right before
    the D metrics start) against pass 1's within-run rise. The rise is taken
    two ways, end-of-pass level minus start and peak minus start; the drop must
    reach 80% of both (the end-of-pass one is the stricter). If it does not, the
    sum rule stands; otherwise 4b: max(pass 1, D metrics) <= 80% of free commit
    and pass 1 <= 80% of free physical RAM. The pass 1 projection is project()'s
    method. The D metrics projection starts from the residual after release,
    scaled by the projected end-of-pass private at the last test day over the
    dry run's (assumes none of the extra state is released), plus the lean
    bytes per row x assumed test filtered rows."""
    with open(os.path.join(L.wpath("final_dryrun_out"), "run.json")) as f:
        run_ = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_lean_memory.json")) as f:
        lean = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_final_estimate.json")) as f:
        est = json.load(f)
    curve = run_["memory_curve_pass1"]
    start = run_["memory_start"]["private"]
    end_pass1 = curve[-1]["private"]
    peak_pass1 = curve[-1]["peak_private"]
    rel = run_["memory_after_pass1_release"]["private"]
    bdm = run_["memory_before_d_metrics"]["private"]
    resid = max(rel, bdm)
    rise_end, rise_peak = end_pass1 - start, peak_pass1 - start
    drop_end, drop_peak = end_pass1 - resid, peak_pass1 - resid
    fr_end, fr_peak = drop_end / rise_end, drop_peak / rise_peak
    use_4b = fr_end >= 0.8 and fr_peak >= 0.8

    dd = np.array([c["day"] for c in curve], float)
    priv = np.array([c["private"] for c in curve], float)
    peak = np.array([c["peak_private"] for c in curve], float)
    slope, icpt = np.polyfit(dd, priv, 1)
    rise = float(max(np.max(peak[1:] - priv[:-1]), peak[0]))
    last = test_end_day()
    end_test = float(icpt + slope * last)
    pass1 = end_test + rise
    scale = end_test / float(icpt + slope * dd[-1])
    resid_test = resid * scale
    dmet_rows = lean["bytes_per_row"] * est["assumed_test_filtered_rows"]
    dmet = resid_test + dmet_rows
    fc = free_commit()
    lim_c, lim_p = 0.8 * fc["free_commit_bytes"], 0.8 * fc["free_physical_bytes"]
    out = OrderedDict([
        ("method", project_cond4.__doc__.strip()),
        ("4a", OrderedDict([
            ("dryrun_private_start_bytes", start),
            ("dryrun_private_end_of_pass1_bytes", end_pass1),
            ("dryrun_peak_private_pass1_bytes", peak_pass1),
            ("dryrun_private_after_pass1_release_bytes", rel),
            ("dryrun_private_before_d_metrics_bytes", bdm),
            ("residual_used_bytes", resid),
            ("rise_end_of_pass_bytes", rise_end), ("drop_from_end_of_pass_bytes", drop_end),
            ("drop_share_of_rise_end_of_pass", fr_end),
            ("rise_peak_bytes", rise_peak), ("drop_from_peak_bytes", drop_peak),
            ("drop_share_of_rise_peak", fr_peak),
            ("drop_ge_80pct", bool(use_4b)),
            ("rule", "4b" if use_4b else "sum rule")])),
        ("end_of_day_private_slope_bytes_per_day", float(slope)),
        ("projected_end_of_pass1_private_last_test_day_bytes", end_test),
        ("largest_within_day_rise_bytes", rise),
        ("projected_pass1_peak_bytes", pass1),
        ("residual_scale", scale),
        ("projected_residual_before_d_metrics_bytes", resid_test),
        ("lean_bytes_per_row", lean["bytes_per_row"]),
        ("assumed_test_filtered_rows", est["assumed_test_filtered_rows"]),
        ("projected_d_metrics_rows_bytes", dmet_rows),
        ("projected_d_metrics_peak_bytes", dmet),
        ("projected_sum_bytes", pass1 + dmet),
        ("projected_max_bytes", max(pass1, dmet)),
        *fc.items(),
        ("limit_80pct_free_commit_bytes", lim_c),
        ("limit_80pct_free_physical_bytes", lim_p),
    ])
    if use_4b:
        c1, c2 = max(pass1, dmet) <= lim_c, pass1 <= lim_p
        out["4b_max_le_80pct_free_commit"] = bool(c1)
        out["4b_pass1_le_80pct_free_physical"] = bool(c2)
        out["passes"] = bool(c1 and c2)
    else:
        out["sum_le_80pct_free_commit"] = bool(pass1 + dmet <= lim_c)
        out["passes"] = out["sum_le_80pct_free_commit"]
    ORIG["save_json"]("lanl_final_projection_cond4.json", out)
    print(json.dumps(out, indent=1))
    return 0 if out["passes"] else 1


def check_lean():
    """The memory-lean D metrics against L2's saved val_a / val_b D results,
    field by field, plus the lean positive ranks against the full ranks."""
    assert os.environ.get("FINAL_EVAL") != "1"
    out_dir = L.wpath("final_leancheck_out")
    os.makedirs(out_dir, exist_ok=True)
    L.save_json = writer(out_dir, {"lanl_d_dev.json": "d.json"})
    t = time.perf_counter()
    DM.main(splits=("val_a", "val_b"))
    secs = time.perf_counter() - t
    peak = peak_working_set()
    L.save_json = ORIG["save_json"]
    with open(os.path.join(out_dir, "d.json")) as f:
        new = json.load(f)
    with open(os.path.join(L.RESULTS, "lanl_d_dev.json")) as f:
        old = json.load(f)
    skip = {"seconds", "peak_working_set_bytes"}
    chk = OrderedDict()
    chk["fields_compared"] = sorted(k for k in old if k not in skip)
    chk["first_difference"] = same({k: v for k, v in new.items() if k not in skip},
                                   {k: v for k, v in old.items() if k not in skip})
    ranks_eq = {}
    for split in ("val_a", "val_b"):
        Z = DM.load_split(split)
        pi = np.flatnonzero(Z["y"])
        for sc in SCORERS:
            rg, rd = DM.positive_ranks(Z[sc], Z["pos"], Z["day"], pi)
            ranks_eq[f"{split}:{sc}"] = bool(np.array_equal(rg, DM.ranks(Z[sc], Z["pos"])[pi])
                                             and np.array_equal(rd, DM.ranks(Z[sc], Z["pos"], Z["day"])[pi]))
        del Z
    chk["positive_ranks_equal_full_ranks"] = ranks_eq
    chk["reproduces_L2_exactly"] = chk["first_difference"] is None and all(ranks_eq.values())
    chk["lean_d_metrics_seconds"] = round(secs, 1)
    chk["lean_d_metrics_peak_working_set_bytes"] = peak
    chk["val_a_filtered_rows"] = new["val_a"]["filtered_rows"]
    ORIG["save_json"]("lanl_final_lean_check.json", chk)
    print(json.dumps(chk, indent=1))
    return 0 if chk["reproduces_L2_exactly"] else 1


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
    ap.add_argument("--tag", default="dryrun")
    ap.add_argument("--stop-after", type=int, default=None)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--estimate", action="store_true")
    ap.add_argument("--check-lean", action="store_true")
    ap.add_argument("--measure-lean", action="store_true")
    ap.add_argument("--project", action="store_true")
    ap.add_argument("--project-cond4", action="store_true")
    ap.add_argument("--project-split", action="store_true")
    ap.add_argument("--measure-lean-scorers", action="store_true")
    ap.add_argument("--p1", action="store_true")
    ap.add_argument("--p2", action="store_true")
    ap.add_argument("--target", default=None)
    ap.add_argument("--scorer", default=None, choices=SCORERS)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--skip-p1", action="store_true")
    ap.add_argument("--no-crosscheck", action="store_true")
    ap.add_argument("--measure-dev-all", action="store_true")
    ap.add_argument("--project-devall", action="store_true")
    ap.add_argument("--check-outside-filter", action="store_true")
    args = ap.parse_args()
    if args.check_outside_filter:
        return check_outside_filter()
    if args.measure_dev_all:
        return measure_dev_all()
    if args.project_devall:
        return project_devall()
    if args.p1:
        return p1_main(args.target, args.tag, args.run_id, args.resume, args.stop_after)
    if args.p2:
        return d_process(args.target, args.tag, args.run_id, args.scorer, not args.no_crosscheck)
    if args.project_split:
        return project_split()
    if args.measure_lean_scorers:
        return measure_lean_scorers()
    if args.project_cond4:
        return project_cond4()
    if args.check_lean:
        return check_lean()
    if args.measure_lean:
        return measure_lean(args.scorer)
    if args.project:
        return project()
    if args.estimate:
        return estimate()
    if args.dry_run:
        return dry_run(args.tag, args.stop_after, args.resume)
    assert args.stop_after is None, "--stop-after is for dry runs"
    return final(resume=args.resume, run_id=args.run_id, skip_p1=args.skip_p1)


if __name__ == "__main__":
    sys.exit(main())
