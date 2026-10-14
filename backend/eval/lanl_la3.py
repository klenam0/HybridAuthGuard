# backend/eval/lanl_la3.py
"""
Shared pieces of amendment LA3 (eval/PROTOCOL_LANL.md) for phase L2:
per-day reads of the dev auth partitions, the LA3.1 labels and the LA3.3
event filter. Only dev days (< day(c3)) can be read here; the test goes
through eval.lanl_data.load_lanl("test").
"""

import json
import os
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_convert, lanl_data, lanl_split, lanl_split_la2  # noqa: E402

RESULTS = os.path.join(BACKEND, "results")
WORK = os.environ.get("LANL_WORK", os.path.join(os.path.dirname(lanl_convert.OUT_ROOT), "l2_work"))
DEV_SPLITS = ("dev_train", "val_a", "val_b")
USER_RE = r"^U[0-9]+(@|$)"          # LA3.3: name before "@" matches ^U[0-9]+$
DAY = lanl_split.DAY


def wpath(name):
    os.makedirs(WORK, exist_ok=True)
    return os.path.join(WORK, name)


def save_json(name, obj):
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
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


def split_days():
    """{split: (first day, end day exclusive)} for the dev splits (LA2)."""
    with open(lanl_split_la2.OUT, encoding="utf-8") as f:
        s = json.load(f)["splits"]
    return {k: (s[k]["start_day"], s[k]["end_day_exclusive"]) for k in DEV_SPLITS}


def c3_day():
    with open(lanl_split_la2.OUT, encoding="utf-8") as f:
        return json.load(f)["c3"]["day"]


def split_of_day(d):
    for k, (lo, hi) in split_days().items():
        if lo <= d < hi:
            return k
    raise ValueError(f"day {d} is not a dev day")


def day_table(d, columns=None):
    """One dev day's auth rows (file order). Refuses test days."""
    if d >= c3_day():
        raise PermissionError("test days are read only through load_lanl('test')")
    path = os.path.join(lanl_convert.dev_dir(lanl_convert.OUT_ROOT), f"day={d:02d}", "part-0.parquet")
    return pq.read_table(path, columns=columns)


def day_offsets():
    """Global stream position of each dev day's first row (rows before it)."""
    with open(lanl_convert.FULL_JSON, encoding="utf-8") as f:
        per = json.load(f)["convert"]["dev_rows_per_day"]
    out, acc = {}, 0
    for k in sorted(per):
        out[int(k)] = acc
        acc += per[k]
    return out


def redteam_dev():
    """Dev red-team events with their split, LA1.5 user stratum and day."""
    t0 = lanl_split.load_t0()
    rows = []
    for s in DEV_SPLITS:
        for r in lanl_data.load_lanl(s, "redteam"):
            rows.append((*r, s))
    rt = pd.DataFrame(rows, columns=["time", "user", "src_computer", "dst_computer", "split"])
    rt["event"] = np.arange(len(rt))
    rt["day"] = lanl_split.day(rt["time"].to_numpy(), t0)
    starts = {s: lo for s, (lo, _) in split_days().items()}
    ret = np.zeros(len(rt), bool)
    for s, lo in starts.items():
        seen = set(rt.loc[rt["day"] < lo, "user"])     # red-team events before the split starts
        m = (rt["split"] == s).to_numpy()
        ret[m] = rt.loc[m, "user"].isin(seen).to_numpy()
    rt["returning_user"] = ret
    return rt


def label_day(tbl, rt_day):
    """LA3.1 on one day: (positive mask over the day's rows, matched rows per
    red-team event index). A row is positive if its time, src_computer and
    dst_computer equal a red-team event's and its src_user is the event's user."""
    n = tbl.num_rows
    pos = np.zeros(n, bool)
    if len(rt_day) == 0:
        return pos, {}, pd.DataFrame({"row": [], "event": []}, dtype=np.int64)
    times = pa.array(sorted(set(rt_day["time"].tolist())), type=pa.int64())
    idx = np.flatnonzero(pc.is_in(tbl.column("time"), value_set=times).to_numpy(zero_copy_only=False))
    sub = tbl.take(pa.array(idx)).select(["time", "src_user", "src_computer", "dst_computer"]).to_pandas()
    sub["row"] = idx
    m = sub.merge(rt_day[["time", "user", "src_computer", "dst_computer", "event"]],
                  left_on=["time", "src_computer", "dst_computer", "src_user"],
                  right_on=["time", "src_computer", "dst_computer", "user"], how="inner")
    pos[m["row"].to_numpy()] = True
    per_event = m.groupby("event")["row"].nunique().to_dict()
    return pos, per_event, m[["row", "event"]]


def filter_mask(tbl):
    """LA3.3 over a table with success, src_computer, dst_computer, src_user."""
    ok = pc.equal(tbl.column("success"), "Success")
    ok = pc.and_(ok, pc.not_equal(tbl.column("src_computer"), tbl.column("dst_computer")))
    ok = pc.and_(ok, pc.match_substring_regex(tbl.column("src_user"), USER_RE))
    return ok.to_numpy(zero_copy_only=False)


def offset_hour(t):
    """LA3.4: ((time - 1) mod 86400) // 3600, an offset from the data start."""
    return ((t - 1) % DAY) // 3600
