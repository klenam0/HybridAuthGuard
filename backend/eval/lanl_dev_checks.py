# backend/eval/lanl_dev_checks.py
"""
LANL phase L1, step 3: checks on the dev auth partitions only
(<root>/auth/dev/day=DD/part-0.parquet, day < day(c3)). No test partition is
listed, opened or read here.

  per dev day   row count (checked against results/lanl_l1_convert.json and
                the Parquet footer), share of "?" in each string field, counts
                and shares of each value of the success field
  over dev      distinct src_user, dst_user, src_computer, dst_computer
  red-team      for each dev red-team event (eval.lanl_data.load_lanl over
                dev_train, val_a, val_b): auth rows with the same time,
                src_computer and dst_computer; whether the red-team user equals
                (a) src_user or (b) dst_user of such a row; the success values
                of the rows matched under (a) or (b)

Writes results/lanl_l1_dev_checks.json.

Run from backend/:  python -m eval.lanl_dev_checks
"""

import collections
import glob
import json
import os
import sys
import time

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_convert, lanl_data, lanl_split  # noqa: E402

OUT = os.path.join(BACKEND, "results", "lanl_l1_dev_checks.json")
STRING_FIELDS = lanl_convert.COLUMNS[1:]
DISTINCT_FIELDS = ("src_user", "dst_user", "src_computer", "dst_computer")
DEV_SPLITS = ("dev_train", "val_a", "val_b")


def dev_partitions():
    pattern = os.path.join(lanl_convert.dev_dir(lanl_convert.OUT_ROOT), "day=*", "part-0.parquet")
    parts = {}
    for p in glob.glob(pattern):
        d = int(os.path.basename(os.path.dirname(p)).split("=")[1])
        parts[d] = p
    return dict(sorted(parts.items()))


def main():
    start = time.perf_counter()
    with open(lanl_convert.FULL_JSON, encoding="utf-8") as f:
        conv = json.load(f)["convert"]
    c3_day = conv["c3_day"]
    parts = dev_partitions()
    if any(d >= c3_day for d in parts):
        raise RuntimeError("a dev partition has day >= day(c3)")

    t0 = lanl_split.load_t0()
    rt = []
    for s in DEV_SPLITS:
        rt.extend(lanl_data.load_lanl(s, "redteam"))
    rt = pd.DataFrame(rt, columns=["time", "user", "src_computer", "dst_computer"])
    rt["event"] = range(len(rt))
    rt["day"] = lanl_split.day(rt["time"].to_numpy(), t0)

    per_day = {}
    distinct = {f: set() for f in DISTINCT_FIELDS}
    matched_frames = []
    for d, path in parts.items():
        meta_rows = pq.ParquetFile(path).metadata.num_rows
        q_share, succ = {}, {}
        for f in STRING_FIELDS:
            col = pq.read_table(path, columns=[f]).column(f)
            n = len(col)
            if f == "success":
                vc = pc.value_counts(col).to_pylist()
                succ = {v["values"]: {"rows": v["counts"], "share": v["counts"] / n}
                        for v in sorted(vc, key=lambda x: x["values"])}
            q_share[f] = pc.sum(pc.equal(col, "?")).as_py() / n
            if f in DISTINCT_FIELDS:
                distinct[f].update(pc.unique(col).to_pylist())
            del col
        per_day[f"{d:02d}"] = {
            "rows": meta_rows,
            "rows_match_convert_json": meta_rows == conv["dev_rows_per_day"][f"{d:02d}"],
            "share_question_mark": q_share,
            "success_field": succ,
        }

        day_rt = rt[rt["day"] == d]
        if len(day_rt):
            cols = ["time", "src_user", "dst_user", "src_computer", "dst_computer", "success"]
            tbl = pq.read_table(path, columns=cols)
            times = pa.array(sorted(set(day_rt["time"].tolist())), type=pa.int64())
            tbl = tbl.filter(pc.is_in(tbl.column("time"), value_set=times))
            auth = tbl.to_pandas()
            matched_frames.append(day_rt.merge(auth, on=["time", "src_computer", "dst_computer"],
                                               how="left"))

    m = pd.concat(matched_frames, ignore_index=True)
    m["key_match"] = m["src_user"].notna()
    m["a"] = m["user"] == m["src_user"]
    m["b"] = m["user"] == m["dst_user"]
    ev = m.groupby("event").agg(key=("key_match", "any"), a=("a", "any"), b=("b", "any"))
    ev = ev.reindex(rt["event"], fill_value=False)
    rows_a = m[m["a"]]
    rows_b = m[m["b"]]
    rows_ab = m[m["a"] | m["b"]]

    def vc(df):
        return {str(k): int(v) for k, v in df["success"].value_counts().sort_index().items()}

    # success values per event: does it have a matched (a or b) row with each value
    ev_succ = collections.Counter()
    for _, g in rows_ab.groupby("event"):
        ev_succ["+".join(sorted(set(g["success"])))] += 1

    redteam_match = {
        "dev_redteam_events": int(len(rt)),
        "events_with_time_src_dst_match": int(ev["key"].sum()),
        "events_a_src_user": int(ev["a"].sum()),
        "events_b_dst_user": int(ev["b"].sum()),
        "events_both": int((ev["a"] & ev["b"]).sum()),
        "events_a_only": int((ev["a"] & ~ev["b"]).sum()),
        "events_b_only": int((~ev["a"] & ev["b"]).sum()),
        "events_neither": int((~ev["a"] & ~ev["b"]).sum()),
        "matched_rows_a": int(len(rows_a)),
        "matched_rows_b": int(len(rows_b)),
        "matched_rows_a_or_b": int(len(rows_ab)),
        "success_values_rows_a": vc(rows_a),
        "success_values_rows_b": vc(rows_b),
        "success_values_rows_a_or_b": vc(rows_ab),
        "events_by_success_values_of_a_or_b_rows": dict(sorted(ev_succ.items())),
    }

    out = {
        "scope": "dev partitions only (auth/dev), days " + ", ".join(f"{d:02d}" for d in parts),
        "dev_days": len(parts),
        "dev_rows_total": sum(v["rows"] for v in per_day.values()),
        "dev_rows_total_matches_convert_json": sum(v["rows"] for v in per_day.values())
                                              == conv["rows_written_dev"],
        "per_day": per_day,
        "distinct_over_dev": {f: len(s) for f, s in distinct.items()},
        "redteam_match": redteam_match,
        "elapsed_seconds": round(time.perf_counter() - start, 1),
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(json.dumps({k: v for k, v in out.items() if k != "per_day"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
