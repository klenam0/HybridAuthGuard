# backend/eval/lanl_split.py
"""
Applies amendment LA1 (eval/PROTOCOL_LANL.md) to the LANL red-team file and
writes results/lanl_split.json.

  q(p)      nearest-rank percentile of the sorted red-team times:
            the time at 1-based rank ceil(p * N)
  boundary  t0 + k * 86400; a cut is moved forward to the next boundary
            unless it is already on one
  splits    dev_train [t0, c1), val_a [c1, c2), val_b [c2, c3), test [c3, end)

LA1.1 cuts are tried first; if LA1.2 fails, LA1.3 cuts are tried once; if
that fails too, no split is chosen and the script exits 1.

For the test period only the red-team event count and the number of
distinct red-team days are computed (LA1.2 needs them). No users, computers,
days or strata of the test period are computed or printed. This module and
eval/lanl_lock.py are the only code that reads test-period red-team rows
directly; everything else goes through eval.lanl_data.load_lanl().

Run from backend/:  python -m eval.lanl_split
"""

import gzip
import json
import math
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_inspect  # noqa: E402

REDTEAM_GZ = lanl_inspect.REDTEAM_GZ
INSPECT_JSON = lanl_inspect.OUT
OUT = os.path.join(BACKEND, "results", "lanl_split.json")
DAY = 86400

RULES = (("LA1.1", (0.50, 0.625, 0.75)), ("LA1.3", (0.40, 0.55, 0.70)))
MIN_EVENTS, MIN_DAYS = 30, 2
DEV_SPLITS = ("dev_train", "val_a", "val_b")


def load_t0():
    """t0 as recorded by eval.lanl_inspect from auth.txt.gz line 1."""
    with open(INSPECT_JSON, encoding="utf-8") as f:
        return json.load(f)["auth_line1"]["t0"]


def read_redteam(path=REDTEAM_GZ):
    """All red-team rows as (time, user, src, dst, raw_line), stably time-sorted."""
    with gzip.open(path, "rb") as f:
        text = f.read().decode("utf-8")
    rows = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        t, user, src, dst = raw.split(",")
        rows.append((int(t), user, src, dst, raw))
    rows.sort(key=lambda r: r[0])
    return rows


def q(times, p):
    return times[math.ceil(p * len(times)) - 1]


def to_boundary(c, t0):
    off = (c - t0) % DAY
    return c if off == 0 else c + (DAY - off)


def day(t, t0):
    return (t - t0) // DAY


def cuts(times, t0, ps):
    return tuple(to_boundary(q(times, p), t0) for p in ps)


def split_of(t, t0, c1, c2, c3):
    if t < t0:
        raise ValueError(f"red-team time {t} is before t0 {t0}")
    if t < c1:
        return "dev_train"
    if t < c2:
        return "val_a"
    if t < c3:
        return "val_b"
    return "test"


def test_rows(rows, t0, c3):
    """Test-period rows; used only for counting (here) and the lock hash."""
    return [r for r in rows if r[0] >= c3]


def adequacy(rows, t0, c1, c2, c3):
    """Event and distinct-day counts per split, and the LA1.2 verdict."""
    per = {s: {"events": 0, "days": set()} for s in (*DEV_SPLITS, "test")}
    for r in rows:
        s = split_of(r[0], t0, c1, c2, c3)
        per[s]["events"] += 1
        per[s]["days"].add(day(r[0], t0))
    counts = {s: {"redteam_events": v["events"], "redteam_distinct_days": len(v["days"])}
              for s, v in per.items()}
    checks = {s: (counts[s]["redteam_events"] >= MIN_EVENTS
                  and counts[s]["redteam_distinct_days"] >= MIN_DAYS)
              for s in ("val_a", "val_b", "test")}
    return counts, checks


def strata(rows, start, end):
    """LA1.5 new/returning counts for the dev period [start, end)."""
    before = [r for r in rows if r[0] < start]
    inside = [r for r in rows if start <= r[0] < end]
    out = {}
    for name, i in (("user", 1), ("src_computer", 2), ("dst_computer", 3)):
        seen = {r[i] for r in before}
        ret = sum(1 for r in inside if r[i] in seen)
        out[name] = {"returning": ret, "new": len(inside) - ret}
    return out


def dev_detail(rows, lo, hi):
    inside = [r for r in rows if lo <= r[0] < hi]
    return {"distinct_users": len({r[1] for r in inside}),
            "distinct_src_computers": len({r[2] for r in inside}),
            "distinct_dst_computers": len({r[3] for r in inside})}


def apply_la1(rows, t0):
    """Returns (attempts, chosen) where chosen is None if both rules fail."""
    times = [r[0] for r in rows]
    attempts = []
    for rule, ps in RULES:
        c1, c2, c3 = cuts(times, t0, ps)
        counts, checks = adequacy(rows, t0, c1, c2, c3)
        attempt = {
            "rule": rule,
            "percentiles": list(ps),
            "q_times": [q(times, p) for p in ps],
            "cuts": {"c1": c1, "c2": c2, "c3": c3},
            "cut_days": {"c1": day(c1, t0), "c2": day(c2, t0), "c3": day(c3, t0)},
            "counts": counts,
            "la1_2": checks,
            "la1_2_pass": all(checks.values()),
        }
        attempts.append(attempt)
        if attempt["la1_2_pass"]:
            return attempts, attempt
    return attempts, None


def main():
    t0 = load_t0()
    rows = read_redteam()
    attempts, chosen = apply_la1(rows, t0)
    result = {"t0": t0, "day_convention": "day = floor((time - t0) / 86400)",
              "redteam_rows": len(rows), "attempts": attempts}
    if chosen is None:
        result["rule_used"] = None
        result["status"] = "LA1.2 failed under LA1.1 and LA1.3: no split chosen"
    else:
        c1, c2, c3 = (chosen["cuts"][k] for k in ("c1", "c2", "c3"))
        bounds = {"dev_train": (t0, c1), "val_a": (c1, c2), "val_b": (c2, c3)}
        splits = {}
        for s, (lo, hi) in bounds.items():
            splits[s] = {"start": lo, "end_exclusive": hi,
                         "start_day": day(lo, t0), "end_day_exclusive": day(hi, t0),
                         **chosen["counts"][s], **dev_detail(rows, lo, hi)}
        splits["test"] = {"start": c3, "end": "end of auth data (fixed in phase L1)",
                          "start_day": day(c3, t0), **chosen["counts"]["test"]}
        result.update({
            "rule_used": chosen["rule"],
            "status": "split chosen",
            "c1": {"time": c1, "day": day(c1, t0)},
            "c2": {"time": c2, "day": day(c2, t0)},
            "c3": {"time": c3, "day": day(c3, t0)},
            "splits": splits,
            "strata_la1_5": {"val_a": strata(rows, c1, c2), "val_b": strata(rows, c2, c3)},
        })
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps(result, indent=2))
    return 0 if chosen is not None else 1


if __name__ == "__main__":
    sys.exit(main())
