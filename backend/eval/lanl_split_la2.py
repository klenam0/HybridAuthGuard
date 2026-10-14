# backend/eval/lanl_split_la2.py
"""
Applies amendment LA2 (eval/PROTOCOL_LANL.md) to the LANL red-team file and
writes results/lanl_split_la2.json. LA1's record (eval/lanl_split.py,
results/lanl_split.json) is read, never changed.

Day convention (the same as eval/lanl_split.py): day = floor((time - t0) / 86400),
with t0 from auth.txt.gz line 1 (results/lanl_inspect.json). Day d covers
[t0 + d*86400, t0 + (d+1)*86400). The first day is day 0. A block [x, y) of
whole days, given by day indices, has y - x whole days. c3 is on a day
boundary (LA1.1), so [b, c3) is whole days.

  LA2.1  c3 = LA1.1's c3, read from results/lanl_split.json
  LA2.2  b: move back from day(c3) - 1 one day at a time; the first (largest) b
         with >= 30 red-team events on >= 2 distinct days in [b, c3)
  LA2.3  a: the same search moving back from b - 1, block [a, b)
  LA2.4  dev_train = [day 0, a), at least 5 whole days
  LA2.5  fallback: val = [b, c3), dev_train = [day 0, b), at least 5 whole days

Nothing is computed or printed per day. For the test, only the LA2.7 counts
(events, distinct days, distinct users) are computed.

Run from backend/:  python -m eval.lanl_split_la2
"""

import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_split  # noqa: E402

LA1_JSON = lanl_split.OUT
OUT = os.path.join(BACKEND, "results", "lanl_split_la2.json")
DAY = lanl_split.DAY
MIN_EVENTS, MIN_DAYS = 30, 2
MIN_DEV_DAYS = 5
BOOTSTRAP_MIN_USERS = 20


def load_c3():
    """LA2.1: LA1.1's c3 as recorded in results/lanl_split.json."""
    with open(LA1_JSON, encoding="utf-8") as f:
        la1 = json.load(f)
    (att,) = [a for a in la1["attempts"] if a["rule"] == "LA1.1"]
    return att["cuts"]["c3"]


def start_of(d, t0):
    return t0 + d * DAY


def block_ok(rows, t0, lo_day, hi_day):
    lo, hi = start_of(lo_day, t0), start_of(hi_day, t0)
    inside = [r for r in rows if lo <= r[0] < hi]
    days = {lanl_split.day(r[0], t0) for r in inside}
    return len(inside) >= MIN_EVENTS and len(days) >= MIN_DAYS


def search_back(rows, t0, end_day):
    """Largest start day s < end_day with [s, end_day) adequate, or None."""
    for s in range(end_day - 1, -1, -1):
        if block_ok(rows, t0, s, end_day):
            return s
    return None


def mode(users):
    return "exact counts" if users < BOOTSTRAP_MIN_USERS else "bootstrap (user-clustered, 1,000)"


def period_counts(rows, t0, lo, hi):
    inside = [r for r in rows if lo <= r[0] < hi]
    users = len({r[1] for r in inside})
    return inside, {
        "redteam_events": len(inside),
        "redteam_distinct_days": len({lanl_split.day(r[0], t0) for r in inside}),
        "redteam_distinct_users": users,
        "la2_6_mode": mode(users),
    }


def dev_period(rows, t0, lo_day, hi_day):
    lo, hi = start_of(lo_day, t0), start_of(hi_day, t0)
    inside, out = period_counts(rows, t0, lo, hi)
    before = [r for r in rows if r[0] < lo]
    out.update({"start": lo, "end_exclusive": hi, "start_day": lo_day,
                "end_day_exclusive": hi_day, "whole_days": hi_day - lo_day,
                "distinct_src_computers": len({r[2] for r in inside}),
                "distinct_dst_computers": len({r[3] for r in inside})})
    strata = {}
    for name, i in (("user", 1), ("src_computer", 2), ("dst_computer", 3)):
        seen = {r[i] for r in before}
        ret = [r for r in inside if r[i] in seen]
        new = [r for r in inside if r[i] not in seen]
        strata[name] = {}
        for label, part in (("returning", ret), ("new", new)):
            u = len({r[1] for r in part})
            strata[name][label] = {"events": len(part), "distinct_users": u,
                                   "la2_6_mode": mode(u)}
    out["strata_la1_5"] = strata
    return out


def apply_la2(rows, t0, c3):
    """Returns (rule, a_day, b_day, reason); rule None means no split."""
    c3_day = lanl_split.day(c3, t0)
    if start_of(c3_day, t0) != c3:
        raise ValueError("c3 is not on a day boundary")
    b = search_back(rows, t0, c3_day)
    if b is None:
        return None, None, None, "LA2.2: val_b cannot be formed"
    a = search_back(rows, t0, b)
    if a is not None and a >= MIN_DEV_DAYS:
        return "LA2.2-LA2.4", a, b, None
    if b >= MIN_DEV_DAYS:
        why = ("val_a cannot be formed before the first day" if a is None
               else f"dev_train [0, a) has {a} whole days (< {MIN_DEV_DAYS})")
        return "LA2.5", None, b, why
    return None, a, b, f"LA2.5: dev_train [0, b) has {b} whole days (< {MIN_DEV_DAYS})"


def main():
    t0 = lanl_split.load_t0()
    c3 = load_c3()
    rows = lanl_split.read_redteam()
    rule, a, b, reason = apply_la2(rows, t0, c3)
    c3_day = lanl_split.day(c3, t0)
    result = {
        "t0": t0,
        "day_convention": "day = floor((time - t0) / 86400); day d = [t0 + d*86400, "
                          "t0 + (d+1)*86400); first day = day 0; [x, y) in days has "
                          "y - x whole days (same convention as eval/lanl_split.py)",
        "redteam_rows": len(rows),
        "c3": {"time": c3, "day": c3_day, "source": "results/lanl_split.json LA1.1 cuts.c3"},
        "rule_used": rule,
    }
    if rule is None:
        result["status"] = "no split chosen"
        result["reason"] = reason
    else:
        _, test = period_counts(rows, t0, c3, float("inf"))
        splits = {}
        if rule == "LA2.2-LA2.4":
            result["a"] = {"time": start_of(a, t0), "day": a}
            splits["dev_train"] = dev_period(rows, t0, 0, a)
            splits["val_a"] = dev_period(rows, t0, a, b)
            splits["val_b"] = dev_period(rows, t0, b, c3_day)
        else:
            result["a"] = "fallback used"
            result["fallback_reason"] = reason
            splits["dev_train"] = dev_period(rows, t0, 0, b)
            splits["val"] = dev_period(rows, t0, b, c3_day)
        result["b"] = {"time": start_of(b, t0), "day": b}
        result["dev_train_whole_days"] = splits["dev_train"]["whole_days"]
        splits["test"] = {"start": c3, "start_day": c3_day,
                          "end": "last auth day, fixed in phase L1", **test}
        result["splits"] = splits
        result["status"] = "split chosen"
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps(result, indent=2))
    return 0 if rule is not None else 1


if __name__ == "__main__":
    sys.exit(main())
