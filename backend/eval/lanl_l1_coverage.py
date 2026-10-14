# backend/eval/lanl_l1_coverage.py
"""
LANL phase L1, step 5: the LA2.7 figure and red-team coverage of the test.

Uses only saved records, and reads no test row:
  test end day         results/lanl_l1_convert.json (LA2.1)
  c3 day               results/lanl_split_la2.json
  test red-team days   results/lanl_split_la2.json (splits.test.redteam_distinct_days,
                       computed in L0 over all red-team rows with time >= c3)
  last red-team day    results/lanl_inspect.json (checks.redteam_max_day)

If the test end is on or after the last red-team day, every red-team row with
time >= c3 lies inside [c3, test end], so the L0 test counts are the test's
counts. If it is before, the figures need test red-team rows, which only
load_lanl("test") may read; the script then records that and stops.

Writes results/lanl_l1_coverage.json.

Run from backend/:  python -m eval.lanl_l1_coverage
"""

import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_convert, lanl_inspect, lanl_split_la2  # noqa: E402

OUT = os.path.join(BACKEND, "results", "lanl_l1_coverage.json")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    conv = _load(lanl_convert.FULL_JSON)["convert"]
    la2 = _load(lanl_split_la2.OUT)
    insp = _load(lanl_inspect.OUT)
    test_end = conv["test_end_day"]
    c3_day = la2["c3"]["day"]
    rt_last = insp["checks"]["redteam_max_day"]
    out = {"c3_day": c3_day, "test_end_day": test_end, "last_redteam_day": rt_last,
           "test_days": test_end - c3_day + 1,
           "test_end_before_last_redteam_day": test_end < rt_last}
    if test_end >= rt_last:
        rt_days = la2["splits"]["test"]["redteam_distinct_days"]
        out.update({
            "test_days_with_redteam": rt_days,
            "test_days_without_redteam_la2_7": out["test_days"] - rt_days,
            "redteam_rows_after_test_end": 0,
            "note": "test end >= last red-team day, so all red-team rows with time >= c3 "
                    "are inside the test; counts from L0 (lanl_split_la2.json) apply",
        })
        code = 0
    else:
        out["note"] = ("test end < last red-team day: the figures need test red-team rows "
                       "(load_lanl('test')); not computed")
        code = 1
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(json.dumps(out, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
