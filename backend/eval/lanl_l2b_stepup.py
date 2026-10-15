# backend/eval/lanl_l2b_stepup.py
"""
LANL phase L2b, Q2: step-up challenges per val day from the saved L2 causal
twin arrays (<work>/a_causal/day=DD.npz: per-event `challenged`, alerted
events with their tier). Nothing is re-run; the dev partitions supply only
src_user / src_computer names (and the LA3.1 labels, to exclude red-team rows
as lanl_a_metrics does).

Per val day:
  step_up_incidents      (src computer, day) incidents whose tier at their
                         last alerted event that day is step_up (tiers only rise)
  legit_users_challenged distinct normalised source accounts with a
                         non-positive event from a challenged source computer
                         (equals lanl_a_dev.json legitimate_users_challenged_daily)
  top5                   the five (src computer, day) pairs with the most such
                         users, with whether that pair is a step-up incident
Writes results/lanl_l2b_stepup.json.
"""

import os
import sys

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from agents.rules_v3 import normalize_account  # noqa: E402
from eval import lanl_a as A  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402

COLS = ["time", "src_user", "src_computer", "dst_computer"]


def main():
    rt = L.redteam_dev()
    adir = A.adir("causal")
    out = {"source": "saved L2 causal twin arrays (a_causal/day=DD.npz) + dev partitions for names",
           "splits": {}}
    with open(os.path.join(L.RESULTS, "lanl_a_dev.json"), encoding="utf-8") as f:
        import json
        a_dev = json.load(f)
    for split in ("val_a", "val_b"):
        lo, hi = L.split_days()[split]
        days = {}
        for d in range(lo, hi):
            z = np.load(os.path.join(adir, f"day={d:02d}.npz"))
            tbl = L.day_table(d, COLS)
            pos, _, _ = L.label_day(tbl, rt[rt["day"] == d])
            comp = np.asarray(tbl.column("src_computer").to_numpy(zero_copy_only=False), dtype=object)
            a_pos, tier_ev = z["a_pos"], z["tier_ev"]
            last_tier = pd.Series(tier_ev).groupby(comp[a_pos], sort=False).last()
            step_inc = set(last_tier.index[last_tier.to_numpy() == 1])
            legit = np.flatnonzero(z["challenged"] & ~pos)
            users = [normalize_account(u) for u in tbl.column("src_user").take(legit).to_pylist()]
            df = pd.DataFrame({"comp": comp[legit], "user": users})
            per_comp = df.groupby("comp")["user"].nunique().sort_values(ascending=False, kind="stable")
            top = [{"src_computer": c, "users_challenged": int(n), "is_step_up_incident": c in step_inc}
                   for c, n in per_comp.head(5).items()]
            days[f"{d:02d}"] = {"step_up_incidents": len(step_inc),
                                "legit_users_challenged": int(df["user"].nunique()),
                                "challenged_source_computers": int(len(per_comp)),
                                "top5": top}
            print(split, d, days[f"{d:02d}"], flush=True)
        daily = [days[k]["legit_users_challenged"] for k in sorted(days)]
        ref = a_dev[split]["tiers"]["step_up"]["legitimate_users_challenged_daily"]
        out["splits"][split] = {"days": days, "check_equals_lanl_a_dev_daily": daily == ref}
    L.save_json("lanl_l2b_stepup.json", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
