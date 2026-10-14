# backend/eval/lanl_l2_checks.py
"""
LANL phase L2, step 2: checks of LA3's inputs on the dev days only.

  per dev split   LA3.3-filtered rows per day (min, mean, max), filtered share
  labels (LA3.1)  matched auth rows per red-team event (min, max), unmatched
                  events, positive rows; red-team events and users that pass
                  LA3.3 (an event passes if one of its positive rows does)
  frozen fields   rows whose normalised account is a config.UNKNOWN_ACCOUNT_IDS
                  account; rows the frozen duplicate check would drop if events
                  carried no event_id (same time, ip, account, status and the
                  constant fields); distinct accounts that casefolding merges

Writes results/lanl_l2_checks.json.

Run from backend/:  python -m eval.lanl_l2_checks [--smoke-day D]
"""

import argparse
import sys
import time

import numpy as np
import pandas as pd
import pyarrow.compute as pc

from eval import lanl_la3 as L  # noqa: E402

import config  # noqa: E402
from agents.rules_v3 import normalize_account  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

COLS = ["time", "src_user", "src_computer", "dst_computer", "success"]


def codes(col):
    enc = pc.dictionary_encode(col).combine_chunks()
    return enc.indices.to_numpy(zero_copy_only=False).astype(np.int64), enc.dictionary.to_pylist()


def check_day(d, rt):
    t = time.perf_counter()
    tbl = L.day_table(d, COLS)
    n = tbl.num_rows
    keep = L.filter_mask(tbl)
    rt_day = rt[rt["day"] == d]
    pos, per_event, pairs = L.label_day(tbl, rt_day)

    # frozen-field checks
    u_idx, u_names = codes(tbl.column("src_user"))
    normed = [normalize_account(x) for x in u_names]
    unknown_ids = {normalize_account(x) for x in config.UNKNOWN_ACCOUNT_IDS}
    unk = np.array([x in unknown_ids for x in normed], bool)
    acc_codes, acc_uniq = pd.factorize(pd.Series(normed))
    acc = acc_codes[u_idx]
    ip, _ = codes(tbl.column("src_computer"))
    tm = tbl.column("time").to_numpy()
    st = pc.equal(tbl.column("success"), "Success").to_numpy(zero_copy_only=False).astype(np.int64)
    key = (tm.astype(np.int64) << 40) | (ip << 22) | (acc.astype(np.int64) << 1) | st
    dup_rows = n - len(np.unique(key))
    out = {
        "rows": n,
        "filtered_rows": int(keep.sum()),
        "positive_rows": int(pos.sum()),
        "positive_rows_passing_filter": int((pos & keep).sum()),
        "unknown_account_rows": int(unk[u_idx].sum()),
        "rows_dropped_by_duplicate_check_without_event_id": int(dup_rows),
        "distinct_src_user_strings": len(u_names),
        "distinct_accounts_after_casefold": len(acc_uniq),
        "seconds": round(time.perf_counter() - t, 1),
    }
    ev_pass = {}
    if len(pairs):
        pk = keep[pairs["row"].to_numpy()]
        ev_pass = pd.Series(pk).groupby(pairs["event"].to_numpy()).any().to_dict()
    return out, per_event, ev_pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke-day", type=int, default=None)
    args = ap.parse_args()
    rt = L.redteam_dev()
    days = L.split_days()
    all_days = [args.smoke_day] if args.smoke_day is not None else list(range(0, L.c3_day()))
    per_day, per_event, ev_pass = {}, {}, {}
    t = time.perf_counter()
    for d in all_days:
        o, pe, ep = check_day(d, rt)
        per_day[d] = o
        per_event.update(pe)
        ev_pass.update(ep)
        print(f"day {d:02d}: {o}", flush=True)
    if args.smoke_day is not None:
        L.save_json("lanl_l2_checks_smoke.json", {"day": args.smoke_day, **per_day[args.smoke_day],
                                                   "peak_working_set_bytes": peak_working_set(),
                                                   "estimate_all_dev_days_seconds":
                                                       round(per_day[args.smoke_day]["seconds"] * L.c3_day())})
        return 0

    splits = {}
    for s, (lo, hi) in days.items():
        ds = [per_day[d] for d in range(lo, hi)]
        f = np.array([x["filtered_rows"] for x in ds])
        r = np.array([x["rows"] for x in ds])
        ev = rt[rt["split"] == s]
        matched = ev["event"].map(lambda e: per_event.get(e, 0)).to_numpy()
        passed = ev["event"].map(lambda e: bool(ev_pass.get(e, False))).to_numpy()
        splits[s] = {
            "days": [lo, hi],
            "filtered_rows_per_day": {"min": int(f.min()), "mean": float(f.mean()), "max": int(f.max())},
            "filtered_rows": int(f.sum()), "rows": int(r.sum()),
            "filtered_share": float(f.sum() / r.sum()),
            "redteam_events": int(len(ev)),
            "redteam_users": int(ev["user"].nunique()),
            "events_matched": int((matched > 0).sum()),
            "events_unmatched": int((matched == 0).sum()),
            "matched_rows_per_matched_event": ({"min": int(matched[matched > 0].min()),
                                                "max": int(matched[matched > 0].max())}
                                               if (matched > 0).any() else None),
            "positive_rows": int(sum(per_day[d]["positive_rows"] for d in range(lo, hi))),
            "positive_rows_passing_filter": int(sum(per_day[d]["positive_rows_passing_filter"]
                                                    for d in range(lo, hi))),
            "events_passing_filter": int(passed.sum()),
            "users_passing_filter": int(ev.loc[passed, "user"].nunique()),
            "unknown_account_rows": int(sum(per_day[d]["unknown_account_rows"] for d in range(lo, hi))),
            "rows_dropped_by_duplicate_check_without_event_id": int(sum(
                per_day[d]["rows_dropped_by_duplicate_check_without_event_id"] for d in range(lo, hi))),
        }
    matched_all = rt["event"].map(lambda e: per_event.get(e, 0)).to_numpy()
    out = {
        "scope": "dev days 0-13 only",
        "splits": splits,
        "dev": {
            "redteam_events": int(len(rt)),
            "events_matched": int((matched_all > 0).sum()),
            "events_unmatched": int((matched_all == 0).sum()),
            "matched_rows_per_matched_event": {"min": int(matched_all[matched_all > 0].min()),
                                               "max": int(matched_all[matched_all > 0].max())},
            "events_passing_filter": int(sum(bool(ev_pass.get(e, False)) for e in rt["event"])),
            "users_passing_filter": int(rt.loc[[bool(ev_pass.get(e, False)) for e in rt["event"]],
                                               "user"].nunique()),
            "redteam_users": int(rt["user"].nunique()),
        },
        "per_day": {f"{d:02d}": v for d, v in per_day.items()},
        "seconds": round(time.perf_counter() - t, 1),
        "peak_working_set_bytes": peak_working_set(),
    }
    L.save_json("lanl_l2_checks.json", out)
    print({k: v for k, v in out.items() if k != "per_day"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
