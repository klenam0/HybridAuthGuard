# backend/eval/lanl_a_metrics.py
"""
LA3.6 metrics for A (eval/lanl_a.py, causal twin run from day 0) on the dev
splits: dev_train (warm-up context), val_a, val_b.

Definitions used (LA3.6 names the measures; these are their operational forms):
  red-team events     every red-team event of the split, matched or not (LA3.1)
  caught (detector)   the event's matched auth row raised that detector's alert
  caught (tier)       the matched row is an alerted event whose running tier at
                      that event is the tier; "challenged source" counts
                      matched rows whose IP was under a step-up challenge
                      before the event
  precision           share of the counted alerted rows that are LA3.1 positives
  legit users / day   distinct source accounts with a non-positive event from a
                      challenged IP that day, mean over the split's days
  incidents           (source computer, day); final tier = the incident's tier
                      at its last alerted event
Intervals (LA3.7 / LA2.6): with >= 20 distinct red-team users, 95% percentile
bootstrap over red-team users (1,000 resamples, seed 42), positive rows and
events weighted by their user's multiplicity, negatives fixed; otherwise
exact counts. Strata: LA1.5 new vs returning users (caught counts and shares).

Writes results/lanl_a_dev.json.
"""

import json
import os
import sys
import time
from collections import OrderedDict

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from agents import triage as TR  # noqa: E402
from eval import lanl_a as A  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

B, SEED, MIN_USERS = 1000, 42, 20
LABEL_COLS = ["time", "src_user", "src_computer", "dst_computer"]


def boot_weights(users):
    """(B, U) multiplicities of each user in B resamples of the user list."""
    rng = np.random.default_rng(SEED)
    U = len(users)
    draws = rng.integers(0, U, size=(B, U))
    w = np.zeros((B, U), np.int64)
    for b in range(B):
        np.add.at(w[b], draws[b], 1)
    return w


def ci(x):
    return [float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5))]


def caught_block(ev, caught, users, W=None):
    """Events / users caught out of all red-team events of the scope."""
    n_ev, n_u = len(ev), len(users)
    c_ev = int(caught.sum())
    cu = set(ev.loc[caught, "user"])
    out = {"events_caught": c_ev, "events": n_ev, "users_caught": len(cu), "users": n_u,
           "mode": "bootstrap" if n_u >= MIN_USERS else "exact counts"}
    if n_u >= MIN_USERS and W is not None:
        uidx = {u: j for j, u in enumerate(users)}
        ue = np.bincount(ev["user"].map(uidx).to_numpy(), minlength=n_u)
        uc = np.bincount(ev.loc[caught, "user"].map(uidx).to_numpy(), minlength=n_u)
        uany = (uc > 0).astype(np.int64)
        out["events_caught_share"] = c_ev / n_ev
        out["events_caught_share_ci95"] = ci((W @ uc) / (W @ ue))
        out["users_caught_share"] = len(cu) / n_u
        out["users_caught_share_ci95"] = ci((W @ uany) / W.sum(1))
    return out


def precision_block(pos_alert_user, neg_alerts, users, W=None):
    """Precision of a set of alerted rows: positive rows carry their user."""
    p = len(pos_alert_user)
    tot = p + neg_alerts
    out = {"alerts": int(tot), "positive_alerts": int(p),
           "precision": (p / tot) if tot else None}
    if W is not None and len(users) >= MIN_USERS and tot:
        uidx = {u: j for j, u in enumerate(users)}
        up = np.bincount(np.array([uidx[u] for u in pos_alert_user], np.int64), minlength=len(users))
        wp = W @ up
        out["precision_ci95"] = ci(wp / (wp + neg_alerts))
    return out


def main():
    t_all = time.perf_counter()
    days = L.split_days()
    rt = L.redteam_dev()
    adir = A.adir("causal")
    res = OrderedDict()
    for split, (lo, hi) in days.items():
        ev = rt[rt["split"] == split].reset_index(drop=True)
        users = sorted(ev["user"].unique())
        W = boot_weights(users) if len(users) >= MIN_USERS else None
        det_alert = {x: [] for x in A.DETS}
        det_neg = {x: 0 for x in A.DETS}
        tier_pos = {t: [] for t in TR.TIERS}
        tier_neg = {t: 0 for t in TR.TIERS}
        any_neg = 0
        any_pos = []
        ev_flags = {x: np.zeros(len(ev), bool) for x in list(A.DETS) + list(TR.TIERS) + ["any", "challenged"]}
        inc_rows = []
        legit_per_day = []
        ev_index = {int(e): j for j, e in enumerate(ev["event"])}
        for d in range(lo, hi):
            z = np.load(os.path.join(adir, f"day={d:02d}.npz"))
            tbl = L.day_table(d, LABEL_COLS)
            pos, _, pairs = L.label_day(tbl, rt[rt["day"] == d])
            row_events = pairs.groupby("row")["event"].apply(list).to_dict()
            src_user = tbl.column("src_user")
            a_pos = z["a_pos"]
            tier_ev = z["tier_ev"]
            for x in A.DETS:
                p = z[f"alert::{x}"]
                isp = pos[p]
                det_neg[x] += int((~isp).sum())
                for r in p[isp].tolist():
                    det_alert[x].append(src_user[r].as_py())
                    for e in row_events.get(r, []):
                        if e in ev_index:
                            ev_flags[x][ev_index[e]] = True
            isp = pos[a_pos]
            any_neg += int((~isp).sum())
            for r in a_pos[isp].tolist():
                any_pos.append(src_user[r].as_py())
                for e in row_events.get(r, []):
                    if e in ev_index:
                        ev_flags["any"][ev_index[e]] = True
            for ti, tname in enumerate(TR.TIERS):
                sel = tier_ev == ti
                pp = a_pos[sel]
                ip_ = pos[pp]
                tier_neg[tname] += int((~ip_).sum())
                for r in pp[ip_].tolist():
                    tier_pos[tname].append(src_user[r].as_py())
                    for e in row_events.get(r, []):
                        if e in ev_index:
                            ev_flags[tname][ev_index[e]] = True
            ch = z["challenged"]
            for r in np.flatnonzero(ch & pos).tolist():
                for e in row_events.get(r, []):
                    if e in ev_index:
                        ev_flags["challenged"][ev_index[e]] = True
            legit = np.flatnonzero(ch & ~pos)
            if len(legit):
                names = src_user.take(legit).to_pylist()
                legit_per_day.append(len({A.normalize_account(s) for s in names}))
            else:
                legit_per_day.append(0)
            # incidents: (src computer, day); final tier = tier at the last alerted event
            ipcol = tbl.column("src_computer").take(a_pos).to_pylist() if len(a_pos) else []
            if len(a_pos):
                df = pd.DataFrame({"ip": ipcol, "tier": tier_ev, "pos": isp})
                g = df.groupby("ip", sort=False)
                inc_rows.append(pd.DataFrame({"final": g["tier"].last(), "positive": g["pos"].any()}))
        inc = pd.concat(inc_rows) if inc_rows else pd.DataFrame({"final": [], "positive": []})
        out = OrderedDict()
        out["redteam_events"] = int(len(ev))
        out["redteam_users"] = len(users)
        out["mode"] = "bootstrap" if W is not None else "exact counts"
        out["detectors"] = OrderedDict()
        for x in A.DETS:
            out["detectors"][x] = {**precision_block(det_alert[x], det_neg[x], users, W),
                                   **caught_block(ev, ev_flags[x], users, W)}
        out["any_rule_alert"] = {**precision_block(any_pos, any_neg, users, W),
                                 **caught_block(ev, ev_flags["any"], users, W)}
        out["tiers"] = OrderedDict()
        for ti, tname in enumerate(TR.TIERS):
            blk = {"alerted_events_at_tier": precision_block(tier_pos[tname], tier_neg[tname], users, W),
                   **caught_block(ev, ev_flags[tname], users, W),
                   "incidents_final_tier": int((inc["final"] == ti).sum()),
                   "incidents_final_tier_with_positive": int(((inc["final"] == ti) & inc["positive"]).sum())}
            out["tiers"][tname] = blk
        out["tiers"]["step_up"]["challenged_source"] = caught_block(ev, ev_flags["challenged"], users, W)
        out["tiers"]["step_up"]["legitimate_users_challenged_per_day"] = float(np.mean(legit_per_day))
        out["tiers"]["step_up"]["legitimate_users_challenged_daily"] = legit_per_day
        strata = OrderedDict()
        for name, m in (("new_users", ~ev["returning_user"].to_numpy()),
                        ("returning_users", ev["returning_user"].to_numpy())):
            sev = ev[m].reset_index(drop=True)
            su = sorted(sev["user"].unique())
            SW = boot_weights(su) if len(su) >= MIN_USERS else None
            strata[name] = {"redteam_events": int(len(sev)), "redteam_users": len(su),
                            "mode": "bootstrap" if SW is not None else "exact counts"}
            for key in list(A.DETS) + ["any", "step_up", "queue", "challenged"]:
                strata[name][key] = caught_block(sev, ev_flags[key][m], su, SW)
        out["strata_la1_5_users"] = strata
        res[split] = out
        print(split, "done", flush=True)
    res["definitions"] = __doc__
    res["seconds"] = round(time.perf_counter() - t_all, 1)
    res["peak_working_set_bytes"] = peak_working_set()
    L.save_json("lanl_a_dev.json", res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
