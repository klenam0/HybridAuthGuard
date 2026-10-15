# backend/eval/lanl_d_metrics.py
"""
LA3.6 metrics with LA3.7 intervals for D1, D2, D3 on val_a and val_b
(eval/lanl_d.py outputs). No verdict (LA3.8 applies to the test only).

Ranking: every score is ranked by (score descending, stream position
ascending) -- LA3.5's tie-break -- so each ranking is strict.
  ROC-AUC   share of (positive, negative) pairs with the positive ranked first
  PR-AUC    average precision of the strict ranking (sum over positives of the
            precision at the positive, / positives; equals
            sklearn.metrics.average_precision_score of the strict ranking,
            checked below)
  daily top-k  ranked within each day; k in {100, 1,000, 10,000}:
            positives (rows) caught, red-team events caught (events whose
            matched row is caught), red-team users caught, precision =
            caught rows / selected rows over the split's days, lift =
            precision / the split's filtered base rate
  all-red-team line  events and users caught at each k over every red-team
            event of the split (unmatched or filter-excluded = missed)
Intervals: with >= 20 distinct red-team users in the split or stratum, a
95% percentile bootstrap over red-team users (1,000 resamples, seed 42): a
user drawn w times contributes w copies of each of its positive rows, placed
next to the original in the ranking; negatives are fixed. Otherwise exact
counts. Strata (LA1.5): new vs returning users; a stratum's population is the
split's filtered rows without the other stratum's positives.

Writes results/lanl_d_dev.json.
"""

import json
import os
import sys
import time
from collections import OrderedDict

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_d as D  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402
from eval.lanl_a_metrics import B, MIN_USERS, boot_weights, ci  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

KS = (100, 1000, 10000)
SCORERS = ("D1", "D2", "D3")


def load_split(split):
    lo, hi = L.split_days()[split]
    parts = {k: [] for k in ("pos", "day", "y", "D1", "D2", "D3")}
    pair_rows, pair_events = [], []
    base = 0
    for d in range(lo, hi):
        z = np.load(D.dpath(f"day={d:02d}.npz"))
        m = len(z["rows"])
        parts["pos"].append(z["pos"])
        parts["day"].append(np.full(m, d, np.int64))
        parts["y"].append(z["y"])
        parts["D1"].append(np.load(D.dpath(f"d1_day={d:02d}.npy")))
        parts["D2"].append(z["d2"])
        parts["D3"].append(z["d3"])
        # pairs refer to day-local rows; map to the filtered index of the split
        idx = np.full(int(z["n_day"]), -1, np.int64)
        idx[z["rows"]] = base + np.arange(m)
        pr = idx[z["pairs_row"]]
        assert (pr >= 0).all(), "a positive row is outside the filter"
        pair_rows.append(pr)
        pair_events.append(z["pairs_event"])
        base += m
    out = {k: np.concatenate(v) for k, v in parts.items()}
    out["pair_rows"] = np.concatenate(pair_rows) if pair_rows else np.zeros(0, np.int64)
    out["pair_events"] = np.concatenate(pair_events) if pair_events else np.zeros(0, np.int64)
    return out


def ranks(score, pos, groups=None):
    """0-based rank under (score desc, pos asc), overall or within groups."""
    if groups is None:
        o = np.lexsort((pos, -score))
        r = np.empty(len(score), np.int64)
        r[o] = np.arange(len(score))
        return r
    o = np.lexsort((pos, -score, groups))
    g = groups[o]
    start = np.searchsorted(g, g, side="left")
    r = np.empty(len(score), np.int64)
    r[o] = np.arange(len(score)) - start
    return r


def evaluate(sc, pos, day, y, row_user, row_events, users, ev_users_all, Wu):
    """Metrics of one scorer on one population. y marks the population's
    positives; row_user / row_events give each positive row's user index and
    event count; ev_users_all: user index of every red-team event in scope."""
    n = len(sc)
    P = int(y.sum())
    N = n - P
    pi = np.flatnonzero(y)
    rg = ranks(sc, pos)
    rd = ranks(sc, pos, day)
    # negatives above each positive (overall and within its day)
    og = np.argsort(rg[pi])
    order_g = pi[og]
    neg_above_g = rg[order_g] - np.arange(P)
    dd = day[pi]
    o_d = np.lexsort((rd[pi], dd))
    pd_ = pi[o_d]
    dsort = day[pd_]
    first = np.searchsorted(dsort, dsort, side="left")
    neg_above_d = rd[pd_] - (np.arange(P) - first)
    U = len(users)
    out = OrderedDict()
    # point estimates (all weights 1)
    out["population_rows"], out["positives"] = int(n), P
    out["base_rate"] = P / n
    out["roc_auc"] = float(np.mean((N - neg_above_g) / N)) if P and N else None
    out["pr_auc"] = float(np.mean((np.arange(P) + 1) / (neg_above_g + np.arange(P) + 1))) if P else None
    days_u, n_day = np.unique(day, return_counts=True)
    pos_day = np.bincount(np.searchsorted(days_u, dd), minlength=len(days_u))
    uidx_g = row_user[og]          # row_user / row_events are aligned with pi
    uidx_d = row_user[o_d]
    ev_g = row_events[og]
    ev_d = row_events[o_d]
    n_ev_all = len(ev_users_all)

    def at_k(k, w_d, wsum_day, wtot, W_users):
        # w_d: (R, P) weights in day order; wsum_day: (R, days)
        R = w_d.shape[0]
        cum = np.cumsum(w_d, axis=1)
        prefix = np.concatenate([np.zeros((R, 1), np.int64), cum], axis=1)
        wb = cum - w_d - prefix[:, first]          # weight of earlier positives that day
        caught = np.clip(k - neg_above_d[None, :] - wb, 0, w_d)
        neg_day = n_day[None, :] - pos_day[None, :]
        selected = np.minimum(k, neg_day + wsum_day).sum(1)
        rows_c = caught.sum(1)
        prec = rows_c / selected
        base = wtot / (N + wtot)
        ev_c = (caught * ev_d[None, :]).sum(1)
        # users: copy c of a user is caught if any of its rows has >= c copies caught
        ucaught = np.zeros((R, U), np.int64)
        for j in range(P):
            ucaught[:, uidx_d[j]] = np.maximum(ucaught[:, uidx_d[j]], caught[:, j])
        users_c = np.minimum(ucaught, W_users).sum(1)
        return rows_c, ev_c, users_c, prec, prec / base

    # point
    w1 = np.ones((1, P), np.int64)
    W1u = np.ones((1, U), np.int64)
    ws1 = pos_day[None, :]
    pop_users = np.zeros(U, bool)
    pop_users[row_user] = True
    for k in KS:
        rows_c, ev_c, users_c, prec, lift = at_k(k, w1, ws1, P, W1u)
        users_in_pop = int(pop_users.sum())
        out[f"top{k}"] = {"rows_caught": int(rows_c[0]), "positives": P,
                          "events_caught": int(ev_c[0]), "events": int(row_events.sum()),
                          "users_caught": int(users_c[0]),
                          "users": users_in_pop,
                          "precision": float(prec[0]), "lift": float(lift[0]),
                          "all_redteam": {"events_caught": int(ev_c[0]), "events": n_ev_all,
                                          "users_caught": int(users_c[0]), "users": U}}
    if U >= MIN_USERS and P:
        Wp_g = Wu[:, uidx_g]
        Wp_d = Wu[:, uidx_d]
        wt = Wp_g.sum(1)
        out["roc_auc_ci95"] = ci((Wp_g * (N - neg_above_g)[None, :]).sum(1) / (N * wt))
        cumw = np.cumsum(Wp_g, axis=1)
        wb = cumw - Wp_g
        ap = np.zeros(B)
        for c in range(1, int(Wp_g.max()) + 1):
            on = Wp_g >= c
            ap += np.where(on, (wb + c) / (neg_above_g[None, :] + wb + c), 0).sum(1)
        out["pr_auc_ci95"] = ci(ap / wt)
        wsum_day = np.zeros((B, len(days_u)), np.int64)
        di = np.searchsorted(days_u, dsort)
        for j in range(P):
            wsum_day[:, di[j]] += Wp_d[:, j]
        ev_w_all = np.bincount(ev_users_all, minlength=U)
        for k in KS:
            rows_c, ev_c, users_c, prec, lift = at_k(k, Wp_d, wsum_day, wt, Wu * pop_users[None, :])
            blk = out[f"top{k}"]
            blk["precision_ci95"] = ci(prec)
            blk["lift_ci95"] = ci(lift)
            blk["events_caught_share_ci95"] = ci(ev_c / (Wp_d * ev_d[None, :]).sum(1))
            blk["users_caught_share_ci95"] = ci(users_c / (Wu * pop_users[None, :]).sum(1))
            blk["all_redteam"]["events_caught_share_ci95"] = ci(ev_c / (Wu @ ev_w_all))
            blk["all_redteam"]["users_caught_share_ci95"] = ci(users_c / Wu.sum(1))
    out["mode"] = "bootstrap" if (U >= MIN_USERS and P) else "exact counts"
    return out


def main(splits=("val_a", "val_b")):
    from sklearn.metrics import average_precision_score, roc_auc_score
    t_all = time.perf_counter()
    rt = L.redteam_dev()
    res = OrderedDict()
    checks = {}
    for split in splits:
        Z = load_split(split)
        ev = rt[rt["split"] == split]
        users = sorted(ev["user"].unique())
        uix = {u: j for j, u in enumerate(users)}
        ev_user = dict(zip(ev["event"].tolist(), ev["user"].map(uix).tolist()))
        n = len(Z["y"])
        row_user = np.full(n, -1, np.int64)
        row_events = np.zeros(n, np.int64)
        for r, e in zip(Z["pair_rows"].tolist(), Z["pair_events"].tolist()):
            row_user[r] = ev_user[e]
            row_events[r] += 1
        assert np.array_equal(row_user >= 0, Z["y"])
        ret = dict(zip(ev["user"].map(uix).tolist(), ev["returning_user"].tolist()))
        split_out = OrderedDict([("redteam_events", int(len(ev))), ("redteam_users", len(users)),
                                 ("filtered_rows", int(n)), ("positive_rows", int(Z["y"].sum()))])
        scopes = OrderedDict([("all", None), ("new_users", False), ("returning_users", True)])
        for scope, flag in scopes.items():
            if flag is None:
                keep_users = np.arange(len(users))
            else:
                keep_users = np.array([j for j in range(len(users)) if ret[j] == flag], np.int64)
            su = [users[j] for j in keep_users]
            remap = np.full(len(users), -1, np.int64)
            remap[keep_users] = np.arange(len(keep_users))
            y = Z["y"].copy()
            drop = y & (remap[np.maximum(row_user, 0)] < 0)
            pop = ~drop
            y = y[pop]
            ru = remap[np.maximum(row_user[pop], 0)][y]
            re = row_events[pop][y]
            ev_scope = np.array([remap[ev_user[e]] for e in ev["event"].tolist()
                                 if remap[ev_user[e]] >= 0], np.int64)
            Wu = boot_weights(su) if len(su) >= MIN_USERS else None
            blk = OrderedDict([("redteam_users", len(su)), ("redteam_events", int(len(ev_scope)))])
            for s in SCORERS:
                blk[s] = evaluate(Z[s][pop], Z["pos"][pop], Z["day"][pop], y, ru, re, su, ev_scope, Wu)
            split_out[scope] = blk
            print(split, scope, {s: (blk[s]["roc_auc"], blk[s]["pr_auc"]) for s in SCORERS}, flush=True)
        # check the strict-ranking AUC / AP against sklearn on the all-users population
        for s in SCORERS:
            r = ranks(Z[s], Z["pos"])
            surrogate = -r.astype(np.float64)
            checks[f"{split}:{s}"] = {
                "roc_auc_sklearn": float(roc_auc_score(Z["y"], surrogate)),
                "pr_auc_sklearn": float(average_precision_score(Z["y"], surrogate)),
                "roc_auc": split_out["all"][s]["roc_auc"], "pr_auc": split_out["all"][s]["pr_auc"]}
        res[split] = split_out
    res["check_strict_ranking_vs_sklearn"] = checks
    res["definitions"] = __doc__
    res["seconds"] = round(time.perf_counter() - t_all, 1)
    res["peak_working_set_bytes"] = peak_working_set()
    L.save_json("lanl_d_dev.json", res)
    print(json.dumps(checks, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
