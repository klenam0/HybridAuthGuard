# backend/eval/phase5b.py
"""
Phase 5b: capped causal tier admission and a volume-bounded step-up rate
(eval/PROTOCOL.md amendment 7), and a descriptive label audit. Rules,
T2 and the block criterion are frozen; the locked test month is never read.

Stages (run from backend/, in order):
  python -m eval.phase5b select     block rows (amendment 6 grid, capped) and
                                    the step-up grid on val_a; k_step with
                                    U = 200; the U sensitivity table. No
                                    val_b metric.
  python -m eval.phase5b response   the deployed run with the chosen rates:
                                    tiers and response cost per stratum on
                                    val_a and val_b (val_b previously seen),
                                    emails; caches for the replay gate
  python -m eval.phase5b audit      label audit (descriptive only)
  python -m eval.phase5b replay     real agents with the new defaults vs
                                    `response` (eval/phase5_ops.stage_replay)
  python -m eval.phase5b store      SQLite query cost after the tier-filter fix

Reuses Phase 5's stream, incidents and running ranks (eval/phase5.py), the
frozen rule alerts (phase3b_cache) and the ASN ratio (phase4_cache / phase5_cache).
"""

import argparse
import os
import sys
import time
from collections import OrderedDict

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import triage as TR  # noqa: E402
from eval import phase5 as P5  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402

RESULTS = P5.RESULTS
CACHE = os.path.join(RESULTS, "phase5b_cache")
save_json, load_json = P5.save_json, P5.load_json

# ── Amendment 7 ──────────────────────────────────────────────────────────────
SCORE = "T2"                                   # amendment 6 choice, frozen
STEP_RATES = (10, 25, 50, 100, 200, 500, 1000)
U = 200
U_SENSITIVITY = (50, 200, 1000)
QUEUE_RATE = P5.QUEUE_RATE
BLOCK_BAR, STEP_BAR, STEP_BAR_B = P5.BLOCK_BAR, P5.STEP_BAR, P5.STEP_BAR_B
MIN_INCIDENTS = P5.MIN_INCIDENTS
PLACEHOLDER_MIN = 20                           # label audit: strict misuse


def cpath(name):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, name)


# ── Capped admission (offline twin of agents/triage.IncidentTriage) ──────────

def capped_entries(C, rates, floor=()):
    """Per rated tier: per incident, the index (into I.p) of the alerted
    event at which it entered the tier, or -1. Top down: an event is
    eligible for a tier if the running rank reaches the day's cutoff and the
    incident is not yet in a higher tier; each day the first k eligible
    incidents (by their first eligible event, stream order) are admitted.
    `floor` (amendment 8): detectors of which the incident must carry an
    alert at the event (running indicator); () = no floor."""
    I = C.I
    n_ev = len(I.p)
    pos = np.arange(n_ev)
    ev_day_idx = np.searchsorted(C.days, I.day[I.inc])
    higher = np.full(I.n_inc, -1, np.int64)          # earliest entry into a higher tier
    floor_ok = (I.ind[:, [P5.DETS.index(d) for d in floor]].any(1) if floor
                else np.ones(n_ev, bool))
    out = {}
    for tier in TR.RATED_TIERS:
        k = int(rates.get(tier) or 0)
        if not k:
            continue
        cut = C.cutoff(k)
        c_ev = np.array([cut[int(d)] for d in C.days], dtype=np.float64)
        hit = (C.rank >= c_ev[ev_day_idx]) & floor_ok
        h = higher[I.inc]
        elig = hit & ~((h >= 0) & (pos >= h))
        first = np.full(I.n_inc, n_ev, np.int64)
        idx = np.flatnonzero(elig)
        np.minimum.at(first, I.inc[idx], idx)
        ci = np.flatnonzero(first < n_ev)
        order = ci[np.lexsort((first[ci], I.day[ci]))]
        ds = I.day[order]
        rnk = np.arange(len(order)) - np.searchsorted(ds, ds, side="left")
        adm = order[rnk < k]
        e = np.full(I.n_inc, -1, np.int64)
        e[adm] = first[adm]
        out[tier] = e
        higher = np.where(e >= 0, np.where(higher >= 0, np.minimum(higher, e), e), higher)
    return out


def run(S, C, rates, floor=()):
    rates = {t: int(rates.get(t) or 0) for t in TR.RATED_TIERS}
    D = P5.deployed_run(S, C, capped_entries(C, rates, floor), rates)
    tier_inc = np.full(C.I.n_inc, 3, np.int8)
    np.minimum.at(tier_inc, C.I.inc, D["tier_ev"])
    D["tier_inc"] = tier_inc
    return D


# ── Volume and cost per day ──────────────────────────────────────────────────

def _per_day(days, d_codes, n_days_codes):
    """Mean over the half's days of the count of codes per day."""
    if len(d_codes) == 0:
        return 0.0, [0] * len(days)
    cnt = pd.Series(d_codes).value_counts()
    per = [int(cnt.get(int(d), 0)) for d in days]
    return float(np.mean(per)), per


def cost(S, D, half, strata=True):
    """Phase 5's response cost per stratum plus per-day means: legitimate
    users challenged, benign / attacking IPs challenged, step-up incidents."""
    base = P5.response_cost(S, D, half)
    hm = S.halves[half]
    days = np.unique(S.day[hm])
    I = D["I"]
    place_c = np.zeros(S.n, bool)
    place_c[I.p[D["tier_ev"] == 1]] = True
    under = D["challenged"] & ~D["blocked"]
    in_h = np.isin(I.day, days)
    out = OrderedDict()
    for st, sm in S.strata.items():
        if not strata and st != "all":
            continue
        E = sm & hm
        att = S.attacking_ips(E)
        has = np.zeros(S.n_ip, bool)
        has[S.ip[E]] = True
        ben = has & ~att
        legit = E & under & ~S.truth & ~S.unknown
        u_pairs = np.unique(S.day[legit] * np.int64(S.n_user) + S.user[legit])
        users_pd, users_days = _per_day(days, u_pairs // S.n_user, len(days))
        pl = place_c & hm
        ip_pairs = np.unique(S.day[pl] * np.int64(S.n_ip) + S.ip[pl])
        pd_ip, pd_day = ip_pairs % S.n_ip, ip_pairs // S.n_ip
        ben_pd, _ = _per_day(days, pd_day[ben[pd_ip]], len(days))
        att_pd, _ = _per_day(days, pd_day[att[pd_ip]], len(days))
        r = base[st]
        r["step_up"]["legitimate_users_per_day"] = users_pd
        r["step_up"]["legitimate_users_daily"] = users_days
        r["step_up"]["benign_ips_per_day"] = ben_pd
        r["step_up"]["attacking_ips_per_day"] = att_pd
        if st == "all":
            r["step_up_incidents_per_day"] = float((D["tier_inc"] == 1)[in_h].sum() / len(days))
        out[st] = r
    return out


def band(S, D, half, strata=False):
    I = D["I"]
    in_h = np.isin(I.day, np.unique(S.day[S.halves[half]]))
    return {tier: P5.region_metrics(S, I, D["tier_inc"] == ti, in_h, strata=strata)
            for ti, tier in enumerate(TR.TIERS)}


def choose(rows, u):
    ok = [r for r in rows if r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR
          and r["legitimate_users_per_day"] <= u]
    if not ok:
        return 0
    return max(ok, key=lambda r: (r["attacking_ips_challenged"], -r["rate"]))["rate"]


# ── Stage: select (val_a only) ───────────────────────────────────────────────

def stage_select(args):
    clk = Clock()
    t = time.time()
    S = P5.stream()
    C = P5.Causal(S, SCORE, None)
    I = C.I
    in_a = np.isin(I.day, np.unique(S.day[S.val_a]))
    n_days_a = len(np.unique(S.day[S.val_a]))
    clk.tick("stream, incidents, running ranks (T2)", t)

    t = time.time()
    block_rows = []
    for k in P5.RATES:
        e = capped_entries(C, {"block": k})["block"]
        r = P5.region_metrics(S, I, e >= 0, in_a, strata=False)
        r["rate"] = k
        r["meets_block"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= BLOCK_BAR)
        block_rows.append(r)
    kb = max([r["rate"] for r in block_rows if r["meets_block"]], default=0)
    clk.tick("block rows (capped, amendment 6 grid)", t)

    t = time.time()
    rows = []
    for k in STEP_RATES:
        D = run(S, C, {"block": kb, "step_up": k, "queue": QUEUE_RATE})
        b = band(S, D, "val_a")
        c = cost(S, D, "val_a", strata=False)["all"]
        su = c["step_up"]
        r = {"rate": k, **b["step_up"],
             "step_up_incidents_per_day": c["step_up_incidents_per_day"],
             "max_step_up_incidents_in_a_day": int(pd.Series(I.day[(D["tier_inc"] == 1) & in_a])
                                                   .value_counts().max()) if b["step_up"]["incidents"] else 0,
             "attacking_ips_challenged": su["ips_placed_attacking"],
             "attacking_ips_per_day": su["attacking_ips_per_day"],
             "benign_ips_challenged": su["ips_placed_benign"],
             "benign_ips_per_day": su["benign_ips_per_day"],
             "legitimate_users_challenged": su["legitimate_users_affected"],
             "legitimate_users_per_day": su["legitimate_users_per_day"],
             "benign_events_challenged": su["benign_events_affected"],
             "attack_events_challenged": su["attack_events_affected"],
             "queue_incidents_per_day": b["queue"]["incidents"] / n_days_a}
        r["meets_precision"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR)
        rows.append(r)
        print(f"k={k:>5}: band n {r['incidents']:>6} ({r['step_up_incidents_per_day']:.1f}/d, max "
              f"{r['max_step_up_incidents_in_a_day']}) prec {r['precision']:.3f} [{r['ci_low']:.3f}, "
              f"{r['ci_high']:.3f}] att IPs {r['attacking_ips_challenged']} ({r['attacking_ips_per_day']:.1f}/d) "
              f"ben IPs {r['benign_ips_challenged']} ({r['benign_ips_per_day']:.1f}/d) "
              f"users/d {r['legitimate_users_per_day']:.1f}", flush=True)
    clk.tick(f"step-up grid ({len(STEP_RATES)} deployed runs)", t)

    ks = choose(rows, U)
    sens = [{"U": u, "k_step": choose(rows, u)} for u in U_SENSITIVITY]
    out = {"protocol": "eval/PROTOCOL.md amendment 7", "half": "val_a", "chosen": SCORE,
           "U": U, "block_rate": kb, "step_up_rate": ks, "queue_rate": QUEUE_RATE,
           "tiers": {"block_rate": kb, "step_up_rate": ks, "queue_rate": QUEUE_RATE},
           "status": (f"step-up at {ks}/day" if ks else "no k qualifies: no step-up tier"),
           "block_rows_val_a": block_rows, "step_up_rows_val_a": rows,
           "u_sensitivity": sens, "timings_seconds": clk.total()}
    save_json("phase5b_selection.json", out)
    print(f"block rate {kb}; step-up rate {ks} (U = {U}); sensitivity {sens}")


# ── Stage: response (the chosen rates; val_b previously seen) ────────────────

def stage_response(args):
    import json
    clk = Clock()
    t = time.time()
    S = P5.stream()
    sel = load_json("phase5b_selection.json")
    rates = dict(sel["tiers"])
    rates = {"block": rates["block_rate"], "step_up": rates["step_up_rate"], "queue": rates["queue_rate"]}
    C = P5.Causal(S, SCORE, None)
    clk.tick("stream, selection, running ranks", t)
    t = time.time()
    D = run(S, C, rates)
    clk.tick("deployed causal run (capped)", t)
    t = time.time()
    I = D["I"]
    per_tier, costs = OrderedDict(), OrderedDict()
    for half in ("val_a", "val_b"):
        n_days = len(np.unique(S.day[S.halves[half]]))
        per_tier[half] = band(S, D, half, strata=True)
        for tier, r in per_tier[half].items():
            r["per_day"] = r["incidents"] / n_days
            r["meets_0.80"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= BLOCK_BAR)
            r["meets_0.2149"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR)
            r["meets_0.1915"] = bool(r["incidents"] >= MIN_INCIDENTS and r["ci_low"] >= STEP_BAR_B)
        costs[half] = cost(S, D, half)
    # admitted per day per tier, over the whole stream (the cap holds by construction)
    adm = {}
    for ti, tier in enumerate(TR.RATED_TIERS):
        if rates[tier]:
            vc = pd.Series(I.day[D["tier_inc"] == ti]).value_counts()
            adm[tier] = {"max_per_day": int(vc.max()) if len(vc) else 0, "rate": rates[tier]}
    emails, outcomes = P5.email_per_day(S, D)
    clk.tick("tiers, costs, emails", t)
    np.savez_compressed(cpath("deployed.npz"), p=I.p, tier_ev=D["tier_ev"], prev_ev=D["prev_ev"],
                        rank=D["C"].rank, blocked=D["blocked"], challenged=D["challenged"],
                        **{f"score{j}": c for j, c in enumerate(D["C"].run)})
    with open(cpath("email_log.json"), "w") as f:
        json.dump({"log": D["email_log"], "outcome": {str(k): v for k, v in D["email_outcome"].items()}}, f)
    out = {"protocol": "eval/PROTOCOL.md amendment 7", "chosen": SCORE, "rates": rates,
           "val_b_previously_seen": True,
           "note": "val_b is reported as previously seen (amendment 7): it confirms nothing",
           "tiers_per_half": per_tier, "response_cost": costs, "admitted_max_per_day": adm,
           "emails_per_day": emails, "email_outcomes": outcomes,
           "blocks_placed_events": int((D["tier_ev"] == 0).sum()),
           "challenges_placed_events": int((D["tier_ev"] == 1).sum()),
           "timings_seconds": clk.total()}
    save_json("phase5b_response.json", out)
    for half, per in per_tier.items():
        for tier, r in per.items():
            print(f"{half} {tier:8s} {r['per_day']:>8.1f}/day prec {r['precision']:.3f} "
                  f"[{r['ci_low']:.3f}, {r['ci_high']:.3f}] att IPs {r['attacking_ips']}")
    for st, r in costs["val_b"].items():
        su = r["step_up"]
        print(f"val_b {st:20s} users {su['legitimate_users_affected']:>6} ({su['legitimate_users_per_day']:.1f}/d) "
              f"ben IPs {su['ips_placed_benign']:>5} att IPs {su['ips_placed_attacking']:>5}")
    for span, e in emails.items():
        print(f"emails {span}: mean {e['mean_per_day']:.1f}/day, max {e['max_per_day']}")
    print("admitted", adm, "outcomes", outcomes)


# ── Stage: audit (descriptive only) ──────────────────────────────────────────

def _q(x):
    x = np.asarray(x, np.float64)
    if len(x) == 0:
        return {"n": 0, "median": None, "p90": None}
    return {"n": int(len(x)), "median": float(np.median(x)), "p90": float(np.percentile(x, 90))}


def _distinct_per_ip(S, m, codes, n_codes):
    pairs = np.unique(S.ip[m] * np.int64(n_codes) + codes[m])
    return np.bincount(pairs // n_codes, minlength=S.n_ip)


def stage_audit(args):
    clk = Clock()
    t = time.time()
    S = P5.stream()
    country, _ = pd.factorize(S.df["Country"].astype(str).to_numpy())
    country = country.astype(np.int64)
    n_country = int(country.max()) + 1
    train = ~S.val
    att_asns = np.unique(S.asn[train & S.truth])
    asn_hit = np.isin(S.asn, att_asns)
    ret = S.att_train
    # whole dev history (dev_train + val_a + val_b) per IP
    hist_ph = np.bincount(S.ip, weights=S.unknown, minlength=S.n_ip)
    hist_succ = np.bincount(S.ip, weights=S.success, minlength=S.n_ip)
    clk.tick("stream", t)
    out = OrderedDict()
    for half in ("val_a", "val_b"):
        t = time.time()
        hm = S.halves[half]
        ips = S.ip[hm]
        present = np.zeros(S.n_ip, bool)
        present[ips] = True
        att = S.attacking_ips(hm)
        alerted = np.zeros(S.n_ip, bool)
        ap = S.a_pos[hm[S.a_pos]]
        alerted[S.ip[ap]] = True
        benign = present & ~att & ~ret
        groups = OrderedDict([
            ("R (returning attacking, alerted)", att & ret & alerted),
            ("N alerted (new attacking)", att & ~ret & alerted),
            ("N not alerted (new attacking)", att & ~ret & ~alerted),
            ("BA (benign, alerted, new-attacker stratum)", benign & alerted),
            ("BN (benign, not alerted, new-attacker stratum)", benign & ~alerted),
        ])
        ev = np.bincount(ips, minlength=S.n_ip)
        fail = np.bincount(ips, weights=S.failed[hm], minlength=S.n_ip)
        ph = np.bincount(ips, weights=S.unknown[hm], minlength=S.n_ip)
        succ = np.bincount(ips, weights=S.success[hm], minlength=S.n_ip)
        days = _distinct_per_ip(S, hm, S.day, int(S.day.max()) + 1)
        accts = _distinct_per_ip(S, hm, S.user, S.n_user)
        ctry = _distinct_per_ip(S, hm, country, n_country)
        asn_ip = np.zeros(S.n_ip, bool)
        asn_ip[S.ip[hm & asn_hit]] = True
        res = OrderedDict()
        for g, gm in groups.items():
            idx = np.flatnonzero(gm)
            res[g] = {"ips": int(len(idx)), "events": int(ev[idx].sum()),
                      "events_per_ip": _q(ev[idx]), "active_days": _q(days[idx]),
                      "failure_ratio": _q(fail[idx] / np.maximum(ev[idx], 1)),
                      "distinct_accounts": _q(accts[idx]), "placeholder_attempts": _q(ph[idx]),
                      "successful_logins": _q(succ[idx]), "distinct_countries": _q(ctry[idx]),
                      "share_single_event": float((ev[idx] == 1).mean()) if len(idx) else None,
                      "share_le_5_events": float((ev[idx] <= 5).mean()) if len(idx) else None,
                      "share_asn_hosts_dev_train_attacker": float(asn_ip[idx].mean()) if len(idx) else None}
        ba = groups["BA (benign, alerted, new-attacker stratum)"]
        strict = ba & (hist_ph >= PLACEHOLDER_MIN) & (hist_succ == 0)
        res["BA strict misuse"] = {
            "definition": f">= {PLACEHOLDER_MIN} placeholder attempts and 0 successful logins over "
                          "the IP's whole dev history (dev_train + val_a + val_b)",
            "ips": int(strict.sum()), "of_BA": int(ba.sum()),
            "share": float(strict.sum() / max(ba.sum(), 1)),
            "their_half_events": int(ev[strict].sum()),
            "their_half_alerted_events": int(strict[S.ip[ap]].sum()),
            "half_only_variant_ips": int((ba & (ph >= PLACEHOLDER_MIN) & (succ == 0)).sum())}
        R_ = groups["R (returning attacking, alerted)"]
        res["R strict misuse (reference)"] = {
            "ips": int((R_ & (hist_ph >= PLACEHOLDER_MIN) & (hist_succ == 0)).sum()), "of_R": int(R_.sum())}
        res["alerted_events_by_group"] = {g: int(gm[S.ip[ap]].sum()) for g, gm in groups.items()}
        out[half] = res
        clk.tick(f"audit {half}", t)
    out = {"protocol": "eval/PROTOCOL.md amendment 7, label audit (descriptive only; chooses nothing)",
           "halves": out, "dev_train_attack_asns": int(len(att_asns)), "timings_seconds": clk.total()}
    save_json("phase5b_label_audit.json", out)
    for half, res in out["halves"].items():
        print(f"== {half}")
        for g, r in res.items():
            if "events_per_ip" in r:
                print(f"{g:50s} IPs {r['ips']:>7}  ev med {r['events_per_ip']['median']} p90 "
                      f"{r['events_per_ip']['p90']}  fail {r['failure_ratio']['median']:.2f}  accts "
                      f"{r['distinct_accounts']['median']}/{r['distinct_accounts']['p90']}  ph "
                      f"{r['placeholder_attempts']['median']}/{r['placeholder_attempts']['p90']}  succ "
                      f"{r['successful_logins']['median']}/{r['successful_logins']['p90']}  asn "
                      f"{r['share_asn_hosts_dev_train_attacker']:.3f}")
            else:
                print(g, r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["select", "response", "audit", "replay", "store"])
    ap.add_argument("--day", default="2020-04-20", help="replay / store: the day written to SQLite")
    ap.add_argument("--limit", type=int, default=0, help="replay: first N events only (smoke)")
    args = ap.parse_args()
    stages = {"select": stage_select, "response": stage_response, "audit": stage_audit}
    if args.stage in ("replay", "store"):
        from eval import phase5_ops
        stages["replay"] = lambda a: phase5_ops.stage_replay(a, phase="5b")
        stages["store"] = lambda a: phase5_ops.stage_store(a, phase="5b")
    return stages[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
