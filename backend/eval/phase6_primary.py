# backend/eval/phase6_primary.py
"""
Phase 6 primary results P1-P4 (eval/PROTOCOL.md amendment 9) on May, with
val_a and val_b recomputed by the same code on the same stream (val_b
previously seen). The twin equals the real agents (phase6 replay gate), so
these are the agents' outputs. Run: python -m eval.phase6 primary
"""

import os
import time
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd

import config
from agents import triage as TR
from eval import phase3b as P3B
from eval import phase5 as P5
from eval import phase5b as P5B
from eval import phase6 as P6
from eval.phase3_rules import Clock

BAR_A = 0.2149
MIN_N = 30
SCORES = ("T2", "T0")


def _meets(r, bar):
    return bool(r["alerts" if "alerts" in r else "incidents"] >= MIN_N and r["ci_low"] >= bar)


def p1(S, half):
    """Per detector, per stratum: alert precision with the IP-clustered
    interval, attacking and benign IPs flagged; against 2 x base and 0.2149."""
    out = OrderedDict()
    bar = 2 * S.base[half]
    for st, sm in S.strata.items():
        part = sm & S.halves[half]
        att = S.attacking_ips(part)
        out[st] = OrderedDict()
        for d in P5.DETS:
            p = S.rule_alerts[d][part[S.rule_alerts[d]]]
            y = S.truth[p]
            ips = S.ip[p]
            lo, hi = P3B.bootstrap(ips, y)
            r = {"alerts": int(len(p)), "attack_alerts": int(y.sum()),
                 "precision": float(y.mean()) if len(p) else 0.0, "ci_low": lo, "ci_high": hi,
                 "attacking_ips_flagged": int(len(np.unique(ips[y]))),
                 "benign_ips_flagged": int(len(np.unique(ips[~att[ips]])))}
            r["meets_2x_base"] = _meets(r, bar)
            r["meets_0.2149"] = _meets(r, BAR_A)
            out[st][d] = r
    return {"base_rate": S.base[half], "bar_2x_base": bar, "events": int(S.halves[half].sum()),
            "attacking_ips": int(S.attacking_ips(S.halves[half]).sum()), "strata": out}


def p2(S, half):
    out = OrderedDict()
    for name in SCORES:
        out[name] = OrderedDict()
        for st, sm in S.strata.items():
            part = sm & S.halves[half]
            I = P5.Incidents(S, part)
            out[name][st] = P5.budget_metrics(S, I, I.final(name), S.attacking_ips(part))
    b2, b0 = out["T2"]["all"]["budgets"]["500"], out["T0"]["all"]["budgets"]["500"]
    return {"curves": out, "T2_lower_bound_B500": b2["daily_ci_low"],
            "T0_point_B500": b0["mean_daily_precision"],
            "T2_holds_vs_T0": bool(b2["daily_ci_low"] >= b0["mean_daily_precision"])}


def _emails(S, D, half):
    per = {}
    for kind, hour, ids, outcome in D["email_log"]:
        if kind != "cooldown":
            per.setdefault(int(hour) // 24, Counter())[kind] += 1
    days = np.unique(S.day[S.halves[half]])
    rows = [{"day": str(np.datetime64(int(d), "D")), "emails": per.get(int(d), Counter())["email"],
             "digests": per.get(int(d), Counter())["digest"]} for d in days]
    tot = [r["emails"] + r["digests"] for r in rows]
    hm = S.halves[half]
    oc = Counter(o for p, o in D["email_outcome"].items() if hm[p])
    return {"days": rows, "mean_per_day": float(np.mean(tot)), "max_per_day": int(max(tot)),
            "outcomes": dict(oc)}


def p3(S, C, D, D0, half):
    I = D["I"]
    hm = S.halves[half]
    days = np.unique(S.day[hm])
    n_days = len(days)
    in_h = np.isin(I.day, days)
    tiers = P5B.band(S, D, half, strata=True)
    for r in tiers.values():
        r["per_day"] = r["incidents"] / n_days
        r["meets_2x_base"] = bool(r["incidents"] >= MIN_N and r["ci_low"] >= 2 * S.base[half])
        r["meets_0.2149"] = bool(r["incidents"] >= MIN_N and r["ci_low"] >= BAR_A)
    cost = P5B.cost(S, D, half)
    for st, r in cost.items():
        su = r["step_up"]
        su["legitimate_users_max_day"] = int(max(su["legitimate_users_daily"]))
    # log tier's share of attacking IPs: highest tier over the half's attack incidents
    tier_inc = D["tier_inc"]
    m = in_h & I.attack
    best = pd.Series(tier_inc[m]).groupby(I.ip[m]).min()
    att_ips = S.attacking_ips(hm)
    n_att_inc = int(len(best))
    alerted_att = np.zeros(S.n_ip, bool)
    alerted_att[S.ip[I.p[(hm[I.p]) & S.truth[I.p]]]] = True
    log_share = {"attacking_ips": int(att_ips.sum()),
                 "attacking_ips_with_an_attack_incident": n_att_inc,
                 "highest_tier_counts": {TR.TIERS[int(k)]: int(v) for k, v in best.value_counts().sort_index().items()},
                 "log_share_of_those": float((best == 3).mean()) if n_att_inc else 0.0,
                 "attacking_ips_without_any_rule_alert": int((att_ips & ~alerted_att).sum())}
    adm = {}
    for ti, tier in enumerate(TR.RATED_TIERS):
        vc = pd.Series(I.day[(tier_inc == ti) & in_h]).value_counts()
        adm[tier] = int(vc.max()) if len(vc) else 0
    # how often the amendment 8 floor binds (with vs without it)
    t0, t1 = D0["tier_inc"], tier_inc
    kept = (t0 <= 2) & (t1 > t0) & in_h
    up = (t1 < t0) & in_h
    floor = {"kept_out_of_step_up": int((kept & (t0 == 1)).sum()),
             "kept_out_of_step_up_attack": int((kept & (t0 == 1) & I.attack).sum()),
             "kept_out_of_queue": int((kept & (t0 == 2)).sum()),
             "kept_out_of_queue_attack": int((kept & (t0 == 2) & I.attack).sum()),
             "moved_up": int(up.sum()), "days_floor_binds": int(len(np.unique(I.day[kept])))}
    return {"days": n_days, "tiers": tiers, "response_cost": cost, "log_tier": log_share,
            "admitted_max_per_day": adm,
            "blocks_placed_events": int(((D["tier_ev"] == 0) & hm[I.p]).sum()),
            "challenges_placed_events": int(((D["tier_ev"] == 1) & hm[I.p]).sum()),
            "emails": _emails(S, D, half), "floor_binding": floor}


def p4(S, half):
    out = OrderedDict()
    days = np.unique(S.day[S.halves[half]])
    for st, sm in S.strata.items():
        part = sm & S.halves[half]
        I = P5.Incidents(S, part)
        lo, hi = P3B.bootstrap(I.ip, I.attack)
        n_alerts = int(sum(int(part[S.rule_alerts[d]].sum()) for d in P5.DETS))
        out[st] = {"incidents": int(I.n_inc), "incidents_per_day": I.n_inc / len(days),
                   "incident_precision": float(I.attack.mean()) if I.n_inc else 0.0,
                   "ci_low": lo, "ci_high": hi, "rule_alerts": n_alerts,
                   "rule_alerts_per_day": n_alerts / len(days),
                   "attacking_ips_in_attack_incidents": int(len(np.unique(I.ip[I.attack])))}
    return out


def consistency(S, res):
    """The val_a / val_b columns must equal the earlier phases' numbers."""
    c = OrderedDict()
    sel = P5.load_json("phase3b_selection.json")["chosen"]
    c["P1_val_a_equals_phase3b"] = all(
        res["val_a"]["P1"]["strata"]["all"][d]["alerts"] == sel[d]["alerts"]
        and res["val_a"]["P1"]["strata"]["all"][d]["precision"] == sel[d]["precision"]
        and res["val_a"]["P1"]["strata"]["all"][d]["ci_low"] == sel[d]["ci_low"] for d in P5.DETS)
    conf = P5.load_json("phase5_confirm.json")["curves_val_b"]
    c["P2_val_b_equals_phase5_confirm"] = all(
        res["val_b"]["P2"]["curves"][n]["all"]["budgets"][B]["mean_daily_precision"]
        == conf[n]["all"]["budgets"][B]["mean_daily_precision"] for n in SCORES for B in ("100", "500", "2000"))
    fl = P5.load_json("phase5c_floor.json")["halves"]
    c["P3_tiers_equal_phase5c"] = all(
        res[h]["P3"]["tiers"][t]["incidents"] == fl[h]["with_floor"]["tiers"][t]["incidents"]
        and res[h]["P3"]["tiers"][t]["precision"] == fl[h]["with_floor"]["tiers"][t]["precision"]
        for h in ("val_a", "val_b") for t in TR.TIERS)
    c["ok"] = all(c.values())
    return c


def main(args):
    clk = Clock()
    S = P6.build(args.dev_only, clk)
    C, D = P6.twin(S, clk)
    t = time.time()
    D0 = P5B.run(S, C, P6.rates())          # without the floor, for its binding count
    clk.tick("deployed run without the floor", t)
    res = OrderedDict()
    for half in S.halves:
        t = time.time()
        res[half] = OrderedDict([("previously_seen", half != "may"),
                                 ("P1", p1(S, half)), ("P2", p2(S, half)),
                                 ("P3", p3(S, C, D, D0, half)), ("P4", p4(S, half))])
        clk.tick(f"P1-P4 on {half}", t)
    check = consistency(S, res)
    out = {"protocol": "eval/PROTOCOL.md amendment 9", "consistency_with_earlier_phases": check,
           "results": res, "timings_seconds": clk.total()}
    P5.save_json("phase6_primary.json" if not args.dev_only else "phase6_primary_devonly.json", out)
    print("consistency", check)
    for half, r in res.items():
        a = r["P1"]
        print(f"== {half}: base {a['base_rate']:.4f}, events {a['events']:,}, attacking IPs {a['attacking_ips']:,}")
        for d, x in a["strata"]["all"].items():
            print(f"  P1 {d:26s} n {x['alerts']:>7} prec {x['precision']:.3f} [{x['ci_low']:.3f}, {x['ci_high']:.3f}] "
                  f"att {x['attacking_ips_flagged']:>5} ben {x['benign_ips_flagged']:>6} "
                  f"2xbase {x['meets_2x_base']} 0.2149 {x['meets_0.2149']}")
        for n_ in SCORES:
            bb = r["P2"]["curves"][n_]["all"]["budgets"]
            print(f"  P2 {n_}: " + "  ".join(f"B{B} prec/d {v['mean_daily_precision']:.3f} [{v['daily_ci_low']:.3f}, "
                                            f"{v['daily_ci_high']:.3f}] caught/d {v['mean_daily_attacking_ips_caught']:.1f} "
                                            f"month {v['attacking_ips_caught']}" for B, v in bb.items()))
        print(f"  P2 T2 holds vs T0: {r['P2']['T2_holds_vs_T0']}")
        for tier, x in r["P3"]["tiers"].items():
            print(f"  P3 {tier:8s} n {x['incidents']:>7} ({x['per_day']:.1f}/d) prec {x['precision']:.3f} "
                  f"[{x['ci_low']:.3f}, {x['ci_high']:.3f}] att IPs {x['attacking_ips']}")
        su = r["P3"]["response_cost"]["all"]["step_up"]
        print(f"  P3 step-up: users {su['legitimate_users_affected']} ({su['legitimate_users_per_day']:.1f}/d, "
              f"max {su['legitimate_users_max_day']}) ben IPs {su['ips_placed_benign']} att IPs {su['ips_placed_attacking']}")
        print(f"  P3 log tier {r['P3']['log_tier']}; blocks {r['P3']['blocks_placed_events']}; "
              f"emails {r['P3']['emails']['mean_per_day']:.1f}/d max {r['P3']['emails']['max_per_day']}; "
              f"floor {r['P3']['floor_binding']}; admitted {r['P3']['admitted_max_per_day']}")
        x = r["P4"]["all"]
        print(f"  P4 incidents {x['incidents']} ({x['incidents_per_day']:.1f}/d) prec {x['incident_precision']:.3f} "
              f"[{x['ci_low']:.3f}, {x['ci_high']:.3f}] alerts/d {x['rule_alerts_per_day']:.0f}")
    return 0 if check["ok"] else 1
