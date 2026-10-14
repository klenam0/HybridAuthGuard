# backend/eval/phase5c.py
"""
Phase 5c: the score floor of eval/PROTOCOL.md amendment 8, and the freeze.
Rules, T2, the rates and the capped admission are frozen; the locked test
month is never read.

Stages (run from backend/):
  python -m eval.phase5c floor     the deployed run with and without the
                                   floor: tiers and step-up cost on val_a and
                                   val_b (both previously seen), how often the
                                   floor binds over the whole stream; caches
                                   for the replay gate
  python -m eval.phase5c replay    real agents with the final defaults vs
                                   `floor` (eval/phase5_ops.stage_replay)
  python -m eval.phase5c freeze    results/FREEZE.json (hashes, policy table,
                                   detector settings, commit)

Reuses Phase 5's stream, incidents and running ranks and Phase 5b's capped
admission (eval/phase5b.capped_entries, which takes the floor).
"""

import argparse
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

import config  # noqa: E402
from agents import triage as TR  # noqa: E402
from eval import phase5 as P5  # noqa: E402
from eval import phase5b as P5B  # noqa: E402
from eval.phase3_rules import Clock  # noqa: E402

RESULTS = P5.RESULTS
CACHE = os.path.join(RESULTS, "phase5c_cache")
save_json, load_json = P5.save_json, P5.load_json
SCORE = P5B.SCORE


def cpath(name):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, name)


def floor_detectors():
    """Amendment 8: the detectors that met amendment 3's criterion on val_a
    and held on val_b, read from Phase 3b's results (rule detectors only)."""
    conf = load_json("phase3b_confirm.json")["detectors"]
    return [d for d in TR.RULE_DETECTORS if conf[d]["val_a_meets"] and conf[d]["val_b_holds"]]


def _rates():
    t = load_json("phase5b_selection.json")["tiers"]
    return {"block": t["block_rate"], "step_up": t["step_up_rate"], "queue": t["queue_rate"]}


def _summary(S, D, half):
    n_days = len(np.unique(S.day[S.halves[half]]))
    tiers = P5B.band(S, D, half, strata=False)
    for r in tiers.values():
        r["per_day"] = r["incidents"] / n_days
    c = P5B.cost(S, D, half, strata=True)
    su = {st: {k: r["step_up"][k] for k in ("ips_placed_attacking", "ips_placed_benign",
                                            "legitimate_users_affected", "legitimate_users_per_day",
                                            "benign_events_affected", "attack_events_affected")}
          for st, r in c.items()}
    su["all"]["legitimate_users_max_day"] = int(max(c["all"]["step_up"]["legitimate_users_daily"]))
    return {"tiers": tiers, "step_up_cost": su}


def stage_floor(args):
    clk = Clock()
    t = time.time()
    floor = floor_detectors()
    assert list(config.RESPONSE_FLOOR_DETECTORS) == floor, "config floor != phase3b survivors"
    S = P5.stream()
    rates = _rates()
    assert config.RESPONSE_TIER_RATES == rates and config.TRIAGE_SCORE == SCORE
    C = P5.Causal(S, SCORE, None)
    I = C.I
    clk.tick("stream, incidents, running ranks (T2)", t)

    t = time.time()
    D0 = P5B.run(S, C, rates)                  # amendment 7 (Phase 5b)
    D1 = P5B.run(S, C, rates, floor)           # amendment 8
    clk.tick("deployed runs without / with the floor", t)

    t = time.time()
    halves = OrderedDict()
    for half in ("val_a", "val_b"):
        halves[half] = {"previously_seen": True, "without_floor": _summary(S, D0, half),
                        "with_floor": _summary(S, D1, half)}

    # how often the floor binds (whole stream: dev_train, val_a, val_b)
    fi = [P5.DETS.index(d) for d in floor]
    below = ~I.ind[I.last][:, fi].any(1)           # no floor detector by the final event
    t0, t1 = D0["tier_inc"], D1["tier_inc"]
    kept_out = (t0 <= 2) & (t1 > t0)               # lower tier with the floor
    moved_up = t1 < t0                             # freed slots
    span_of = {"dev_train": ~S.val, "val_a": S.val_a, "val_b": S.val_b}
    binds = OrderedDict()
    for span, m in span_of.items():
        days = np.unique(S.day[m])
        ind = np.isin(I.day, days)
        r = {"days": int(len(days)), "incidents": int(ind.sum()),
             "below_floor_incidents": int((below & ind).sum()),
             "below_floor_attack_incidents": int((below & ind & I.attack).sum())}
        for ti, tier in ((1, "step_up"), (2, "queue")):
            k = ind & kept_out & (t0 == ti)
            r[f"kept_out_of_{tier}"] = int(k.sum())
            r[f"kept_out_of_{tier}_attack"] = int((k & I.attack).sum())
            r[f"kept_out_of_{tier}_days"] = int(len(np.unique(I.day[k])))
            u = ind & moved_up & (t1 == ti)
            r[f"moved_into_{tier}"] = int(u.sum())
            r[f"moved_into_{tier}_attack"] = int((u & I.attack).sum())
        r["days_floor_binds"] = int(len(np.unique(I.day[ind & kept_out])))
        binds[span] = r
    # detector composition of the below-floor incidents (whole stream)
    names = {}
    for j in np.flatnonzero(below):
        key = " + ".join(d for q, d in enumerate(P5.DETS) if I.ind[I.last[j], q])
        names[key] = names.get(key, 0) + 1
    adm = {}
    for ti, tier in enumerate(TR.RATED_TIERS):
        if rates[tier]:
            vc = pd.Series(I.day[t1 == ti]).value_counts()
            adm[tier] = int(vc.max()) if len(vc) else 0
    emails, outcomes = P5.email_per_day(S, D1)
    clk.tick("tiers, costs, binding, emails", t)

    np.savez_compressed(cpath("deployed.npz"), p=I.p, tier_ev=D1["tier_ev"], prev_ev=D1["prev_ev"],
                        rank=D1["C"].rank, blocked=D1["blocked"], challenged=D1["challenged"],
                        **{f"score{j}": c for j, c in enumerate(D1["C"].run)})
    with open(cpath("email_log.json"), "w") as f:
        json.dump({"log": D1["email_log"],
                   "outcome": {str(k): v for k, v in D1["email_outcome"].items()}}, f)
    out = {"protocol": "eval/PROTOCOL.md amendment 8", "chosen": SCORE, "rates": rates,
           "floor": floor, "previously_seen": "val_a and val_b are both previously seen",
           "halves": halves, "binding": binds,
           "below_floor_by_detectors": dict(sorted(names.items(), key=lambda kv: -kv[1])),
           "admitted_max_per_day": adm, "emails_per_day": emails, "email_outcomes": outcomes,
           "challenges_placed_events": int((D1["tier_ev"] == 1).sum()),
           "blocks_placed_events": int((D1["tier_ev"] == 0).sum()),
           "timings_seconds": clk.total()}
    save_json("phase5c_floor.json", out)
    for half, h in halves.items():
        for lab in ("without_floor", "with_floor"):
            for tier, r in h[lab]["tiers"].items():
                print(f"{half} {lab:13s} {tier:8s} n {r['incidents']:>7} ({r['per_day']:.1f}/d) "
                      f"prec {r['precision']:.3f} [{r['ci_low']:.3f}, {r['ci_high']:.3f}] "
                      f"att IPs {r['attacking_ips']}")
            su = h[lab]["step_up_cost"]["all"]
            print(f"   step-up: att IPs {su['ips_placed_attacking']} ben IPs {su['ips_placed_benign']} "
                  f"users {su['legitimate_users_affected']} ({su['legitimate_users_per_day']:.1f}/d)")
    print(json.dumps(binds, indent=1))
    print("admitted max/day", adm)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["floor", "replay", "freeze"])
    ap.add_argument("--day", default="2020-04-20", help="replay: the day written to SQLite")
    ap.add_argument("--limit", type=int, default=0, help="replay: first N events only (smoke)")
    args = ap.parse_args()
    stages = {"floor": stage_floor}
    if args.stage == "replay":
        from eval import phase5_ops
        stages["replay"] = lambda a: phase5_ops.stage_replay(a, phase="5c")
    if args.stage == "freeze":
        from eval import freeze
        stages["freeze"] = freeze.main
    return stages[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
