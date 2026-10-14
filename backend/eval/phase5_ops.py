# backend/eval/phase5_ops.py
"""
Phase 5 operational stages (called through `python -m eval.phase5`):

  replay   The real MonitoringAgent with the new defaults (RULES_MODE v3,
           ML_MODE v4 with the forest retired, the amendment 6 policy) over
           dev_train, val_a and val_b. Every event goes through the
           production path (_process_event_v3: detection, triage, analysis,
           response, store). Compared with the offline `response` stage:
           rule alerts per detector, running score and tier at every alerted
           event, blocked / challenged state before every event, the email
           log and each incident's email outcome. Alerts of one day (--day)
           are also written to a fresh SQLite store, timing each insert.
  store    SQLite insert and query cost on that day's alerts (one
           transaction per alert, as the pipeline does), and the legacy JSON
           store on the first 2,000 of them for comparison.

phase="5b" (python -m eval.phase5b replay / store): the amendment 7 policy;
the offline run, selection and outputs are Phase 5b's (results/phase5b_*),
and `store` re-measures the queries on Phase 5's day and on the new one,
without the JSON comparison.
"""

import json
import os
import time
from collections import Counter

import numpy as np

import config
from agents import rules_v3 as R
from agents import triage as TR
from eval import phase4 as P4
from eval import phase5 as P5
from eval.phase3_rules import Clock


class RecordingAlerter:
    enabled = True

    def send_incident(self, incident):
        return True

    def send_digest(self, hour, incidents):
        return True


class ReplayStore:
    """Records what the pipeline saves; alerts of one day also go to a
    SQLite store (timed) and to a JSONL file for the `store` stage."""

    def __init__(self, day, db_path, jsonl_path):
        from utils.alert_store_sqlite import SqliteAlertStore
        self.day = day
        self.i = -1
        self.rows = []                 # (event index, type, tier, score, email)
        for p in (db_path, db_path + "-wal", db_path + "-shm", jsonl_path):
            if os.path.exists(p):
                os.remove(p)
        self.db = SqliteAlertStore(db_path)
        self.jsonl = open(jsonl_path, "w", encoding="utf-8")
        self.insert_s = []

    def save_alert(self, a):
        inc = a.get("incident") or {}
        self.rows.append((self.i, a["type"], inc.get("tier"), tuple(inc.get("score") or ()),
                          inc.get("email")))
        if a.get("detected_at", "")[:10] == self.day:
            t = time.perf_counter()
            self.db.save_alert(a)
            self.insert_s.append(time.perf_counter() - t)
            self.jsonl.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")

    def close(self):
        self.jsonl.close()
        self.db.close()


def _phase(phase):
    """(cache path function, selection file, output prefix)."""
    if phase == "5b":
        from eval import phase5b as P5B
        return P5B.cpath, "phase5b_selection.json", "phase5b"
    return P5.cpath, "phase5_selection.json", "phase5"


def stage_replay(args, phase="5"):
    from agents.monitoring_agent import MonitoringAgent
    from agents.response_agent import ResponseAgent
    assert (config.RULES_MODE, config.ML_MODE, config.ML_V4_IFOREST) == ("v3", "v4", "retired"), \
        "the replay gate runs with the new defaults"
    clk = Clock()
    t = time.time()
    cpath, sel_file, prefix = _phase(phase)
    S = P5.stream()
    sel = P5.load_json(sel_file)
    assert config.TRIAGE_SCORE == sel["chosen"]
    t_ = sel["tiers"]
    assert config.RESPONSE_TIER_RATES == {"block": t_["block_rate"], "step_up": t_["step_up_rate"],
                                          "queue": t_["queue_rate"]}, "config rates != selection"
    z = np.load(cpath("deployed.npz"))
    with open(cpath("email_log.json")) as f:
        em = json.load(f)
    n = args.limit or S.n
    clk.tick("load stream and the offline deployed run", t)

    store = ReplayStore(args.day, cpath("store_day.db"), cpath("store_day.jsonl"))
    responder = ResponseAgent(email_alerter=RecordingAlerter(), email_log_max=None)
    mon = MonitoringAgent(alert_manager=store, responder=responder)
    assert mon.detector.anomaly_detector is None, "v4 with the forest retired runs no ML step"
    got_blocked = np.zeros(n, bool)
    got_challenged = np.zeros(n, bool)
    t = time.time()
    for i, e in enumerate(P4.events(S, with_id=True)):
        if i >= n:
            break
        st = responder.status(e)
        got_blocked[i], got_challenged[i] = st["blocked"], st["challenged"]
        store.i = i
        mon._process_event(e)
    responder.flush()
    t_replay = time.time() - t
    store.close()
    clk.tick(f"real agents, new defaults ({n:,} events)", t)

    # ── comparison ──────────────────────────────────────────────────────
    t = time.time()
    spans = {"dev_train": ~S.val, "val_a": S.val_a, "val_b": S.val_b}
    spans = {k: m[:n] for k, m in spans.items()}
    rows = store.rows
    pos = np.array([r[0] for r in rows], np.int64)
    typ = [r[1] for r in rows]
    check, ok = {"detectors": {}}, True
    for d in R.RULE_DETECTORS:
        exp = np.zeros(n, bool)
        p = S.rule_alerts[d]
        exp[p[p < n]] = True
        got = np.zeros(n, bool)
        got[pos[[x == d for x in typ]]] = True
        check["detectors"][d] = {s: int((exp != got)[m].sum()) for s, m in spans.items()}
        ok &= all(v == 0 for v in check["detectors"][d].values())
    ml_alerts = sum(x == R.ML for x in typ)
    ok &= ml_alerts == 0

    p_off, tier_off, run = z["p"], z["tier_ev"], [z[f"score{j}"] for j in range(len(z.files) - 6)]
    j_of = {int(p): j for j, p in enumerate(p_off.tolist()) if p < n}
    tier_mm = score_mm = 0
    by_span = Counter()
    seen = set()
    for i, ty, tier, score, email in rows:
        if ty == R.ML or i in seen:
            continue
        seen.add(i)
        j = j_of.get(i)
        bad_t = j is None or tier != TR.TIERS[tier_off[j]]
        bad_s = j is None or score != tuple(float(c[j]) for c in run)
        tier_mm += bad_t
        score_mm += bad_s
        if bad_t or bad_s:
            by_span[next(s for s, m in spans.items() if m[i])] += 1
    missing = len(set(j_of) - seen)
    ok &= tier_mm == 0 and score_mm == 0 and missing == 0
    blk_mm = {s: int((got_blocked != z["blocked"][:n])[m].sum()) for s, m in spans.items()}
    chl_mm = {s: int((got_challenged != z["challenged"][:n])[m].sum()) for s, m in spans.items()}
    ok &= all(v == 0 for v in blk_mm.values()) and all(v == 0 for v in chl_mm.values())

    last_hour = int(S.t[n - 1]) // 3600
    norm = lambda log: Counter((k, int(h), tuple(ids), o) for k, h, ids, o in log   # noqa: E731
                               if args.limit == 0 or int(h) < last_hour)
    got_log, exp_log = norm(responder.notifier.log), norm(em["log"])
    email_mm = sum(((got_log - exp_log) + (exp_log - got_log)).values())
    exp_out = {int(k): v for k, v in em["outcome"].items() if int(k) < n}
    got_out = {i: e for i, ty, tier, score, e in rows if e not in (None, "not_required")}
    out_mm = sum(1 for k in set(exp_out) | set(got_out) if exp_out.get(k) != got_out.get(k)
                 and (args.limit == 0 or int(S.t[k]) // 3600 < last_hour))
    ok &= email_mm == 0 and out_mm == 0
    clk.tick("comparison", t)

    per_day = {}
    for kind, hour, ids, outcome in responder.notifier.log:
        if kind != "cooldown":
            d = str(np.datetime64(int(hour) // 24, "D"))
            per_day.setdefault(d, Counter())[kind] += 1
    ins = np.array(store.insert_s)
    out = {"equivalent": bool(ok), "events": int(n), "limit": int(args.limit),
           "defaults": {"RULES_MODE": config.RULES_MODE, "ML_MODE": config.ML_MODE,
                        "ML_V4_IFOREST": config.ML_V4_IFOREST, "TRIAGE_SCORE": config.TRIAGE_SCORE,
                        "RESPONSE_TIER_RATES": config.RESPONSE_TIER_RATES},
           "alerts_saved": len(rows), "ml_alerts": int(ml_alerts),
           "detector_alert_mismatches": check["detectors"],
           "alerted_events_compared": len(seen), "alerted_events_missing": int(missing),
           "tier_mismatches": int(tier_mm), "score_mismatches": int(score_mm),
           "tier_or_score_mismatches_by_span": dict(by_span),
           "blocked_state_mismatches": blk_mm, "challenged_state_mismatches": chl_mm,
           "email_log_mismatches": int(email_mm), "incident_email_outcome_mismatches": int(out_mm),
           "email_log_entries": len(responder.notifier.log),
           "emails_per_day": {d: dict(c) for d, c in sorted(per_day.items())},
           "blocked_source_events": mon.blocked_source_events,
           "challenged_source_events": mon.challenged_source_events,
           "duplicate_events": mon.duplicate_events,
           "state_sizes_end": {"rules": mon.detector.state_sizes(),
                               "triage": responder.triage.state_sizes()},
           "store_day": args.day,
           "store_inline_inserts": int(len(ins)),
           "store_inline_insert_us_mean": round(1e6 * float(ins.mean()), 1) if len(ins) else None,
           "store_inline_insert_us_p99": round(1e6 * float(np.percentile(ins, 99)), 1) if len(ins) else None,
           "replay_seconds": round(t_replay, 1), "replay_us_per_event": round(1e6 * t_replay / n, 1),
           "peak_rss_mb": P4.peak_rss_mb(), "timings_seconds": clk.total()}
    name = f"{prefix}_replay_check.json" if not args.limit else f"{prefix}_replay_smoke.json"
    P5.save_json(name, out)
    print(json.dumps({k: v for k, v in out.items() if k != "emails_per_day"}, indent=1))
    return 0 if ok else 1


def _timed(fn, reps=20):
    ts = []
    for _ in range(reps):
        t = time.perf_counter()
        r = fn()
        ts.append(time.perf_counter() - t)
    return {"ms_median": round(1e3 * float(np.median(ts)), 3), "ms_max": round(1e3 * max(ts), 3),
            "rows": len(r) if hasattr(r, "__len__") else None}


def stage_store(args, phase="5"):
    if phase == "5b":
        from eval import phase5b as P5B
        out = {}
        for label, cp in (("phase5_day_alerts", P5.cpath), ("phase5b_day_alerts", P5B.cpath)):
            if os.path.exists(cp("store_day.jsonl")):
                out[label], _ = _store_sqlite(cp("store_day.jsonl"), P5B.cpath(f"store_bench_{label}.db"))
        assert out, "run a replay first (it writes the day's alerts)"
        P5.save_json("phase5b_store.json", out)
        print(json.dumps(out, indent=1))
        return
    out, alerts = _store_sqlite(P5.cpath("store_day.jsonl"), P5.cpath("store_bench.db"))
    _store_json(out, alerts)


def _store_sqlite(src, db):
    from utils.alert_store_sqlite import SqliteAlertStore
    with open(src, encoding="utf-8") as f:
        alerts = [json.loads(line) for line in f]
    assert alerts, "run `replay` first (it writes the day's alerts)"
    out = {"day": alerts[0]["detected_at"][:10], "alerts": len(alerts),
           "incidents": len({(a.get("incident") or {}).get("incident_id") for a in alerts}),
           "alerts_by_tier": dict(Counter((a.get("incident") or {}).get("tier") for a in alerts))}

    for p in (db, db + "-wal", db + "-shm"):
        if os.path.exists(p):
            os.remove(p)
    s = SqliteAlertStore(db)
    ts = []
    t0 = time.perf_counter()
    for a in alerts:
        t = time.perf_counter()
        s.save_alert(dict(a))
        ts.append(time.perf_counter() - t)
    total = time.perf_counter() - t0
    ts = np.array(ts)
    out["sqlite_insert"] = {"per_alert_transaction": True, "total_s": round(total, 2),
                            "us_mean": round(1e6 * float(ts.mean()), 1),
                            "us_p50": round(1e6 * float(np.median(ts)), 1),
                            "us_p99": round(1e6 * float(np.percentile(ts, 99)), 1),
                            "us_max": round(1e6 * float(ts.max()), 1)}
    s._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    out["sqlite_file_mb"] = round(os.path.getsize(db) / 2**20, 2)
    ip = max(Counter(a["ip"] for a in alerts).items(), key=lambda kv: kv[1])[0]
    s._cache_key = None
    out["sqlite_queries"] = {
        "recent_2000 (/api/alerts)": _timed(lambda: s.query(limit=2000)),
        "tier=step_up, 500": _timed(lambda: s.query(tier="step_up", limit=500)),
        f"ip (busiest, {ip})": _timed(lambda: s.query(ip=ip, limit=5000)),
        "incidents tier=step_up, 500 (/api/incidents)": _timed(lambda: s.incidents(tier="step_up", limit=500)),
        "stats (/api/stats)": _timed(lambda: list(s.stats().items())),
        "hourly (/api/timeline)": _timed(s.hourly),
        "by_type (/api/detectors)": _timed(s.by_type),
        "enrichment_counts": _timed(lambda: list(s.enrichment_counts().items())),
        "load_cached, unchanged (LLM scanner)": _timed(s.load_cached),
    }
    out["tier_query_plan"] = " | ".join(r[3] for r in s._con.execute(
        "EXPLAIN QUERY PLAN SELECT body FROM alerts WHERE tier = ? ORDER BY id DESC LIMIT ?",
        ("step_up", 500)))
    s.close()
    return out, alerts


def _store_json(out, alerts):
    from utils.alert_manager import AlertManager
    n_json = min(2000, len(alerts))
    jpath = P5.cpath("store_bench.json")
    if os.path.exists(jpath):
        os.remove(jpath)
    js = AlertManager(jpath)
    jt = []
    for a in alerts[:n_json]:
        t = time.perf_counter()
        js.save_alert(dict(a))
        jt.append(time.perf_counter() - t)
    jt = np.array(jt)
    out["json_insert_first_2000"] = {
        "alerts": n_json, "total_s": round(float(jt.sum()), 2),
        "us_mean": round(1e6 * float(jt.mean()), 1),
        "us_first_100_mean": round(1e6 * float(jt[:100].mean()), 1),
        "us_last_100_mean": round(1e6 * float(jt[-100:].mean()), 1),
        "file_mb": round(os.path.getsize(jpath) / 2**20, 2),
        "note": "the JSON store rewrites the whole file on every save (quadratic in the day)"}
    P5.save_json("phase5_store.json", out)
    print(json.dumps(out, indent=1))
