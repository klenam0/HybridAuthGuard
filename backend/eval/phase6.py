# backend/eval/phase6.py
"""
Phase 6: the final evaluation on the locked May 2020 test month
(eval/PROTOCOL.md amendment 9). The system is frozen (results/FREEZE.json);
nothing here changes it.

Stages (run from backend/):
  FINAL_EVAL=1 python -m eval.phase6 cache
                         the one read of the test month: load("test") with
                         every column, written to results/phase6_cache/
  python -m eval.phase6 twin [--dev-only]
                         the offline twin over dev + May: frozen rule alerts,
                         T2 running scores, capped tiers with the floor,
                         blocks / challenges, emails. --dev-only checks the
                         twin against the Phase 3b / 5c caches without May.
  python -m eval.phase6 replay [--limit N]
                         the real agents (frozen defaults) over dev + May vs
                         the twin, with per-stage timers (S5)
  python -m eval.phase6 primary
                         P1-P4 on May (val_a / val_b recomputed alongside)

Nothing here calls load("test") except `cache`. Every other stage reads the
cache. Secondary results S1-S4 are in eval/phase6_secondary.py.
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from agents import triage as TR  # noqa: E402
from eval import datasets  # noqa: E402
from eval import phase3_rules as P3  # noqa: E402
from eval import phase3b as P3B  # noqa: E402
from eval import phase4 as P4  # noqa: E402
from eval import phase5 as P5  # noqa: E402
from eval import phase5b as P5B  # noqa: E402
from eval.phase3_rules import Clock, Detector, Keyed, distinct_counts, failures_before, multi_ip_stats  # noqa: E402

RESULTS = P5.RESULTS
CACHE = os.path.join(RESULTS, "phase6_cache")
TEST_CACHE = os.path.join(CACHE, "test_2020-05.parquet")
MAY_START = int(np.datetime64("2020-05-01T00:00:00", "s").astype(np.int64))
STORE_DAY = "2020-05-15"
save_json, load_json = P5.save_json, P5.load_json
TS = datasets.TS


def cpath(name):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, name)


# ── Stage: cache (the one test read) ─────────────────────────────────────────

def stage_cache(args):
    assert os.environ.get("FINAL_EVAL") == "1", "set FINAL_EVAL=1 for this command only"
    assert not os.path.exists(TEST_CACHE), "the test month is already cached; read the cache"
    t = time.time()
    df = datasets.load("test")
    n = len(df)
    assert n == 2158083, n
    assert df[TS].min() >= datasets.TEST_START and df[TS].max() < datasets.TEST_END
    os.makedirs(CACHE, exist_ok=True)
    df.to_parquet(TEST_CACHE, index=False)
    print(f"cached {n:,} test rows to {TEST_CACHE} in {time.time() - t:.1f} s")


def read_test(columns):
    return pd.read_parquet(TEST_CACHE, columns=list(dict.fromkeys(columns)))


# ── The stream (dev, then May) ───────────────────────────────────────────────

def _frames(columns, dev_only):
    dev = datasets.load("dev", columns=columns)
    if dev_only:
        return [dev]
    may = read_test(columns)
    assert list(may.columns) == list(dev.columns)
    return [dev, may]


class Stream6(P3.Stream):
    """P3.Stream over dev + May (May events: S.may). val = dev_val only."""

    def __init__(self, dev_only=False):     # noqa: C901  (mirrors P3.Stream.__init__)
        parts = _frames(P3.COLS, dev_only)
        self.n_dev = len(parts[0])
        n_train = int((parts[0][TS] < datasets.DEV_TRAIN_END).sum())
        # IP codes: dev's category order (as P3.Stream), then May's new IPs, so
        # dev events keep their Phase 3 codes (bootstrap clusters and incident
        # order, hence intervals and tie-breaks, are reproduced exactly).
        dev_ips = parts[0]["IP Address"].astype("category").cat.categories
        cats = list(dev_ips)
        if len(parts) > 1:
            seen = set(cats)
            cats += sorted({x for x in parts[1]["IP Address"].astype(str).unique() if x not in seen})
        df = pd.concat([p.astype({c: object for c in p.columns if isinstance(p[c].dtype, pd.CategoricalDtype)})
                        for p in parts], ignore_index=True)
        df["IP Address"] = pd.Categorical(df["IP Address"].astype(str), categories=cats)
        assert not df["IP Address"].isna().any()
        for c in ("Country", "Device Type"):
            df[c] = df[c].astype("category")
        self.df = df
        n = self.n = len(df)
        self.n_train = n_train
        secs = df[TS].to_numpy().astype("datetime64[s]")
        self.t = secs.astype(np.int64)
        self.t0 = int(self.t[0])
        assert np.all(np.diff(self.t) >= 0), "stream must be time-ordered"
        self.hour = (self.t // 3600) % 24
        ipcat = df["IP Address"]
        self.ip = ipcat.cat.codes.to_numpy().astype(np.int64)
        self.ip_names = ipcat.cat.categories.astype(str).to_numpy(dtype=object)
        assert all(s == s.strip() for s in self.ip_names)
        self.n_ip = len(self.ip_names)
        uid = df["User ID"].to_numpy()
        codes, uniq = pd.factorize(uid)
        self.user, self.user_ids, self.n_user = codes.astype(np.int64), uniq, len(uniq)
        self.unknown = np.isin(uid, [int(x) for x in config.UNKNOWN_ACCOUNT_IDS])
        ok = df["Login Successful"].to_numpy().astype(bool)
        self.success, self.failed = ok, ~ok
        self.real_fail = self.failed & ~self.unknown
        self.real_succ = self.success & ~self.unknown
        self.truth = (df["Is Attack IP"].to_numpy() | df["Is Account Takeover"].to_numpy()).astype(bool)
        self.asn = df["ASN"].to_numpy().astype(np.int64)
        self.event_id = df["index"].to_numpy().astype(np.int64)
        pos = np.arange(n)
        self.may = pos >= self.n_dev
        self.val = (pos >= n_train) & ~self.may
        train_users = np.unique(uid[:n_train])
        dev_users = np.unique(uid[:self.n_dev])
        # cold users: dev_val rows -> no dev_train row; May rows -> no row before 1 May
        self.cold = (self.val & ~np.isin(uid, train_users)) | (self.may & ~np.isin(uid, dev_users))
        self.val_a = self.val & (self.t < P3B.VAL_B_START)
        self.val_b = self.val & (self.t >= P3B.VAL_B_START)
        self.halves = OrderedDict([("val_a", self.val_a), ("val_b", self.val_b)])
        if not dev_only:
            assert int(self.t[self.n_dev]) >= MAY_START and int(self.t[self.n_dev - 1]) < MAY_START
            self.halves["may"] = self.may
        self.base = {h: float(self.truth[m].mean()) for h, m in self.halves.items()}
        self.day = self.t // 86400
        # new / returning attackers: val rows against dev_train, May rows against all of dev
        att_train = np.zeros(self.n_ip, bool)
        att_train[self.ip[:n_train][self.truth[:n_train]]] = True
        att_dev = np.zeros(self.n_ip, bool)
        att_dev[self.ip[:self.n_dev][self.truth[:self.n_dev]]] = True
        self.att_train, self.att_dev = att_train, att_dev
        returning = np.where(self.may, att_dev[self.ip], att_train[self.ip])
        self.returning = returning
        self.strata = OrderedDict([("all", np.ones(n, bool)), ("excl_placeholder", ~self.unknown),
                                   ("cold_users", self.cold), ("new_attackers", ~returning),
                                   ("returning_attackers", returning)])


def asn_ratio(S):
    """agents.triage.AsnReputation for every event: prior failure share of
    the event's ASN over every earlier event (0.0 for an ASN's first)."""
    g = pd.Series(S.failed.astype(np.int64)).groupby(S.asn, sort=False)
    n_prev = g.cumcount().to_numpy()
    f_prev = (g.cumsum() - S.failed.astype(np.int64)).to_numpy()
    out = np.zeros(S.n, np.float64)
    nz = n_prev > 0
    out[nz] = f_prev[nz] / n_prev[nz]
    return out


def rule_alerts(S, clk):
    """The eight frozen rule detectors at their config.V3_* settings (the
    amendment 3 choice), as alert positions: phase3b's computation at one
    grid point per detector."""
    out = OrderedDict()
    pair = S.user * S.n_ip + S.ip
    t = time.time()
    rf = np.flatnonzero(S.real_fail)
    kd = Keyed(S, rf, S.ip)
    bf, _ = kd.count_since(config.V3_BF_WINDOW_SECONDS)
    m = rf[bf >= config.V3_BF_MIN_FAILURES]
    out[R.BF] = Detector(R.BF, {}, m, S.ip[m], S)
    c, lf = kd.count_since(config.V3_SLOW_BF_WINDOW_SECONDS)
    sp = kd.spread(lf)
    m = rf[(bf < config.V3_BF_MIN_FAILURES) & (c >= config.V3_SLOW_BF_MIN_FAILURES)
           & (sp >= config.V3_SLOW_BF_MIN_SPREAD_SECONDS)]
    out[R.SLOW] = Detector(R.SLOW, {}, m, S.ip[m], S)
    dc = distinct_counts(S, rf, S.ip, S.user, [config.V3_CS_WINDOW_SECONDS])[config.V3_CS_WINDOW_SECONDS]
    m = rf[dc >= config.V3_CS_MIN_ACCOUNTS]
    out[R.CS] = Detector(R.CS, {}, m, S.ip[m], S)
    ua = np.flatnonzero(S.unknown)
    c, _ = Keyed(S, ua, S.ip).count_since(config.V3_INVALID_WINDOW_SECONDS)
    m = ua[c >= config.V3_INVALID_MIN_ATTEMPTS]
    out[R.INVALID] = Detector(R.INVALID, {}, m, S.ip[m], S)
    dc = distinct_counts(S, rf, S.user, S.ip, [config.V3_DIST_WINDOW_SECONDS])[config.V3_DIST_WINDOW_SECONDS]
    m = rf[dc >= config.V3_DIST_MIN_IPS]
    out[R.DIST] = Detector(R.DIST, {}, m, pair[m], S)
    W, N = config.V3_SAF_WINDOW_SECONDS, config.V3_SAF_MIN_FAILURES
    spos, acc = failures_before(S, S.user, W)
    spos2, ipc = failures_before(S, S.ip, W)
    assert np.array_equal(spos, spos2)
    m = spos[(acc >= N) | (ipc >= N)]
    out[R.SAF] = Detector(R.SAF, {}, m, pair[m], S)
    mp, base, ex = multi_ip_stats(S)
    hit = base.copy()
    for e in config.V3_MULTI_IP_EXEMPT:
        hit &= ~ex[e]
    m = mp[hit]
    out[R.MULTI] = Detector(R.MULTI, {}, m, pair[m], S)
    lo, hi = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
    m = np.flatnonzero(S.success & (S.hour >= lo) & (S.hour <= hi))
    out[R.OFF_HOURS] = Detector(R.OFF_HOURS, {}, m, S.ip[m], S, cooldown=config.V3_DEDUP_SECONDS[R.OFF_HOURS])
    clk.tick("frozen rule alerts (8 detectors)", t)
    return {d: det.alert_pos for d, det in out.items()}


def build(dev_only=False, clk=None):
    """Stream6 with everything P5 / P5B need (the P5.stream() fields)."""
    clk = clk or Clock()
    t = time.time()
    S = Stream6(dev_only)
    clk.tick("stream (dev" + ("" if dev_only else " + May cache") + ")", t)
    S.key = S.ip * P5.SHIFT + S.day
    t = time.time()
    S.asn_ratio = asn_ratio(S)
    df = pd.DataFrame({"k": S.key, "f": S.failed.astype(np.int64), "s": S.success.astype(np.int64),
                       "p": S.unknown.astype(np.int64), "a": S.asn_ratio})
    g = df.groupby("k", sort=False)
    S.c_failed = g["f"].cumsum().to_numpy()
    S.c_success = g["s"].cumsum().to_numpy()
    S.c_placeholder = g["p"].cummax().to_numpy()
    S.c_asn_max = g["a"].cummax().to_numpy()
    clk.tick("ASN ratio and per-IP daily counters", t)
    S.rule_alerts = rule_alerts(S, clk)
    DETS = P5.DETS
    pos = np.concatenate([S.rule_alerts[d] for d in DETS])
    bit = np.concatenate([np.full(len(S.rule_alerts[d]), j, np.int64) for j, d in enumerate(DETS)])
    up, inv = np.unique(pos, return_inverse=True)
    mask = np.zeros(len(up), np.int64)
    np.bitwise_or.at(mask, inv, np.int64(1) << bit)
    S.a_pos, S.a_mask, S.a_cnt = up, mask, np.bincount(inv).astype(np.int64)
    return S


def rates():
    return {t: int(config.RESPONSE_TIER_RATES.get(t) or 0) for t in TR.RATED_TIERS}


def twin(S, clk):
    t = time.time()
    C = P5.Causal(S, config.TRIAGE_SCORE, None)
    D = P5B.run(S, C, rates(), tuple(config.RESPONSE_FLOOR_DETECTORS))
    clk.tick("offline twin: running T2 scores, capped tiers with the floor, emails", t)
    return C, D


# ── Stage: twin ──────────────────────────────────────────────────────────────

def stage_twin(args):
    clk = Clock()
    S = build(args.dev_only, clk)
    C, D = twin(S, clk)
    I = D["I"]
    check = OrderedDict()
    n_dev = S.n_dev
    # dev part against the Phase 3b frozen alerts and the Phase 5c deployed run
    z = np.load(os.path.join(P3B.CACHE, "chosen_rules.npz"))
    check["rule_alerts_dev_equal_phase3b"] = {
        d: bool(np.array_equal(S.rule_alerts[d][S.rule_alerts[d] < n_dev], z[f"alert::{d}"]))
        for d in P5.DETS}
    a5 = np.load(os.path.join(P5.CACHE, "asn_ratio.npy"))
    check["asn_ratio_dev_equal_phase5"] = bool(np.array_equal(S.asn_ratio[:n_dev], a5))
    zc = np.load(os.path.join(RESULTS, "phase5c_cache", "deployed.npz"))
    dev_ev = I.p < n_dev
    check["deployed_dev_equal_phase5c"] = {
        "alerted_positions": bool(np.array_equal(I.p[dev_ev], zc["p"])),
        "tiers": bool(np.array_equal(D["tier_ev"][dev_ev], zc["tier_ev"])),
        "scores": bool(all(np.array_equal(D["C"].run[j][dev_ev], zc[f"score{j}"]) for j in range(2))),
        "blocked": bool(np.array_equal(D["blocked"][:n_dev], zc["blocked"])),
        "challenged": bool(np.array_equal(D["challenged"][:n_dev], zc["challenged"]))}
    with open(os.path.join(RESULTS, "phase5c_cache", "email_log.json")) as f:
        em5 = json.load(f)
    dev_hours_end = MAY_START // 3600
    norm = lambda log: [(k, int(h), tuple(ids), o) for k, h, ids, o in log]   # noqa: E731
    got = [x for x in norm(D["email_log"]) if x[1] < dev_hours_end]
    exp = norm(em5["log"])
    # the dev-only run flushes the last digest at the end; compare complete hours
    last = min(max((x[1] for x in got), default=0), max((x[1] for x in exp), default=0))
    check["email_log_dev_equal_phase5c"] = bool([x for x in got if x[1] < last] == [x for x in exp if x[1] < last])
    ok = (all(check["rule_alerts_dev_equal_phase3b"].values()) and check["asn_ratio_dev_equal_phase5"]
          and all(check["deployed_dev_equal_phase5c"].values()) and check["email_log_dev_equal_phase5c"])
    check["ok"] = bool(ok)
    sfx = "" if not args.dev_only else "_devcheck"
    np.savez_compressed(cpath(f"deployed{sfx}.npz"), p=I.p, tier_ev=D["tier_ev"], prev_ev=D["prev_ev"],
                        blocked=D["blocked"], challenged=D["challenged"],
                        **{f"score{j}": c for j, c in enumerate(D["C"].run)},
                        **{f"alert::{d}": S.rule_alerts[d] for d in P5.DETS})
    with open(cpath(f"email_log{sfx}.json"), "w") as f:
        json.dump({"log": D["email_log"], "outcome": {str(k): v for k, v in D["email_outcome"].items()}}, f)
    check["events"] = int(S.n)
    check["events_may"] = int(S.may.sum())
    check["timings_seconds"] = clk.total()
    print(json.dumps(check, indent=1))
    save_json("phase6_twin_check.json" if not args.dev_only else "phase6_twin_check_devonly.json", check)
    return 0 if ok else 1


# ── Stage: replay (real agents, S5 timers) ───────────────────────────────────

def events(S):
    """Event dicts for the real agents over dev + May, as eval/phase4.events."""
    parts = _frames(P4.EXTRA, dev_only=not S.may.any())
    cols = {}
    for name in P4.EXTRA[1:]:
        vals = []
        for df in parts:
            s = df[name]
            if hasattr(s, "cat"):
                names = s.cat.categories.astype(str).to_numpy(dtype=object)
                codes = s.cat.codes.to_numpy()
                vals += np.where(codes < 0, None, names[np.maximum(codes, 0)]).tolist()
            else:
                vals += s.astype(object).where(s.notna(), None).tolist()
        cols[name] = vals
    ids = np.concatenate([df["index"].to_numpy() for df in parts])
    assert np.array_equal(ids, S.event_id), "extra columns out of step"
    del parts
    region, ua = cols["Region"], cols["User Agent String"]
    browser, os_ = cols["Browser Name and Version"], cols["OS Name and Version"]
    rtt = cols["Round-Trip Time [ms]"]
    stamps = S.timestamps()
    users = [str(u) for u in S.user_ids]
    countries = S.df["Country"].astype(str).replace("", "XX").to_numpy(dtype=object)
    devices = S.df["Device Type"].astype(str).replace("", "Unknown").to_numpy(dtype=object)
    status = ["SUCCESS" if ok else "FAILED" for ok in S.success.tolist()]
    asn = S.asn.tolist()
    ipn, ipc, uc = S.ip_names, S.ip.tolist(), S.user.tolist()
    eid = S.event_id.tolist()
    for i in range(S.n):
        yield {"timestamp": stamps[i], "user": users[uc[i]], "ip": ipn[ipc[i]], "status": status[i],
               "country": countries[i], "device_type": devices[i], "asn": asn[i],
               "region": region[i], "user_agent": ua[i], "browser": browser[i], "os": os_[i],
               "rtt": rtt[i], "event_id": eid[i]}


class _Timer:
    """Accumulates wall time of wrapped bound methods into named buckets."""

    def __init__(self):
        self.acc = Counter()
        self.calls = Counter()

    def wrap(self, obj, method, bucket):
        f = getattr(obj, method)
        acc, calls, pc = self.acc, self.calls, time.perf_counter

        def timed(*a, **k):
            t = pc()
            try:
                return f(*a, **k)
            finally:
                acc[bucket] += pc() - t
                calls[bucket] += 1
        setattr(obj, method, timed)


def stage_replay(args):
    from agents.monitoring_agent import MonitoringAgent
    from agents.response_agent import ResponseAgent
    from eval.phase5_ops import RecordingAlerter, ReplayStore
    assert (config.RULES_MODE, config.ML_MODE, config.ML_V4_IFOREST) == ("v3", "v4", "retired")
    clk = Clock()
    t = time.time()
    S = Stream6(args.dev_only)
    sfx = "" if not args.dev_only else "_devcheck"
    z = np.load(cpath(f"deployed{sfx}.npz"))
    with open(cpath(f"email_log{sfx}.json")) as f:
        em = json.load(f)
    n = args.limit or S.n
    clk.tick("stream and the offline twin", t)

    store = ReplayStore(args.day, cpath(f"store_day{sfx}.db"), cpath(f"store_day{sfx}.jsonl"))
    responder = ResponseAgent(email_alerter=RecordingAlerter(), email_log_max=None)
    mon = MonitoringAgent(alert_manager=store, responder=responder)
    assert mon.detector.anomaly_detector is None
    status_untimed = responder.status
    tm = _Timer()
    tm.wrap(mon.detector, "analyze", "rules")
    for m in ("status", "observe", "assess", "decide", "take_action"):
        tm.wrap(responder, m, "triage_response")
    tm.wrap(mon.analyzer, "evaluate_alert", "analysis")
    tm.wrap(store, "save_alert", "store_record")
    got_blocked = np.zeros(n, bool)
    got_challenged = np.zeros(n, bool)
    per_event = np.zeros(n, np.float32)
    pc = time.perf_counter
    t = time.time()
    may_snap = None
    for i, e in enumerate(events(S)):
        if i >= n:
            break
        if i == S.n_dev:
            may_snap = (Counter(tm.acc), Counter(tm.calls))
        st = status_untimed(e)            # state before the event (not timed)
        got_blocked[i], got_challenged[i] = st["blocked"], st["challenged"]
        store.i = i
        t0 = pc()
        mon._process_event(e)
        per_event[i] = pc() - t0
    responder.flush()
    t_replay = time.time() - t
    store.close()
    clk.tick(f"real agents, frozen defaults ({n:,} events)", t)

    # ── comparison with the twin ────────────────────────────────────────
    t = time.time()
    spans = OrderedDict([("dev_train", np.arange(S.n) < S.n_train), ("val_a", S.val_a),
                         ("val_b", S.val_b), ("may", S.may)])
    if args.dev_only:
        spans.pop("may")
    spans = {k: m[:n] for k, m in spans.items()}
    rows = store.rows
    pos = np.array([r[0] for r in rows], np.int64)
    typ = [r[1] for r in rows]
    check, ok = {"detectors": {}}, True
    for d in R.RULE_DETECTORS:
        exp = np.zeros(n, bool)
        p = z[f"alert::{d}"]
        exp[p[p < n]] = True
        got = np.zeros(n, bool)
        got[pos[[x == d for x in typ]]] = True
        check["detectors"][d] = {s: int((exp != got)[m].sum()) for s, m in spans.items()}
        ok &= all(v == 0 for v in check["detectors"][d].values())
    ml_alerts = sum(x == R.ML for x in typ)
    ok &= ml_alerts == 0
    p_off, tier_off = z["p"], z["tier_ev"]
    run = [z["score0"], z["score1"]]
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

    # ── S5: per-stage latency on May events ─────────────────────────────
    s5 = {}
    if may_snap is not None:
        acc0, calls0 = may_snap
        n_may = int(n - S.n_dev)
        s5 = {"may_events": n_may,
              "us_per_event": {b: round(1e6 * (tm.acc[b] - acc0[b]) / n_may, 2) for b in tm.acc},
              "calls_in_may": {b: int(tm.calls[b] - calls0[b]) for b in tm.calls},
              "total_us_per_event_mean": round(1e6 * float(per_event[S.n_dev:n].mean()), 2),
              "total_us_per_event_p50": round(1e6 * float(np.median(per_event[S.n_dev:n])), 2),
              "total_us_per_event_p99": round(1e6 * float(np.percentile(per_event[S.n_dev:n], 99)), 2),
              "note": "the timers' own overhead is inside each bucket; 'total' is the whole "
                      "MonitoringAgent._process_event call"}
        ins = np.array(store.insert_s)
        s5["store_sqlite_insert_per_alert_ms"] = {
            "day": args.day, "alerts": int(len(ins)),
            "mean": round(1e3 * float(ins.mean()), 3) if len(ins) else None,
            "p50": round(1e3 * float(np.median(ins)), 3) if len(ins) else None,
            "p99": round(1e3 * float(np.percentile(ins, 99)), 3) if len(ins) else None}
    out = {"equivalent": bool(ok), "events": int(n), "events_may": int(max(0, n - S.n_dev)),
           "limit": int(args.limit),
           "defaults": {"RULES_MODE": config.RULES_MODE, "ML_MODE": config.ML_MODE,
                        "ML_V4_IFOREST": config.ML_V4_IFOREST, "TRIAGE_SCORE": config.TRIAGE_SCORE,
                        "RESPONSE_TIER_RATES": config.RESPONSE_TIER_RATES,
                        "RESPONSE_FLOOR_DETECTORS": list(config.RESPONSE_FLOOR_DETECTORS)},
           "alerts_saved": len(rows), "ml_alerts": int(ml_alerts),
           "detector_alert_mismatches": check["detectors"],
           "alerted_events_compared": len(seen), "alerted_events_missing": int(missing),
           "tier_mismatches": int(tier_mm), "score_mismatches": int(score_mm),
           "tier_or_score_mismatches_by_span": dict(by_span),
           "blocked_state_mismatches": blk_mm, "challenged_state_mismatches": chl_mm,
           "email_log_mismatches": int(email_mm), "incident_email_outcome_mismatches": int(out_mm),
           "email_log_entries": len(responder.notifier.log),
           "blocked_source_events": mon.blocked_source_events,
           "challenged_source_events": mon.challenged_source_events,
           "duplicate_events": mon.duplicate_events,
           "state_sizes_end": {"rules": mon.detector.state_sizes(), "triage": responder.triage.state_sizes()},
           "S5": s5, "replay_seconds": round(t_replay, 1),
           "replay_us_per_event": round(1e6 * t_replay / n, 1),
           "peak_rss_mb": P4.peak_rss_mb(), "timings_seconds": clk.total()}
    name = "phase6_replay_check.json" if not args.limit else "phase6_replay_smoke.json"
    if args.dev_only:
        name = name.replace(".json", "_devcheck.json")
    save_json(name, out)
    print(json.dumps(out, indent=1))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["cache", "twin", "replay", "primary"])
    ap.add_argument("--dev-only", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--day", default=STORE_DAY)
    args = ap.parse_args()
    if args.stage == "primary":
        from eval import phase6_primary
        return phase6_primary.main(args) or 0
    return {"cache": stage_cache, "twin": stage_twin, "replay": stage_replay}[args.stage](args) or 0


if __name__ == "__main__":
    sys.exit(main())
