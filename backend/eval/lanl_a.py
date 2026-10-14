# backend/eval/lanl_a.py
"""
LANL phase L2, LA3.4 (A): the frozen v3 rules, triage, step-up response and
email on the full, unfiltered dev auth stream, as an offline twin processed
one day at a time with causal state carried across days, checked against the
real agents (frozen defaults) on one day.

Mapping (LA3.4): ip = src_computer; user = src_user; status SUCCESS for
"Success", FAILED for "Fail"; ASN one constant (CONST_ASN); country, region,
user agent, browser, OS, device type and RTT constants. Event time
T = BASE + (time - 1), BASE = 2000-01-01 00:00:00, so the frozen code's
day (T // 86400) is the LANL day index plus BASE // 86400 and its clock hour
is the LA3.4 offset hour. Every event carries event_id = its global stream
position, so the frozen duplicate check (rules_v3._is_duplicate) never drops
a row (without ids it would collapse rows with the same second, computer,
account and status; results/lanl_l2_checks.json).

Stages (run from backend/):
  python -m eval.lanl_a twin [--days 0-13] [--fresh] [--tag NAME]
        the twin; per-day arrays to <work>/a_<tag>/day=DD.npz
  python -m eval.lanl_a replay --day 8 [--limit N]
        the real agents from empty state on one day, against a fresh twin run
        of the same day (twin --days 8 --fresh --tag fresh8)
  python -m eval.lanl_a metrics
        LA3.6 A metrics for dev_train, val_a, val_b from the causal run
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, OrderedDict

import numpy as np
import pandas as pd
import pyarrow.compute as pc

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from agents import rules_v3 as R  # noqa: E402
from agents import triage as TR  # noqa: E402
from agents.rules_v3 import normalize_account  # noqa: E402
from eval import lanl_la3 as L  # noqa: E402
from eval.lanl_convert import peak_working_set  # noqa: E402

BASE = 946684800                      # 2000-01-01 00:00:00, a multiple of 86400
BASE_DAY = BASE // 86400
CONST = "LANL"
CONST_ASN = 0
DETS = R.RULE_DETECTORS
BIT = {d: j for j, d in enumerate(DETS)}
PREC = [float(config.TRIAGE_DETECTOR_PRECISION[d]) for d in DETS]
COLS = ["time", "src_user", "src_computer", "dst_computer", "success"]
PAIR = 1 << 20                         # pair key = account * PAIR + ip


def adir(tag):
    d = L.wpath(f"a_{tag}")
    os.makedirs(d, exist_ok=True)
    return d


def ts_strings(T):
    return [s.replace("T", " ") for s in np.datetime_as_string(T.astype("datetime64[s]"), unit="s")]


class Codes:
    """Persistent string -> int codes."""

    def __init__(self, norm=None):
        self.d, self.names, self.norm = {}, [], norm

    def encode(self, col):
        enc = pc.dictionary_encode(col).combine_chunks()
        idx = enc.indices.to_numpy(zero_copy_only=False)
        out = np.empty(len(enc.dictionary), np.int64)
        for j, s in enumerate(enc.dictionary.to_pylist()):
            k = self.norm(s) if self.norm else s
            c = self.d.get(k)
            if c is None:
                c = self.d[k] = len(self.names)
                self.names.append(k)
            out[j] = c
        return out[idx]


class Twin:
    """The frozen pipeline's state, carried from day to day."""

    def __init__(self):
        c = config
        self.ipc = Codes(lambda s: str(s).strip())
        self.accc = Codes(normalize_account)
        self.unknown = frozenset(normalize_account(u) for u in c.UNKNOWN_ACCOUNT_IDS)
        # failure-driven detectors (rules_v3 windows, keyed by codes)
        self.w_bf, self.n_bf = c.V3_BF_WINDOW_SECONDS, c.V3_BF_MIN_FAILURES
        self.w_slow, self.n_slow = c.V3_SLOW_BF_WINDOW_SECONDS, c.V3_SLOW_BF_MIN_FAILURES
        self.slow_spread = c.V3_SLOW_BF_MIN_SPREAD_SECONDS
        self.w_cs, self.n_cs = c.V3_CS_WINDOW_SECONDS, c.V3_CS_MIN_ACCOUNTS
        self.w_dist, self.n_dist = c.V3_DIST_WINDOW_SECONDS, c.V3_DIST_MIN_IPS
        self.w_saf, self.n_saf = c.V3_SAF_WINDOW_SECONDS, c.V3_SAF_MIN_FAILURES
        self.w_multi, self.known_ttl = c.V3_MULTI_IP_WINDOW_SECONDS, c.V3_KNOWN_IP_TTL_SECONDS
        assert tuple(c.V3_MULTI_IP_EXEMPT) == ("known_ip",), c.V3_MULTI_IP_EXEMPT
        self.w_ip_fail = max(self.w_bf, self.w_slow, self.w_saf)
        self.ipfail, self.ipaccts, self.accfail, self.accips = {}, {}, {}, {}
        self.dedup = dict(c.V3_DEDUP_SECONDS)
        self.last_fire = {d: {} for d in DETS}
        # SAF failure history (time, pos, ip, account) inside the window
        self.fh = (np.zeros(0, np.int64),) * 4
        # Multiple IP Login: last SUCCESS per account; last SUCCESS per (account, ip)
        self.last_ip = np.full(0, -1, np.int64)
        self.last_t = np.full(0, -1, np.int64)
        self.pair_k = np.zeros(0, np.int64)
        self.pair_t = np.zeros(0, np.int64)
        # triage
        self.n_before = 0
        self.f_before = 0
        self.rates = {t: int(c.RESPONSE_TIER_RATES.get(t) or 0) for t in TR.RATED_TIERS}
        self.floor = 0
        for x in c.RESPONSE_FLOOR_DETECTORS:
            self.floor |= 1 << BIT[x]
        self.cutoffs = {t: TR.NONE for t in TR.RATED_TIERS}
        self.day = None
        self.incidents = {}
        self.admitted = {t: 0 for t in TR.RATED_TIERS}
        self.chal_exp = {}                    # ip code -> challenge expiry (T)
        self.block_exp = {}
        self.notifier = TR.IncidentNotifier(_Rec())
        self.n_events = 0

    # ── one day ──────────────────────────────────────────────────────────

    def day_pass(self, d, offset, clk):
        t_start = time.perf_counter()
        tbl = L.day_table(d, COLS)
        n = tbl.num_rows
        t = tbl.column("time").to_numpy().astype(np.int64)
        T = BASE + t - 1
        ip = self.ipc.encode(tbl.column("src_computer"))
        acc = self.accc.encode(tbl.column("src_user"))
        succ_s = tbl.column("success")
        succ = pc.equal(succ_s, "Success").to_numpy(zero_copy_only=False)
        fail = pc.equal(succ_s, "Fail").to_numpy(zero_copy_only=False)
        assert (succ | fail).all(), "success field outside {Success, Fail}"
        unk_codes = np.array([x in self.unknown for x in self.accc.names], bool)
        unknown = unk_codes[acc]
        assert not unknown.any(), "unknown-account rows are not handled by this twin"
        pos = offset + np.arange(n, dtype=np.int64)
        self._grow(len(self.accc.names))
        clk["load_encode"] += time.perf_counter() - t_start

        hits = {}
        t1 = time.perf_counter()
        hits.update(self._failure_detectors(np.flatnonzero(fail), T, ip, acc))
        clk["failure_detectors"] += time.perf_counter() - t1
        t1 = time.perf_counter()
        si = np.flatnonzero(succ)
        hits[R.SAF] = self._saf(si, fail, T, ip, acc, pos)
        clk["saf"] += time.perf_counter() - t1
        t1 = time.perf_counter()
        hits[R.MULTI] = self._multi(si, T, ip, acc)
        clk["multi"] += time.perf_counter() - t1
        hour = L.offset_hour(t)
        lo, hi = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
        off = si[(hour[si] >= lo) & (hour[si] <= hi)]
        hits[R.OFF_HOURS] = (off, ip[off])
        hits.setdefault(R.INVALID, (np.zeros(0, np.int64), np.zeros(0, np.int64)))

        t1 = time.perf_counter()
        alerts = {}
        for dname in DETS:
            m, key = hits[dname]
            alerts[dname] = self._emit(dname, m, key, T)
        clk["emit"] += time.perf_counter() - t1

        t1 = time.perf_counter()
        res = self._triage(alerts, n, T, ip, fail, d)
        clk["triage_response"] += time.perf_counter() - t1
        self.n_events += n
        out = {"pos0": offset, "n": n}   # positions below are local to the day (0..n-1)
        for dname in DETS:
            out[f"alert::{dname}"] = alerts[dname]
        out.update(res)
        return out

    def _grow(self, n_acc):
        k = n_acc - len(self.last_ip)
        if k > 0:
            self.last_ip = np.concatenate([self.last_ip, np.full(k, -1, np.int64)])
            self.last_t = np.concatenate([self.last_t, np.full(k, -1, np.int64)])

    def _failure_detectors(self, fi, T, ip, acc):
        out = {x: ([], []) for x in (R.BF, R.SLOW, R.CS, R.DIST)}
        for j, tt, a, b in zip(fi.tolist(), T[fi].tolist(), ip[fi].tolist(), acc[fi].tolist()):
            fw = self.ipfail.get(a)
            if fw is None:
                fw = self.ipfail[a] = R.Window()
                self.ipaccts[a] = R.Window(distinct=True)
            accts = self.ipaccts[a]
            fw.add(tt)
            fw.prune(fw.last() - self.w_ip_fail)
            accts.add(tt, b)
            accts.prune(accts.last() - self.w_cs)
            anchor = fw.last()
            n_bf = fw.count_since(anchor - self.w_bf)
            if n_bf >= self.n_bf:
                out[R.BF][0].append(j); out[R.BF][1].append(a)
            else:
                n_slow = fw.count_since(anchor - self.w_slow)
                if n_slow >= self.n_slow:
                    spread = anchor - fw.first_since(anchor - self.w_slow)
                    if spread >= self.slow_spread:
                        out[R.SLOW][0].append(j); out[R.SLOW][1].append(a)
            if accts.distinct() >= self.n_cs:
                out[R.CS][0].append(j); out[R.CS][1].append(a)
            af = self.accfail.get(b)
            if af is None:
                af = self.accfail[b] = R.Window()
                self.accips[b] = R.Window(distinct=True)
            ai = self.accips[b]
            af.add(tt)
            af.prune(af.last() - self.w_saf)
            ai.add(tt, a)
            ai.prune(ai.last() - self.w_dist)
            if ai.distinct() >= self.n_dist:
                out[R.DIST][0].append(j); out[R.DIST][1].append(b * PAIR + a)
        return {k: (np.array(v[0], np.int64), np.array(v[1], np.int64)) for k, v in out.items()}

    def _saf(self, si, fail, T, ip, acc, pos):
        fi = np.flatnonzero(fail)
        ht, hp, hip, hacc = self.fh
        at = np.concatenate([ht, T[fi]])
        ap = np.concatenate([hp, pos[fi]])
        aip = np.concatenate([hip, ip[fi]])
        aacc = np.concatenate([hacc, acc[fi]])
        st, sp = T[si], pos[si]
        lo_t = np.maximum(st - self.w_saf, 0) - BASE + 1   # window start, as an offset >= 0
        counts = []
        for key_all, key_s in ((aacc, acc[si]), (aip, ip[si])):
            o = np.lexsort((ap, key_all))
            k = key_all[o]
            cp = (k << 32) | ap[o]
            ct = (k << 32) | (at[o] - BASE + 1)
            c = (np.searchsorted(cp, (key_s << 32) | sp, "left")
                 - np.searchsorted(ct, (key_s << 32) | np.maximum(lo_t, 0), "left"))
            counts.append(c)
        n_acc, n_ip = counts
        m = (n_acc >= self.n_saf) | (n_ip >= self.n_saf)
        # keep the failures that can still fall inside a later day's window
        keep_from = T[-1] - self.w_saf if len(T) else 0
        k = at >= keep_from - 86400
        self.fh = (at[k], ap[k], aip[k], aacc[k])
        mm = si[m]
        return mm, acc[mm] * PAIR + ip[mm]

    def _multi(self, si, T, ip, acc):
        a, i, tt = acc[si], ip[si], T[si]
        n = len(si)
        if n == 0:
            return np.zeros(0, np.int64), np.zeros(0, np.int64)
        o = np.argsort(a, kind="stable")
        ao, io, to = a[o], i[o], tt[o]
        first = np.ones(n, bool)
        first[1:] = ao[1:] != ao[:-1]
        prev_ip = np.empty(n, np.int64)
        prev_t = np.empty(n, np.int64)
        prev_ip[1:], prev_t[1:] = io[:-1], to[:-1]
        prev_ip[first], prev_t[first] = self.last_ip[ao[first]], self.last_t[ao[first]]
        last = np.ones(n, bool)
        last[:-1] = ao[1:] != ao[:-1]
        self.last_ip[ao[last]], self.last_t[ao[last]] = io[last], to[last]
        pk = ao * PAIR + io
        o2 = np.argsort(pk, kind="stable")
        pko, to2 = pk[o2], to[o2]
        f2 = np.ones(n, bool)
        f2[1:] = pko[1:] != pko[:-1]
        prev_pair = np.empty(n, np.int64)
        prev_pair[1:] = to2[:-1]
        if len(self.pair_k):
            j = np.minimum(np.searchsorted(self.pair_k, pko[f2]), len(self.pair_k) - 1)
            found = self.pair_k[j] == pko[f2]
            prev_pair[f2] = np.where(found, self.pair_t[j], -1)
        else:
            prev_pair[f2] = -1
        l2 = np.ones(n, bool)
        l2[:-1] = pko[1:] != pko[:-1]
        # carry the latest SUCCESS per pair
        nk, nt = pko[l2], to2[l2]
        allk = np.concatenate([self.pair_k, nk])
        allt = np.concatenate([self.pair_t, nt])
        oo = np.lexsort((allt, allk))
        allk, allt = allk[oo], allt[oo]
        keep = np.ones(len(allk), bool)
        keep[:-1] = allk[1:] != allk[:-1]
        self.pair_k, self.pair_t = allk[keep], allt[keep]
        # back to the account-sorted order (o2 permutes the account-sorted arrays)
        pp = np.empty(n, np.int64)
        pp[o2] = prev_pair
        known = (pp >= 0) & (pp >= to - self.known_ttl)
        hit = (prev_t >= 0) & (io != prev_ip) & (np.abs(to - prev_t) < self.w_multi) & ~known
        mpos = np.sort(si[o][hit])
        return mpos, acc[mpos] * PAIR + ip[mpos]

    def _emit(self, dname, m, key, T):
        cd = self.dedup.get(dname, self.dedup["default"])
        last = self.last_fire[dname]
        keep = []
        for j, k, tt in zip(m.tolist(), key.tolist(), T[m].tolist()):
            lt = last.get(k)
            if lt is None or tt - lt > cd:
                last[k] = tt
                keep.append(j)
        return np.array(keep, np.int64)

    def _close_day(self):
        finals = sorted((inc[2] for inc in self.incidents.values()), reverse=True)
        if finals:
            for tier, k in self.rates.items():
                if k:
                    self.cutoffs[tier] = finals[k - 1] if len(finals) >= k else TR.ALL
        self.incidents = {}
        self.admitted = {t: 0 for t in TR.RATED_TIERS}

    def _qual(self, score, tier):
        c = self.cutoffs[tier]
        return c == TR.ALL or (c != TR.NONE and score >= c)

    def _triage(self, alerts, n, T, ip, fail, d):
        tday = BASE_DAY + d
        if self.day is not None and tday > self.day:
            self._close_day()
        self.day = tday
        # global prior failure share (constant ASN), then its running max per IP today
        nb = self.n_before + np.arange(n, dtype=np.int64)
        fb = self.f_before + np.cumsum(fail, dtype=np.int64) - fail
        ratio = np.zeros(n)
        nz = nb > 0
        ratio[nz] = fb[nz] / nb[nz]
        self.n_before += n
        self.f_before += int(fail.sum())
        amax = pd.Series(ratio).groupby(ip, sort=False).cummax().to_numpy()
        amax = np.maximum(amax, 0.0)
        # alerted events
        pos_l = [alerts[x] for x in DETS]
        allp = np.concatenate(pos_l)
        bits = np.concatenate([np.full(len(p), 1 << j, np.int64) for j, p in enumerate(pos_l)])
        up, inv = np.unique(allp, return_inverse=True)
        mask = np.zeros(len(up), np.int64)
        np.bitwise_or.at(mask, inv, bits)
        tier_ev = np.full(len(up), 3, np.int8)
        prev_ev = np.full(len(up), 3, np.int8)
        s0 = np.zeros(len(up))
        s1 = np.zeros(len(up))
        email = {}
        ips_names = self.ipc.names
        TI = {x: i for i, x in enumerate(TR.TIERS)}
        place = np.zeros(n, bool)
        for j, (p, mk) in enumerate(zip(up.tolist(), mask.tolist())):
            a = int(ip[p])
            inc = self.incidents.get(a)
            if inc is None:
                inc = self.incidents[a] = [0, 0, None, set(), "log"]
            inc[0] |= mk
            m_ = inc[0]
            top = max(PREC[b] for b in range(len(DETS)) if m_ >> b & 1)
            score = (top, float(amax[p]))
            inc[2] = score
            before = inc[4]
            regions = inc[3]
            if not self.floor or m_ & self.floor:
                for tier in TR.RATED_TIERS:
                    if tier in regions:
                        break
                    k = self.rates[tier]
                    if k and self.admitted[tier] < k and self._qual(score, tier):
                        regions.add(tier)
                        self.admitted[tier] += 1
                        break
            inc[4] = next((x for x in TR.RATED_TIERS if x in regions), "log")
            tier_ev[j], prev_ev[j] = TI[inc[4]], TI[before]
            s0[j], s1[j] = score
            tt = int(T[p])
            if inc[4] == "block":
                self.block_exp[a] = max(self.block_exp.get(a, 0), tt + config.BLOCK_TTL_SECONDS)
            elif inc[4] == "step_up":
                place[p] = True
            incd = {"incident_id": f"{ips_names[a]}|{tday}", "ip": ips_names[a],
                    "tier": inc[4], "previous_tier": before}
            if self.notifier.wants(incd):
                email[p] = self.notifier.notify(incd, tt)
        # challenged before each event: the latest earlier placement on the IP
        pt = np.where(place, T, -1).astype(np.int64)
        prior = pd.Series(np.where(place, pt, np.nan)).groupby(ip, sort=False).shift(1)
        prior = prior.groupby(ip, sort=False).ffill().to_numpy()
        carried = np.array([self.chal_exp.get(int(a), -1) for a in range(len(ips_names))], np.int64)
        exp_prev = carried[ip]
        last_today = np.where(np.isnan(prior), -1, prior + config.STEP_UP_TTL_SECONDS).astype(np.int64)
        challenged = T < np.maximum(exp_prev, last_today)
        for a, tt in zip(ip[place].tolist(), T[place].tolist()):
            self.chal_exp[a] = max(self.chal_exp.get(a, -1), tt + config.STEP_UP_TTL_SECONDS)
        assert not self.block_exp, "block tier is off (rate 0)"
        return {"a_pos": up, "a_mask": mask, "tier_ev": tier_ev, "prev_ev": prev_ev,
                "score0": s0, "score1": s1, "challenged": challenged,
                "email_pos": np.array(sorted(email), np.int64),
                "email_out": np.array([email[k] for k in sorted(email)], dtype="U12")}


class _Rec:
    enabled = True

    def send_incident(self, incident):
        return True

    def send_digest(self, hour, incidents):
        return True


def parse_days(s):
    a, _, b = s.partition("-")
    return list(range(int(a), int(b or a) + 1))


def stage_twin(args):
    days = parse_days(args.days)
    offs = L.day_offsets()
    tw = Twin()
    clk = Counter()
    tag = args.tag or ("fresh" if args.fresh else "causal")
    if not args.fresh and not args.tag:
        assert days[0] == 0, "the causal run starts at day 0"
    out_dir = adir(tag)
    t_all = time.perf_counter()
    per_day = {}
    for d in days:
        t = time.perf_counter()
        r = tw.day_pass(d, offs[d], clk)
        np.savez(os.path.join(out_dir, f"day={d:02d}.npz"), **r)
        per_day[f"{d:02d}"] = {"events": int(r["n"]), "alerted_events": int(len(r["a_pos"])),
                               "alerts": {x: int(len(r[f"alert::{x}"])) for x in DETS},
                               "seconds": round(time.perf_counter() - t, 1)}
        print(f"day {d:02d}: {per_day[f'{d:02d}']}", flush=True)
    tw.notifier.flush()
    log = [(k, int(h), list(ids), o) for k, h, ids, o in tw.notifier.log]
    with open(os.path.join(out_dir, "email_log.json"), "w") as f:
        json.dump(log, f)
    out = {"tag": tag, "days": days, "fresh_start": bool(args.fresh), "per_day": per_day,
           "events": int(tw.n_events), "accounts": len(tw.accc.names), "ips": len(tw.ipc.names),
           "email_log_entries": len(log),
           "seconds": round(time.perf_counter() - t_all, 1),
           "seconds_by_part": {k: round(v, 1) for k, v in clk.items()},
           "peak_working_set_bytes": peak_working_set()}
    L.save_json(f"lanl_a_twin_{tag}.json", out)
    print(json.dumps({k: v for k, v in out.items() if k != "per_day"}, indent=1))
    return 0


# ── Real agents on one day ───────────────────────────────────────────────────

class _Store:
    def __init__(self):
        self.i = -1
        self.rows = []

    def save_alert(self, a):
        inc = a.get("incident") or {}
        self.rows.append((self.i, a["type"], inc.get("tier"), tuple(inc.get("score") or ()),
                          inc.get("email")))

    def update_fields(self, *a, **k):
        pass


def events_of_day(d, limit=None):
    tbl = L.day_table(d, ["time", "src_user", "src_computer", "success"])
    if limit:
        tbl = tbl.slice(0, limit)
    off = L.day_offsets()[d]
    t = tbl.column("time").to_numpy().astype(np.int64)
    users = tbl.column("src_user").to_pylist()
    ips = tbl.column("src_computer").to_pylist()
    st = ["SUCCESS" if x == "Success" else "FAILED" if x == "Fail" else x
          for x in tbl.column("success").to_pylist()]
    n = len(t)
    for a in range(0, n, 1_000_000):
        b = min(n, a + 1_000_000)
        stamps = ts_strings(BASE + t[a:b] - 1)
        for i in range(a, b):
            yield {"timestamp": stamps[i - a], "user": users[i], "ip": ips[i], "status": st[i],
                   "country": CONST, "device_type": CONST, "asn": CONST_ASN, "region": CONST,
                   "user_agent": CONST, "browser": CONST, "os": CONST, "rtt": 0.0,
                   "event_id": off + i}


def stage_replay(args):
    """Real agents from empty state over --days (one or more consecutive
    days), against the fresh twin run of the same days (tag fresh<a>[_<b>])."""
    from agents.monitoring_agent import MonitoringAgent
    from agents.response_agent import ResponseAgent
    assert (config.RULES_MODE, config.ML_MODE, config.ML_V4_IFOREST) == ("v3", "v4", "retired")
    days = parse_days(args.days)
    tag = f"fresh{days[0]}" + (f"_{days[-1]}" if len(days) > 1 else "")
    assert not args.limit or len(days) == 1, "--limit is for a single-day smoke"
    with open(os.path.join(adir(tag), "email_log.json")) as f:
        exp_log_list = json.load(f)
    store = _Store()
    responder = ResponseAgent(email_alerter=_Rec(), email_log_max=None)
    mon = MonitoringAgent(alert_manager=store, responder=responder)
    assert mon.detector.anomaly_detector is None
    status = responder.status
    ok = True
    res = {"days": days, "twin_tag": tag, "limit": args.limit, "fresh_start": True, "per_day": {}}
    t_all = time.perf_counter()
    events_total = 0
    for d in days:
        z = dict(np.load(os.path.join(adir(tag), f"day={d:02d}.npz")))
        n_day = int(z["n"])
        n = args.limit or n_day
        got_ch = np.zeros(n, bool)
        got_bl = np.zeros(n, bool)
        store.rows = []
        t0 = time.perf_counter()
        for i, e in enumerate(events_of_day(d, args.limit)):
            st = status(e)
            got_bl[i], got_ch[i] = st["blocked"], st["challenged"]
            store.i = i
            mon._process_event(e)
        secs = time.perf_counter() - t0
        events_total += n
        rows = store.rows                      # positions local to the day, as the twin's
        pos = np.array([r[0] for r in rows], np.int64)
        typ = np.array([r[1] for r in rows], dtype=object)
        det_mm = {}
        for x in DETS:
            exp = np.zeros(n, bool)
            p = z[f"alert::{x}"]
            exp[p[p < n]] = True
            got = np.zeros(n, bool)
            got[pos[typ == x]] = True
            det_mm[x] = {"twin": int(exp.sum()), "agents": int(got.sum()),
                         "mismatches": int((exp != got).sum())}
            ok &= det_mm[x]["mismatches"] == 0
        ml = int(sum(1 for x in typ if x == R.ML))
        j_of = {int(p): j for j, p in enumerate(z["a_pos"].tolist()) if p < n}
        tier_mm = score_mm = 0
        seen = set()
        tiers_seen = Counter()
        for i, ty, tier, score, email in rows:
            if i in seen:
                continue
            seen.add(i)
            tiers_seen[tier] += 1
            j = j_of.get(i)
            tier_mm += j is None or tier != TR.TIERS[z["tier_ev"][j]]
            score_mm += j is None or score != (float(z["score0"][j]), float(z["score1"][j]))
        missing = len(set(j_of) - seen)
        ch_mm = int((got_ch != z["challenged"][:n]).sum())
        bl_mm = int(got_bl.sum())
        exp_out = {int(p): o for p, o in zip(z["email_pos"].tolist(), z["email_out"].tolist())
                   if int(p) < n}
        got_out = {i: e for i, ty, tier, score, e in rows if e not in (None, "not_required")}
        out_mm = sum(1 for k in set(exp_out) | set(got_out) if exp_out.get(k) != got_out.get(k))
        ok &= (ml == 0 and tier_mm == 0 and score_mm == 0 and missing == 0 and ch_mm == 0
               and bl_mm == 0 and out_mm == 0)
        res["per_day"][f"{d:02d}"] = {
            "events": n, "detector_alerts": det_mm, "ml_alerts": ml,
            "alerted_events_compared": len(seen), "alerted_events_missing": missing,
            "alerted_events_by_tier_agents": dict(tiers_seen),
            "tier_mismatches": int(tier_mm), "score_mismatches": int(score_mm),
            "challenged_events_agents": int(got_ch.sum()), "challenged_state_mismatches": ch_mm,
            "blocked_events": bl_mm, "email_outcomes_agents": dict(Counter(got_out.values())),
            "email_outcome_mismatches": int(out_mm),
            "replay_seconds": round(secs, 1), "us_per_event": round(1e6 * secs / n, 1)}
        if args.limit:
            res["estimate_full_day_seconds"] = round(secs * n_day / n)
        print(f"day {d:02d}: {res['per_day'][f'{d:02d}']}", flush=True)
    responder.flush()
    last_day = days[-1]
    n_last = args.limit or int(np.load(os.path.join(adir(tag), f"day={last_day:02d}.npz"))["n"])
    last_hour = (BASE + int(L.day_table(last_day, ["time"]).column("time")[n_last - 1].as_py()) - 1) // 3600
    norm = lambda log: Counter((k, int(h), tuple(ids), o) for k, h, ids, o in log     # noqa: E731
                               if not args.limit or int(h) < last_hour)
    got_log, exp_log = norm(responder.notifier.log), norm(exp_log_list)
    email_mm = sum(((got_log - exp_log) + (exp_log - got_log)).values())
    ok &= email_mm == 0
    res.update({"equivalent": bool(ok), "email_log_entries_agents": len(responder.notifier.log),
                "email_log_mismatches": int(email_mm), "duplicate_events": mon.duplicate_events,
                "challenged_source_events": mon.challenged_source_events,
                "replay_seconds": round(time.perf_counter() - t_all, 1),
                "us_per_event": round(1e6 * (time.perf_counter() - t_all) / events_total, 1),
                "peak_working_set_bytes": peak_working_set()})
    name = f"lanl_a_replay_{tag}{'_smoke' if args.limit else ''}.json"
    L.save_json(name, res)
    print(json.dumps({k: v for k, v in res.items() if k != "per_day"}, indent=1))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["twin", "replay", "metrics"])
    ap.add_argument("--days", default="0-13")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--tag", default=None)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    if args.stage == "metrics":
        from eval import lanl_a_metrics
        return lanl_a_metrics.main()
    return {"twin": stage_twin, "replay": stage_replay}[args.stage](args)


if __name__ == "__main__":
    sys.exit(main())
