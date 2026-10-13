# backend/agents/rules_v3.py
"""
v3 rule engine (config.RULES_MODE = "v3", Phase 3). Selected through the
agents.detection_agent.DetectionAgent factory.

State model
  - Every event is evaluated by every detector and by the ML step. Nothing
    is skipped because an address alerted or was blocked earlier (F01, F19).
    The ML scorer therefore sees, and counts, every event (F20).
  - Alerts are de-duplicated per (detector, key) with a cooldown that
    expires (V3_DEDUP_SECONDS). A suppressed match is still recorded as a
    match (Detection.matched) and still updates all state.
  - Blocking is not detection state. It lives in the response layer
    (agents/response_agent.py BlockList, BLOCK_TTL_SECONDS); events from a
    blocked address are detected as usual and reported by the pipeline as
    "event from blocked source".
  - Every counter is a sliding window over event time, kept sorted (so late,
    out-of-order events land in the right place) and pruned to its longest
    window. Per-key state is evicted once idle for longer than its horizon,
    so memory is bounded by the traffic inside the windows (F02, F23).
  - Input normalisation: status upper-cased, usernames stripped and
    casefolded, and repeated delivery of the same event (same event_id, or
    the same fields when there is no id) inside V3_DUPLICATE_WINDOW_SECONDS
    is counted once (F16, F17).
  - User IDs in config.UNKNOWN_ACCOUNT_IDS are "unknown-account attempts":
    they never enter per-account state and never count as a distinct
    account. They are counted per IP, for the invalid-account detector
    only (Phase 3.3).

Detectors (thresholds and windows in config.V3_*; every detector that
matches an event is reported, not just the first):
  Brute Force Attack        real-account failures from one IP in V3_BF_WINDOW
  Slow Brute Force          failures from one IP over V3_SLOW_BF_WINDOW,
                            spread >= V3_SLOW_BF_MIN_SPREAD, while the Brute
                            Force count is below its threshold
  Credential Stuffing       distinct real accounts with FAILED attempts from
                            one IP in V3_CS_WINDOW (successes excluded, F18)
  Invalid Account Spraying  unknown-account attempts from one IP in
                            V3_INVALID_WINDOW
  Distributed Brute Force   distinct IPs failing against one real account
                            in V3_DIST_WINDOW (F16)
  Success After Failures    a real-account SUCCESS preceded, within
                            V3_SAF_WINDOW, by >= V3_SAF_MIN_FAILURES
                            failures on that account or from that IP (F01)
  Multiple IP Login         the legacy 120 s rule, with optional exemptions
                            (V3_MULTI_IP_EXEMPT: known_ip, same_prefix,
                            same_asn; F29)
  Suspicious Login Time     unchanged: SUCCESS in the off-hours window,
                            de-duplicated per IP for 600 s
"Failures" are FAILED events against real accounts.
"""

import ipaddress
from bisect import bisect_left, bisect_right, insort
from collections import OrderedDict
from functools import lru_cache

import config
from agents.detection_agent import is_internal_ip
from utils.event_schema import epoch_seconds

BF = "Brute Force Attack"
SLOW = "Slow Brute Force"
CS = "Credential Stuffing"
INVALID = "Invalid Account Spraying"
DIST = "Distributed Brute Force"
SAF = "Success After Failures"
MULTI = "Multiple IP Login"
OFF_HOURS = "Suspicious Login Time"
ML = "ML Anomaly Detected"

RULE_DETECTORS = (BF, SLOW, CS, INVALID, DIST, SAF, MULTI, OFF_HOURS)
DETECTORS = RULE_DETECTORS + (ML,)

MULTI_IP_EXEMPTIONS = ("known_ip", "same_prefix", "same_asn")


def normalize_account(user):
    return str(user).strip().casefold()


@lru_cache(maxsize=1 << 16)
def ip_prefix(ip):
    """The /24 (IPv4) or /64 (IPv6) network of ip, or None if it is not an IP."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    bits = 24 if addr.version == 4 else 64
    return ipaddress.ip_network(f"{addr}/{bits}", strict=False)


# ── State primitives ─────────────────────────────────────────────────────────

class Window:
    """
    Event times (seconds) of one key, kept sorted, optionally with an item
    per time for distinct counting. Late events are inserted in order.
    prune(t0) drops times < t0; the list is compacted as the head advances.
    """

    __slots__ = ("t", "v", "h", "counts")

    def __init__(self, distinct=False):
        self.t = []
        self.v = [] if distinct else None
        self.h = 0
        self.counts = {} if distinct else None

    def add(self, t, item=None):
        ts = self.t
        if not ts or t >= ts[-1]:
            ts.append(t)
            i = None
        else:
            i = bisect_right(ts, t, self.h)
            ts.insert(i, t)
        if self.counts is not None:
            if i is None:
                self.v.append(item)
            else:
                self.v.insert(i, item)
            self.counts[item] = self.counts.get(item, 0) + 1

    def prune(self, t0):
        ts, h, n = self.t, self.h, len(self.t)
        counts = self.counts
        while h < n and ts[h] < t0:
            if counts is not None:
                item = self.v[h]
                c = counts[item] - 1
                if c:
                    counts[item] = c
                else:
                    del counts[item]
            h += 1
        if h > 32 and 2 * h > n:
            del ts[:h]
            if self.v is not None:
                del self.v[:h]
            h = 0
        self.h = h

    def __len__(self):
        return len(self.t) - self.h

    def last(self):
        return self.t[-1]

    def first_since(self, t0):
        """Earliest time >= t0 (the caller knows one exists)."""
        return self.t[bisect_left(self.t, t0, self.h)]

    def count_since(self, t0):
        return len(self.t) - bisect_left(self.t, t0, self.h)

    def count_between(self, t0, t1):
        return bisect_right(self.t, t1, self.h) - bisect_left(self.t, t0, self.h)

    def distinct(self):
        return len(self.counts)


class KeyedState:
    """
    key -> state object (with a .wm watermark, the latest event time seen
    for the key), in least-recently-touched order. evict(now) drops keys
    idle for longer than the horizon, so the dict stays bounded.
    """

    def __init__(self, factory, horizon):
        self.d = OrderedDict()
        self.factory = factory
        self.horizon = horizon

    def touch(self, key, t):
        s = self.d.get(key)
        if s is None:
            s = self.d[key] = self.factory()
            s.wm = t
        else:
            self.d.move_to_end(key)
            if t > s.wm:
                s.wm = t
        return s

    def get(self, key):
        return self.d.get(key)

    def evict(self, now):
        d, cut = self.d, now - self.horizon
        while d:
            k = next(iter(d))
            if d[k].wm >= cut:
                break
            del d[k]

    def __len__(self):
        return len(self.d)


class _IPState:
    __slots__ = ("wm", "fail", "accts", "unknown")

    def __init__(self):
        self.fail = None      # Window: real-account failures
        self.accts = None     # Window(distinct): real accounts with a failure
        self.unknown = None   # Window: unknown-account attempts


class _AccountState:
    __slots__ = ("wm", "fail", "ips")

    def __init__(self):
        self.fail = None      # Window: failures on this account (any IP)
        self.ips = None       # Window(distinct): IPs with a failure on it


class _AccountHistory:
    __slots__ = ("wm", "last", "known")

    def __init__(self):
        self.last = None      # (ip, t, asn) of the latest SUCCESS
        self.known = {}       # ip -> time of its latest SUCCESS on the account


class _Stamp:
    __slots__ = ("wm",)


class Cooldowns:
    """Last emission time per key; fires if none or older than the cooldown."""

    def __init__(self, horizon):
        self.state = KeyedState(_Stamp, horizon)

    def fire(self, key, t, cooldown):
        s = self.state.get(key)
        if s is not None and not (t - s.wm > cooldown):
            return False
        s = self.state.touch(key, t)
        s.wm = t
        return True


class Detection:
    """What the engine concluded about one event."""

    __slots__ = ("alerts", "matched", "duplicate", "ml")

    def __init__(self):
        self.alerts = []      # alerts raised (after de-duplication)
        self.matched = []     # every detector whose condition held
        self.duplicate = False
        self.ml = None        # the ML scorer's result, if it scored the event


# ── The engine ───────────────────────────────────────────────────────────────

class V3DetectionAgent:

    def __init__(self, anomaly_detector=None):
        c = config
        self.anomaly_detector = anomaly_detector
        if anomaly_detector is not None and hasattr(anomaly_detector, "set_failed_rate_window"):
            anomaly_detector.set_failed_rate_window(c.ML_FAILED_RATE_WINDOW_DAYS)

        self.w_bf, self.n_bf = c.V3_BF_WINDOW_SECONDS, c.V3_BF_MIN_FAILURES
        self.w_slow, self.n_slow = c.V3_SLOW_BF_WINDOW_SECONDS, c.V3_SLOW_BF_MIN_FAILURES
        self.slow_spread = c.V3_SLOW_BF_MIN_SPREAD_SECONDS
        self.w_cs, self.n_cs = c.V3_CS_WINDOW_SECONDS, c.V3_CS_MIN_ACCOUNTS
        self.w_inv, self.n_inv = c.V3_INVALID_WINDOW_SECONDS, c.V3_INVALID_MIN_ATTEMPTS
        self.w_dist, self.n_dist = c.V3_DIST_WINDOW_SECONDS, c.V3_DIST_MIN_IPS
        self.w_saf, self.n_saf = c.V3_SAF_WINDOW_SECONDS, c.V3_SAF_MIN_FAILURES
        self.w_multi = c.V3_MULTI_IP_WINDOW_SECONDS
        self.multi_exempt = frozenset(c.V3_MULTI_IP_EXEMPT)
        unknown = self.multi_exempt - set(MULTI_IP_EXEMPTIONS)
        if unknown:
            raise ValueError(f"unknown V3_MULTI_IP_EXEMPT entries: {sorted(unknown)}")
        self.known_ttl = c.V3_KNOWN_IP_TTL_SECONDS
        self.dedup = dict(c.V3_DEDUP_SECONDS)
        self.unknown_accounts = frozenset(normalize_account(u) for u in c.UNKNOWN_ACCOUNT_IDS)

        self.w_ip_fail = max(self.w_bf, self.w_slow, self.w_saf)
        ip_horizon = max(self.w_ip_fail, self.w_cs, self.w_inv)
        acct_horizon = max(self.w_dist, self.w_saf)
        self.ips = KeyedState(_IPState, ip_horizon)
        self.accounts = KeyedState(_AccountState, acct_horizon)
        self.history = KeyedState(_AccountHistory, max(self.known_ttl, self.w_multi))
        self.cooldowns = Cooldowns(max(self.dedup.values()))
        self.dup_window = c.V3_DUPLICATE_WINDOW_SECONDS
        self.seen = KeyedState(_Stamp, self.dup_window)
        self.now = None       # latest event time seen (eviction clock)
        self.events = 0

    # ── public API ──────────────────────────────────────────────────────────

    def analyze_all(self, log_event):
        """The alerts raised for one event (possibly several)."""
        return self.analyze(log_event).alerts

    def analyze(self, log_event):
        det = Detection()
        t = epoch_seconds(log_event["timestamp"])
        ip = str(log_event["ip"]).strip()
        user = log_event["user"]
        account = normalize_account(user)
        status = str(log_event.get("status", "")).strip().upper()

        if self.now is None or t > self.now:
            self.now = t
        self.events += 1
        if self.events % 4096 == 0:
            self._evict()

        if self._is_duplicate(log_event, t, ip, account, status):
            det.duplicate = True
            return det

        unknown = account in self.unknown_accounts
        failed = status == "FAILED"
        success = status == "SUCCESS"
        hits = []             # (detector, dedup key, alert body)

        # ── per-IP state ────────────────────────────────────────────────────
        ips = self.ips.touch(ip, t)
        if unknown:
            if ips.unknown is None:
                ips.unknown = Window()
            ips.unknown.add(t)
            ips.unknown.prune(ips.unknown.last() - self.w_inv)
            n = ips.unknown.count_since(ips.unknown.last() - self.w_inv)
            if n >= self.n_inv:
                hits.append((INVALID, ip, self._body_invalid(ip, user, n)))
        elif failed:
            if ips.fail is None:
                ips.fail, ips.accts = Window(), Window(distinct=True)
            fw = ips.fail
            fw.add(t)
            fw.prune(fw.last() - self.w_ip_fail)
            ips.accts.add(t, account)
            ips.accts.prune(ips.accts.last() - self.w_cs)
            anchor = fw.last()
            n_bf = fw.count_since(anchor - self.w_bf)
            if n_bf >= self.n_bf:
                hits.append((BF, ip, self._body_bf(ip, user, n_bf)))
            else:
                n_slow = fw.count_since(anchor - self.w_slow)
                if n_slow >= self.n_slow:
                    spread = anchor - fw.first_since(anchor - self.w_slow)
                    if spread >= self.slow_spread:
                        hits.append((SLOW, ip, self._body_slow(ip, user, n_slow, spread)))
            n_accts = ips.accts.distinct()
            if n_accts >= self.n_cs:
                hits.append((CS, ip, self._body_cs(ip, user, n_accts)))

        # ── per-account state (real accounts only) ──────────────────────────
        if not unknown and failed:
            acc = self.accounts.touch(account, t)
            if acc.fail is None:
                acc.fail, acc.ips = Window(), Window(distinct=True)
            acc.fail.add(t)
            acc.fail.prune(acc.fail.last() - self.w_saf)
            acc.ips.add(t, ip)
            acc.ips.prune(acc.ips.last() - self.w_dist)
            n_ips = acc.ips.distinct()
            if n_ips >= self.n_dist:
                hits.append((DIST, (account, ip), self._body_dist(ip, user, n_ips)))

        if not unknown and success:
            n_acc = 0
            acc = self.accounts.get(account)
            if acc is not None and acc.fail is not None:
                n_acc = acc.fail.count_between(t - self.w_saf, t)
            n_ip = 0
            if ips.fail is not None:
                n_ip = ips.fail.count_between(t - self.w_saf, t)
            if n_acc >= self.n_saf or n_ip >= self.n_saf:
                hits.append((SAF, (account, ip), self._body_saf(ip, user, n_acc, n_ip)))
            self._multi_ip(hits, account, user, ip, t, log_event.get("asn"))

        # ── off-hours (per IP, every SUCCESS) ───────────────────────────────
        if success:
            hour = int(log_event["timestamp"][11:13]) if len(log_event["timestamp"]) >= 13 else -1
            start, end = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
            if start <= hour <= end:
                hits.append((OFF_HOURS, ip, self._body_off_hours(ip, user, log_event["timestamp"], hour)))

        # ── ML: every event ─────────────────────────────────────────────────
        if self.anomaly_detector is not None and not (
                config.INTERNAL_IP_GUARD_ENABLED and is_internal_ip(ip)):
            ml_event = log_event
            if log_event.get("status") != status:
                ml_event = dict(log_event, status=status)
            result = self.anomaly_detector.score_event(ml_event)
            det.ml = result
            if result and result["is_anomaly"]:
                hits.append((ML, ip, None))

        for name, key, body in hits:
            det.matched.append(name)
            cooldown = self.dedup.get(name, self.dedup["default"])
            if not self.cooldowns.fire((name, key), t, cooldown):
                continue
            if name == ML:
                body = self._body_ml(ml_event, ip, user, failed, det.ml)
            alert = {"type": name, "ip": ip, "user": user}
            alert.update(body)
            det.alerts.append(alert)
        return det

    def state_sizes(self):
        """Number of tracked keys per state table (for memory checks)."""
        return {"ips": len(self.ips), "accounts": len(self.accounts),
                "account_history": len(self.history),
                "cooldowns": len(self.cooldowns.state), "recent_events": len(self.seen)}

    # ── internals ───────────────────────────────────────────────────────────

    def _evict(self):
        now = self.now
        for s in (self.ips, self.accounts, self.history, self.cooldowns.state, self.seen):
            s.evict(now)

    def _is_duplicate(self, e, t, ip, account, status):
        if self.dup_window <= 0:
            return False
        eid = e.get("event_id")
        key = ("id", eid) if eid is not None else (
            t, ip, account, status, e.get("country"), e.get("device_type"))
        s = self.seen.get(key)
        if s is not None and self.now - s.wm <= self.dup_window:
            return True
        self.seen.touch(key, t)
        return False

    def _multi_ip(self, hits, account, user, ip, t, asn):
        h = self.history.touch(account, t)
        prev = h.last
        if prev is not None:
            last_ip, last_t, last_asn = prev
            diff = abs(t - last_t)
            if ip != last_ip and diff < self.w_multi and not self._exempt(
                    h, ip, t, last_ip, asn, last_asn):
                hits.append((MULTI, (account, ip), self._body_multi(user, last_ip, ip, diff)))
        h.last = (ip, t, asn)
        known = h.known
        if self.known_ttl > 0:
            cut = t - self.known_ttl
            if len(known) > 8:
                for k in [k for k, v in known.items() if v < cut]:
                    del known[k]
            if known.get(ip, t) <= t:
                known[ip] = t

    def _exempt(self, h, ip, t, last_ip, asn, last_asn):
        ex = self.multi_exempt
        if "known_ip" in ex:
            seen = h.known.get(ip)
            if seen is not None and seen >= t - self.known_ttl:
                return True
        if "same_prefix" in ex:
            p = ip_prefix(ip)
            if p is not None and p == ip_prefix(last_ip):
                return True
        if "same_asn" in ex and asn is not None and last_asn is not None and asn == last_asn:
            return True
        return False

    # ── alert bodies ────────────────────────────────────────────────────────

    def _body_bf(self, ip, user, n):
        return {
            "description": f"{n} failed logins from {ip} within {self.w_bf} s",
            "trigger_details": {
                "rule": "Failed logins from one IP within a sliding window",
                "threshold": f"{self.n_bf}+ failures within {self.w_bf} s",
                "actual": f"{n} failures from {ip}",
                "values": {"failed_count": n, "threshold": self.n_bf,
                           "window_s": self.w_bf},
            },
        }

    def _body_slow(self, ip, user, n, spread):
        return {
            "description": (f"{n} failed logins from {ip} spread over "
                            f"{spread // 60} minutes (below the Brute Force rate)"),
            "trigger_details": {
                "rule": "Slow brute force: failures spread out over a long window",
                "threshold": (f"{self.n_slow}+ failures within {self.w_slow} s, spread "
                              f">= {self.slow_spread} s, fewer than {self.n_bf} "
                              f"within {self.w_bf} s"),
                "actual": f"{n} failures over {spread} s from {ip}",
                "values": {"failure_count": n, "spread_s": spread,
                           "window_s": self.w_slow, "min_spread_s": self.slow_spread},
            },
        }

    def _body_cs(self, ip, user, n):
        return {
            "description": f"IP {ip} failed logins on {n} different accounts within {self.w_cs} s",
            "trigger_details": {
                "rule": "Distinct accounts with failed logins from one IP",
                "threshold": f"{self.n_cs}+ failing accounts within {self.w_cs} s",
                "actual": f"{n} accounts failed from {ip}",
                "values": {"failing_accounts": n, "threshold": self.n_cs,
                           "window_s": self.w_cs},
            },
        }

    def _body_invalid(self, ip, user, n):
        return {
            "description": f"IP {ip} made {n} attempts on unknown accounts within {self.w_inv} s",
            "trigger_details": {
                "rule": "Login attempts against unknown usernames from one IP",
                "threshold": f"{self.n_inv}+ unknown-account attempts within {self.w_inv} s",
                "actual": f"{n} unknown-account attempts from {ip}",
                "values": {"unknown_account_attempts": n, "threshold": self.n_inv,
                           "window_s": self.w_inv},
            },
        }

    def _body_dist(self, ip, user, n):
        return {
            "description": f"Account {user} failed logins from {n} different IPs within {self.w_dist} s",
            "trigger_details": {
                "rule": "Failed logins against one account from many IPs",
                "threshold": f"{self.n_dist}+ IPs within {self.w_dist} s",
                "actual": f"{n} IPs failed on {user}, latest {ip}",
                "values": {"distinct_ips": n, "threshold": self.n_dist,
                           "window_s": self.w_dist},
            },
        }

    def _body_saf(self, ip, user, n_acc, n_ip):
        return {
            "description": (f"Successful login for {user} from {ip} after {n_acc} failures on "
                            f"the account and {n_ip} from the IP within {self.w_saf} s"),
            "trigger_details": {
                "rule": "Success after failures (possible compromise)",
                "threshold": f"{self.n_saf}+ failures on the account or from the IP within {self.w_saf} s",
                "actual": f"{n_acc} account failures, {n_ip} IP failures before the success",
                "values": {"account_failures": n_acc, "ip_failures": n_ip,
                           "threshold": self.n_saf, "window_s": self.w_saf},
            },
        }

    def _body_multi(self, user, last_ip, ip, diff):
        w = self.w_multi
        return {
            "description": f"User {user} logged in from {last_ip} and {ip} within {diff} seconds",
            "trigger_details": {
                "rule": f"Same user authenticated from two IPs within {w} s",
                "threshold": (f"Maximum {w} seconds between logins from different IPs"
                              + (f"; exempt: {', '.join(sorted(self.multi_exempt))}"
                                 if self.multi_exempt else "")),
                "actual": f"{user} logged from {last_ip} then {ip} within {diff}s",
                "values": {"first_ip": last_ip, "second_ip": ip, "time_diff_s": diff,
                           "threshold_s": w},
            },
        }

    def _body_off_hours(self, ip, user, ts, hour):
        start, end = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
        return {
            "description": f"User {user} logged in at unusual hour ({ts[11:16]})",
            "trigger_details": {
                "rule": "Off-hours login detected",
                "threshold": f"Logins between {start:02d}:00–{end:02d}:59 flagged",
                "actual": f"Login at {ts[11:16]} (hour {hour})",
                "values": {"login_hour": hour, "restricted_window": f"{start:02d}:00–{end:02d}:59"},
            },
        }

    def _body_ml(self, log_event, ip, user, failed, result):
        explanation = None
        if hasattr(self.anomaly_detector, "explain_event"):
            explanation = self.anomaly_detector.explain_event(
                log_event, result["anomaly_score"], result["confidence"])
        return {
            "anomaly_score": result["anomaly_score"],
            "confidence": result["confidence"],
            "feature_explanation": explanation,
            "description": (f"Unusual login behaviour detected for user {user} from {ip}. "
                            f"Anomaly score: {result['anomaly_score']} "
                            f"(confidence: {result['confidence']}). "
                            + (explanation["summary"] if explanation else "")),
            "trigger_details": {
                "rule": "Isolation Forest (scored on every event)",
                "threshold": (f"Score < {config.CONFIDENCE_HIGH_CUTOFF:.2f} = High, "
                              f"< {config.CONFIDENCE_MEDIUM_CUTOFF:.2f} = Medium confidence"),
                "actual": f"Score {result['anomaly_score']} ({result['confidence']} confidence)",
                "values": {"anomaly_score": result["anomaly_score"],
                           "confidence": result["confidence"],
                           "is_failed_event": failed},
            },
        }
