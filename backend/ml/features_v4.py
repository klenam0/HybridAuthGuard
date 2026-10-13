# backend/ml/features_v4.py
"""
Phase 4 causal feature extractor (eval/PROTOCOL.md amendment 4).

FeatureExtractorV4.update_and_extract(event) returns the feature vector of
one login event and then adds the event to its state. Every feature is
computed from events strictly before the current one (earlier calls), so a
vector never depends on later events. The same object is used by the live
DetectionAgent (ML_MODE = "v4", through ml/model_v4.V4Scorer) and by the
offline evaluation (eval/phase4.py), which feeds it the development stream
in time order from 2020-02-03.

Event fields read (missing ones count as the empty value):
  timestamp "%Y-%m-%d %H:%M:%S", user, ip, status (SUCCESS/FAILED), country,
  region, asn, device_type, user_agent, browser ("Browser Name and Version"),
  os ("OS Name and Version"), rtt (milliseconds, may be missing).
No label is ever read.

Feature groups (FEATURE_GROUPS; the ablation table drops one at a time):
  A  per-user novelty: first event of the user; new IP, /24 (/64), ASN,
     country, region, user-agent string, browser family, OS family and
     device type for the user; log1p(prior events of the user); log1p(seconds
     since the user's last event) (-1 for the first event); circular hour
     deviation 1 - cos(angle(hour) - circular mean of the user's prior hours)
     (0 with fewer than 3 prior events).
  B  per-IP velocity: failures from the IP in the last 1 h and 24 h; distinct
     real accounts with an event from the IP in 24 h; failure share of the
     IP's events in 24 h (0 if none); placeholder-ID attempts in 24 h.
  C  per-account velocity (real accounts): failures in the last 1 h and
     24 h; distinct IPs and distinct countries with an event on the account
     in 24 h; all 0 for config.UNKNOWN_ACCOUNT_IDS, plus is_unknown_account.
  D  aggregate reputation, all prior history: failure share and log1p(event
     count) of the ASN and of the IP (behaviour only, never labels).
  E  context: login succeeded, log1p(RTT ms) (-1 if missing), hour of day
     (sin, cos), weekday (Monday = 0).
"Last 1 h / 24 h" = prior events with time >= t - 3600 / t - 86400; hours
are the event's own clock (UTC in the RBA data), fractional.

Freeman et al. (2016) risk ("Who Are You? A Statistical Approach to
Measuring User Authenticity", NDSS 2016), computed in the same pass for each
beta in FREEMAN_BETAS and kept in .last_freeman (log risk, one per beta):

  log risk = sum over levels of log p(v | population) - log p(v | user)

  IP chain:  country -> ASN -> /24 (/64) -> IP
  UA chain:  browser family -> browser + OS -> UA string
  Levels are nested (an ASN node lives under its country, and so on).
  p(v | population) at a node = (G(v) + 1) / (G(parent) + K(parent) + 1),
  with G the prior event counts and K the distinct children seen (one
  reserved slot for unseen values). p(v | user) = (n_u(v) + beta *
  p(v | population)) / (n_u(parent) + beta), so a user with no history at a
  level gets the population value and the term is 0.

Simplifications relative to the paper:
  - p(v | attacker) is approximated by the population distribution of all
    prior logins (label-free); the paper also explored attack data and IP
    reputation lists, which are not used.
  - Only the IP and user-agent hierarchies are used; the paper's other
    features (e.g. time of day as a risk factor, cookie and device-ID
    signals) are not modelled. There is no global login-rate or p(user)
    prior, and the features are combined under the paper's independence
    assumption only (no learned weights).
  - Smoothing is a single fixed-strength (beta) backoff per level towards
    the population conditional, instead of the paper's per-level smoothing
    estimated from data; the population side uses add-one smoothing.
  - History is every prior event of the user (successes and failures, no
    decay or forgetting window), not only successful, verified logins.
  - Browser and OS families are the strings with their trailing version
    tokens removed; no user-agent parsing beyond that.
"""

import math
from collections import OrderedDict, deque

import numpy as np

import config
from agents.rules_v3 import ip_prefix, normalize_account
from utils.event_schema import epoch_seconds

FEATURE_GROUPS = OrderedDict([
    ("A", ["a_first_event", "a_new_ip", "a_new_prefix", "a_new_asn", "a_new_country",
           "a_new_region", "a_new_ua", "a_new_browser", "a_new_os", "a_new_device",
           "a_log_prior_events", "a_log_secs_since_last", "a_hour_deviation"]),
    ("B", ["b_ip_fail_1h", "b_ip_fail_24h", "b_ip_accounts_24h", "b_ip_fail_ratio_24h",
           "b_ip_placeholder_24h"]),
    ("C", ["c_acct_fail_1h", "c_acct_fail_24h", "c_acct_ips_24h", "c_acct_countries_24h",
           "c_is_unknown_account"]),
    ("D", ["d_asn_fail_ratio", "d_asn_log_count", "d_ip_fail_ratio", "d_ip_log_count"]),
    ("E", ["e_success", "e_log_rtt", "e_hour_sin", "e_hour_cos", "e_weekday"]),
])
FEATURE_NAMES = [f for fs in FEATURE_GROUPS.values() for f in fs]
N_FEATURES = len(FEATURE_NAMES)
FREEMAN_BETAS = (0.5, 2.0, 8.0)

H1, H24 = 3600, 86400
_TWO_PI = 2.0 * math.pi
# Per-user seen-value keys: (value id << 4) | attribute.
_IP, _PFX, _ASN, _CTRY, _REG, _UA, _BR, _OS, _DEV = range(9)


def columns(groups):
    """Column indices of FEATURE_NAMES for the given group letters."""
    keep = {f for g in groups for f in FEATURE_GROUPS[g]}
    return [i for i, f in enumerate(FEATURE_NAMES) if f in keep]


def family(name):
    """Browser or OS name without its trailing version tokens."""
    parts = name.split()
    while parts and parts[-1][:1].isdigit():
        parts.pop()
    return " ".join(parts)


def prefix_of(ip):
    """/24 for IPv4 (string cut), /64 for IPv6, the string itself otherwise."""
    if ip.count(".") == 3 and ":" not in ip:
        return ip.rsplit(".", 1)[0]
    p = ip_prefix(ip)
    return ip if p is None else str(p)


class _User:
    __slots__ = ("n", "last_t", "s", "c", "seen")

    def __init__(self):
        self.n = 0
        self.last_t = 0
        self.s = 0.0          # sum of sin(hour angle) over prior events
        self.c = 0.0          # sum of cos(hour angle)
        self.seen = {}        # value key -> prior events with it (A and Freeman)


class _IPWin:
    __slots__ = ("ev", "f1", "n", "f", "ph", "accts", "wm")

    def __init__(self):
        self.ev = deque()     # (t, failed, account id or -1 for the placeholder)
        self.f1 = deque()     # failure times, last hour
        self.n = self.f = self.ph = 0
        self.accts = {}


class _AcctWin:
    __slots__ = ("ev", "f1", "f", "ips", "ctry", "wm")

    def __init__(self):
        self.ev = deque()     # (t, failed, ip id, country id)
        self.f1 = deque()
        self.f = 0
        self.ips = {}
        self.ctry = {}


class FeatureExtractorV4:
    """Streaming, causal feature extractor (see the module docstring)."""

    def __init__(self, unknown_account_ids=None, betas=FREEMAN_BETAS):
        ids = config.UNKNOWN_ACCOUNT_IDS if unknown_account_ids is None else unknown_account_ids
        self.unknown = frozenset(normalize_account(u) for u in ids)
        self.betas = tuple(betas)
        self._intern = [dict() for _ in range(9)]    # per attribute: value -> id
        self._acct_ids = {}
        self._fam = {}                               # browser/OS string -> family
        self.users = {}
        self.ipwin = OrderedDict()
        self.acctwin = OrderedDict()
        self.ip_rep = {}                             # ip id -> [events, failures]
        self.asn_rep = {}
        # Freeman population tree: node id -> count / distinct children.
        self._node = {}
        self._G = []
        self._K = []
        self._root_ip = self._node_id(("root", "ip"))
        self._root_ua = self._node_id(("root", "ua"))
        self.now = None
        self.events = 0
        self.last_freeman = None

    # ── interning ────────────────────────────────────────────────────────

    def _id(self, attr, value):
        d = self._intern[attr]
        i = d.get(value)
        if i is None:
            i = d[value] = len(d)
        return i

    def _node_id(self, key):
        i = self._node.get(key)
        if i is None:
            i = self._node[key] = len(self._G)
            self._G.append(0)
            self._K.append(0)
        return i

    def _family(self, s):
        f = self._fam.get(s)
        if f is None:
            f = self._fam[s] = family(s)
        return f

    # ── the one public step ──────────────────────────────────────────────

    def update_and_extract(self, e):
        t = epoch_seconds(e["timestamp"])
        if self.now is None or t > self.now:
            self.now = t
        self.events += 1
        if self.events % 4096 == 0:
            self._evict()

        ip = str(e.get("ip", "")).strip()
        account = normalize_account(e.get("user", ""))
        unknown = account in self.unknown
        status = str(e.get("status", "")).strip().upper()
        failed = status == "FAILED"
        success = status == "SUCCESS"
        country = _s(e.get("country"))
        region = _s(e.get("region"))
        asn = _s(e.get("asn"))
        ua = _s(e.get("user_agent"))
        browser = _s(e.get("browser"))
        os_name = _s(e.get("os"))
        device = _s(e.get("device_type"))
        pfx = prefix_of(ip)
        bfam, ofam = self._family(browser), self._family(os_name)

        ip_i = self._id(_IP, ip)
        k_ip = ip_i << 4 | _IP
        k_pfx = self._id(_PFX, pfx) << 4 | _PFX
        asn_i = self._id(_ASN, asn)
        k_asn = asn_i << 4 | _ASN
        ctry_i = self._id(_CTRY, country)
        k_ctry = ctry_i << 4 | _CTRY
        k_reg = self._id(_REG, (country, region)) << 4 | _REG
        k_ua = self._id(_UA, ua) << 4 | _UA
        k_br = self._id(_BR, bfam) << 4 | _BR
        k_os = self._id(_OS, ofam) << 4 | _OS
        k_dev = self._id(_DEV, device) << 4 | _DEV

        # ── A: per-user novelty ──────────────────────────────────────────
        u = self.users.get(account)
        if u is None:
            u = self.users[account] = _User()
        seen = u.seen
        n = u.n
        hour = (t % 86400) / 3600.0
        ang = _TWO_PI * hour / 24.0
        if n:
            dt = t - u.last_t
            a = [0.0, float(k_ip not in seen), float(k_pfx not in seen), float(k_asn not in seen),
                 float(k_ctry not in seen), float(k_reg not in seen), float(k_ua not in seen),
                 float(k_br not in seen), float(k_os not in seen), float(k_dev not in seen),
                 math.log1p(n), math.log1p(dt if dt > 0 else 0),
                 1.0 - math.cos(ang - math.atan2(u.s, u.c)) if n >= 3 else 0.0]
        else:
            a = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, -1.0, 0.0]

        # ── B: per-IP velocity (last 1 h / 24 h, prior events) ───────────
        w = self.ipwin.get(ip_i)
        if w is None:
            w = self.ipwin[ip_i] = _IPWin()
        else:
            self.ipwin.move_to_end(ip_i)
            _prune_ip(w, t)
        b = [float(len(w.f1)), float(w.f), float(len(w.accts)),
             w.f / w.n if w.n else 0.0, float(w.ph)]

        # ── C: per-account velocity (real accounts) ──────────────────────
        if unknown:
            c = [0.0, 0.0, 0.0, 0.0, 1.0]
            acct_i = -1
        else:
            acct_i = self._acct_ids.get(account)
            if acct_i is None:
                acct_i = self._acct_ids[account] = len(self._acct_ids)
            aw = self.acctwin.get(acct_i)
            if aw is None:
                aw = self.acctwin[acct_i] = _AcctWin()
            else:
                self.acctwin.move_to_end(acct_i)
                _prune_acct(aw, t)
            c = [float(len(aw.f1)), float(aw.f), float(len(aw.ips)), float(len(aw.ctry)), 0.0]

        # ── D: aggregate reputation (all prior history) ──────────────────
        r_ip = self.ip_rep.get(ip_i)
        if r_ip is None:
            r_ip = self.ip_rep[ip_i] = [0, 0]
        r_asn = self.asn_rep.get(asn_i)
        if r_asn is None:
            r_asn = self.asn_rep[asn_i] = [0, 0]
        d = [r_asn[1] / r_asn[0] if r_asn[0] else 0.0, math.log1p(r_asn[0]),
             r_ip[1] / r_ip[0] if r_ip[0] else 0.0, math.log1p(r_ip[0])]

        # ── E: context ───────────────────────────────────────────────────
        rtt = e.get("rtt")
        try:
            rtt = float(rtt)
        except (TypeError, ValueError):
            rtt = float("nan")
        ev = [1.0 if success else 0.0, math.log1p(rtt) if rtt >= 0 else -1.0,
              math.sin(ang), math.cos(ang), float((t // 86400 + 3) % 7)]

        # ── Freeman risk (prior state), then the population update ───────
        g_ctry = self._node_id(("c", country))
        g_asn = self._node_id((g_ctry, asn))
        g_pfx = self._node_id((g_asn, pfx))
        g_ip = self._node_id((g_pfx, ip))
        g_br = self._node_id(("b", bfam))
        g_bos = self._node_id((g_br, browser, os_name))
        g_ua = self._node_id((g_bos, ua))
        chains = ((self._root_ip, g_ctry, g_asn, g_pfx, g_ip),
                  (self._root_ua, g_br, g_bos, g_ua))
        self.last_freeman = self._freeman(seen, n, chains)
        G, K = self._G, self._K
        for chain in chains:
            for j in range(1, len(chain)):
                node = chain[j]
                if G[node] == 0:
                    K[chain[j - 1]] += 1
                G[node] += 1
            G[chain[0]] += 1

        # ── state updates (after every feature was read) ─────────────────
        for k in (k_ip, k_pfx, k_asn, k_ctry, k_reg, k_ua, k_br, k_os, k_dev,
                  ~g_ctry, ~g_asn, ~g_pfx, ~g_ip, ~g_br, ~g_bos, ~g_ua):
            seen[k] = seen.get(k, 0) + 1
        u.n = n + 1
        u.last_t = t
        u.s += math.sin(ang)
        u.c += math.cos(ang)

        w.ev.append((t, failed, acct_i))
        w.n += 1
        if failed:
            w.f += 1
            w.f1.append(t)
        if unknown:
            w.ph += 1
        else:
            w.accts[acct_i] = w.accts.get(acct_i, 0) + 1
        w.wm = t

        if not unknown:
            aw.ev.append((t, failed, ip_i, ctry_i))
            if failed:
                aw.f += 1
                aw.f1.append(t)
            aw.ips[ip_i] = aw.ips.get(ip_i, 0) + 1
            aw.ctry[ctry_i] = aw.ctry.get(ctry_i, 0) + 1
            aw.wm = t

        r_ip[0] += 1
        r_asn[0] += 1
        if failed:
            r_ip[1] += 1
            r_asn[1] += 1

        return np.array(a + b + c + d + ev, dtype=np.float64)

    def _freeman(self, seen, n, chains):
        """Log risk per beta from the prior state (see the docstring)."""
        G, K = self._G, self._K
        out = [0.0] * len(self.betas)
        if n == 0:
            return tuple(out)
        for chain in chains:
            for j in range(1, len(chain)):
                parent, node = chain[j - 1], chain[j]
                p_g = (G[node] + 1) / (G[parent] + K[parent] + 1)
                n_par = n if j == 1 else seen.get(~parent, 0)
                n_node = seen.get(~node, 0)
                if n_par == 0:
                    continue
                lg = math.log(p_g)
                for bi, beta in enumerate(self.betas):
                    out[bi] += lg - math.log((n_node + beta * p_g) / (n_par + beta))
        return tuple(out)

    def _evict(self):
        cut = self.now - H24
        for d in (self.ipwin, self.acctwin):
            while d:
                k = next(iter(d))
                if d[k].wm >= cut:
                    break
                del d[k]

    def state_sizes(self):
        return {"users": len(self.users), "ips_windowed": len(self.ipwin),
                "accounts_windowed": len(self.acctwin), "ips_reputation": len(self.ip_rep),
                "asns": len(self.asn_rep), "population_nodes": len(self._G)}


def _s(v):
    if v is None:
        return ""
    if isinstance(v, float) and v != v:
        return ""
    return str(v).strip()


def _prune_ip(w, t):
    cut = t - H24
    ev = w.ev
    while ev and ev[0][0] < cut:
        _, failed, acct = ev.popleft()
        w.n -= 1
        if failed:
            w.f -= 1
        if acct < 0:
            w.ph -= 1
        else:
            c = w.accts[acct] - 1
            if c:
                w.accts[acct] = c
            else:
                del w.accts[acct]
    f1, cut1 = w.f1, t - H1
    while f1 and f1[0] < cut1:
        f1.popleft()


def _prune_acct(w, t):
    cut = t - H24
    ev = w.ev
    while ev and ev[0][0] < cut:
        _, failed, ip_i, ctry_i = ev.popleft()
        if failed:
            w.f -= 1
        c = w.ips[ip_i] - 1
        if c:
            w.ips[ip_i] = c
        else:
            del w.ips[ip_i]
        c = w.ctry[ctry_i] - 1
        if c:
            w.ctry[ctry_i] = c
        else:
            del w.ctry[ctry_i]
    f1, cut1 = w.f1, t - H1
    while f1 and f1[0] < cut1:
        f1.popleft()
