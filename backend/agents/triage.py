# backend/agents/triage.py
"""
Incident triage and the graded response tiers (eval/PROTOCOL.md amendment 6).

An incident is (source IP, calendar day of event time). IncidentTriage keeps,
for the current day, every IP's event counts and the incidents opened by rule
alerts, and scores an incident each time one of its events carries alerts:

  observe(event, t)         every (non-duplicate) event, before its alerts:
                            the IP's FAILED / SUCCESS counts that day,
                            whether it targeted a config.UNKNOWN_ACCOUNT_IDS
                            account, and the maximum ASN prior failure ratio
  assess(event, t, types)   the event's rule alert types: updates the
                            incident and returns its running score and tier

Scores (higher = more urgent, compared as tuples):
  T0  (highest val_a alert precision of the incident's detectors, distinct
      detectors)                       amendment 3's budget score
  T1  (distinct detectors, max ASN failure ratio)
  T2  (highest val_a alert precision, max ASN failure ratio)
  T3  (linear predictor of the dev_train logistic regression,)

Tiers are rate-based and causal: for a daily rate k the cutoff on day d is
the k-th highest final score of the most recent earlier day that had
incidents (every incident qualifies if that day had fewer than k; none does
before the first day closes). Admission is capped (amendment 7): an
incident enters a tier at its first alerted event whose running score is
>= the tier's cutoff while fewer than k incidents have entered that tier
today, and stays there. Tiers admit from the top; an incident already in a
higher tier takes no slot of a lower one, and a used slot is not returned.
So a tier admits at most k incidents a day. The tier is the highest one
entered: block > step_up > queue > log.

Only the eight rule detectors (agents.rules_v3.RULE_DETECTORS) form
incidents; ML alerts are not part of the incident features.

IncidentNotifier sends one email per incident when it first enters an
email tier, with a per-IP cooldown and a global limit per event-time clock
hour; incidents over the limit go into that hour's digest, sent when the
hour closes. Everything runs on event time, so a replay is deterministic.
"""

import math

import config
from agents.rules_v3 import RULE_DETECTORS, normalize_account

SCORES = ("T0", "T1", "T2", "T3")
TIERS = ("block", "step_up", "queue", "log")
RATED_TIERS = ("block", "step_up", "queue")
T3_FEATURES = tuple(f"has[{d}]" for d in RULE_DETECTORS) + (
    "n_detectors", "log1p_alerts", "log1p_failed", "log1p_success",
    "placeholder_targeted", "max_asn_fail_ratio")
_BIT = {d: j for j, d in enumerate(RULE_DETECTORS)}

ALL = "all"        # cutoff: every incident qualifies
NONE = "none"      # cutoff: no incident qualifies (no completed day yet)


def _s(v):
    if v is None or (isinstance(v, float) and v != v):
        return ""
    return str(v).strip()


class AsnReputation:
    """Prior failure share per ASN over every earlier event: the same value
    as ml/features_v4 d_asn_fail_ratio (0.0 for an ASN's first event)."""

    def __init__(self):
        self.rep = {}

    def observe(self, event):
        asn = _s(event.get("asn"))
        r = self.rep.get(asn)
        if r is None:
            r = self.rep[asn] = [0, 0]
        ratio = r[1] / r[0] if r[0] else 0.0
        r[0] += 1
        if str(event.get("status", "")).strip().upper() == "FAILED":
            r[1] += 1
        return ratio


def t3_linear(x, params):
    """Linear predictor of the T3 model, accumulated feature by feature (the
    offline evaluation does the same operations column by column, so the
    results are bit-identical)."""
    z = params["intercept"]
    for xj, m, s, c in zip(x, params["mean"], params["scale"], params["coef"]):
        z += c * ((xj - m) / s)
    return z


class _IPDay:
    __slots__ = ("failed", "success", "placeholder", "asn_max")

    def __init__(self):
        self.failed = self.success = self.placeholder = 0
        self.asn_max = 0.0


class _Incident:
    __slots__ = ("mask", "alerts", "score", "regions", "tier")

    def __init__(self):
        self.mask = 0
        self.alerts = 0
        self.score = None
        self.regions = set()
        self.tier = "log"


class IncidentTriage:

    def __init__(self, score=None, rates=None, precision=None, t3=None, unknown_ids=None):
        self.score_name = score or config.TRIAGE_SCORE
        if self.score_name not in SCORES:
            raise ValueError(f"unknown TRIAGE_SCORE {self.score_name!r}")
        rates = dict(config.RESPONSE_TIER_RATES if rates is None else rates)
        self.rates = {t: int(rates.get(t) or 0) for t in RATED_TIERS}
        prec = config.TRIAGE_DETECTOR_PRECISION if precision is None else precision
        self.prec = [float(prec[d]) for d in RULE_DETECTORS]
        self.t3 = t3 if t3 is not None else (config.triage_t3_params()
                                            if self.score_name == "T3" else None)
        ids = config.UNKNOWN_ACCOUNT_IDS if unknown_ids is None else unknown_ids
        self.unknown = frozenset(normalize_account(u) for u in ids)
        self.asn = AsnReputation()
        self.day = None
        self.ipday = {}
        self.incidents = {}
        self.cutoffs = {t: NONE for t in RATED_TIERS}
        self.admitted = {t: 0 for t in RATED_TIERS}      # today's entries per tier
        self.days_closed = 0

    # ── per event ───────────────────────────────────────────────────────

    def observe(self, event, t):
        self._roll(t)
        ratio = self.asn.observe(event)
        ip = str(event.get("ip", "")).strip()
        d = self.ipday.get(ip)
        if d is None:
            d = self.ipday[ip] = _IPDay()
        status = str(event.get("status", "")).strip().upper()
        if status == "FAILED":
            d.failed += 1
        elif status == "SUCCESS":
            d.success += 1
        if normalize_account(event.get("user", "")) in self.unknown:
            d.placeholder = 1
        if ratio > d.asn_max:
            d.asn_max = ratio
        return ratio

    def assess(self, event, t, alert_types):
        """Update the event's incident with its rule alerts. Returns None if
        none of them is a rule detector, else the incident's state."""
        bits = 0
        n = 0
        for a in alert_types:
            j = _BIT.get(a)
            if j is not None:
                bits |= 1 << j
                n += 1
        if not n:
            return None
        self._roll(t)
        ip = str(event.get("ip", "")).strip()
        d = self.ipday.get(ip)
        if d is None:            # assess() without observe(): count nothing
            d = self.ipday[ip] = _IPDay()
        inc = self.incidents.get(ip)
        if inc is None:
            inc = self.incidents[ip] = _Incident()
        inc.mask |= bits
        inc.alerts += n
        inc.score = self.score(inc, d)
        before = inc.tier
        for tier in RATED_TIERS:                  # top down
            if tier in inc.regions:               # nothing below it can apply
                break
            k = self.rates[tier]
            if k and self.admitted[tier] < k and self._qualifies(inc.score, tier):
                inc.regions.add(tier)
                self.admitted[tier] += 1
                break
        inc.tier = next((x for x in RATED_TIERS if x in inc.regions), "log")
        return {"incident_id": f"{ip}|{self.day}", "ip": ip, "day": self.day,
                "score": list(inc.score), "tier": inc.tier, "previous_tier": before,
                "detectors": [x for j, x in enumerate(RULE_DETECTORS) if inc.mask >> j & 1],
                "alerts": inc.alerts}

    # ── scores ──────────────────────────────────────────────────────────

    def features(self, inc, d):
        """The T3 feature vector of an incident (T3_FEATURES order)."""
        ind = [float(inc.mask >> j & 1) for j in range(len(RULE_DETECTORS))]
        return ind + [float(bin(inc.mask).count("1")), math.log1p(inc.alerts),
                      math.log1p(d.failed), math.log1p(d.success),
                      float(d.placeholder), d.asn_max]

    def score(self, inc, d):
        n_det = bin(inc.mask).count("1")
        name = self.score_name
        if name == "T1":
            return (n_det, d.asn_max)
        if name == "T3":
            return (t3_linear(self.features(inc, d), self.t3),)
        top = max(p for j, p in enumerate(self.prec) if inc.mask >> j & 1)
        return (top, n_det) if name == "T0" else (top, d.asn_max)

    # ── days and cutoffs ────────────────────────────────────────────────

    def _qualifies(self, score, tier):
        c = self.cutoffs[tier]
        return c == ALL or (c != NONE and score >= c)

    def _roll(self, t):
        day = t // 86400
        if self.day is None:
            self.day = day
        elif day > self.day:       # earlier days (late events) count as today
            self._close_day()
            self.day = day

    def _close_day(self):
        finals = sorted((inc.score for inc in self.incidents.values()), reverse=True)
        if finals:
            for tier, k in self.rates.items():
                if k:
                    self.cutoffs[tier] = finals[k - 1] if len(finals) >= k else ALL
            self.days_closed += 1
        self.ipday = {}
        self.incidents = {}
        self.admitted = {t: 0 for t in RATED_TIERS}

    def state_sizes(self):
        return {"ips_today": len(self.ipday), "incidents_today": len(self.incidents),
                "asns": len(self.asn.rep), "days_closed": self.days_closed}


class IncidentNotifier:
    """One email per incident for the email tiers, per-IP cooldown, a global
    limit per clock hour of event time, and an hourly digest for the rest."""

    def __init__(self, alerter, max_per_hour=None, cooldown=None, tiers=None):
        self.alerter = alerter
        self.max_per_hour = config.EMAIL_MAX_PER_HOUR if max_per_hour is None else max_per_hour
        self.cooldown = config.EMAIL_IP_COOLDOWN_SECONDS if cooldown is None else cooldown
        self.tiers = tuple(config.EMAIL_TIERS if tiers is None else tiers)
        self.last_ip = {}
        self.hour = None
        self.sent_this_hour = 0
        self.digest = []
        self.digest_hour = None
        self.log = []            # (kind, hour, incident ids, outcome)

    def wants(self, incident):
        return (incident is not None and incident["tier"] in self.tiers
                and incident["previous_tier"] not in self.tiers)

    def notify(self, incident, t):
        """Returns the outcome: sent, failed, disabled, digest or cooldown."""
        self.flush(t)
        ip = incident["ip"]
        last = self.last_ip.get(ip)
        if last is not None and t - last < self.cooldown:
            self.log.append(("cooldown", t // 3600, [incident["incident_id"]], "cooldown"))
            return "cooldown"
        self.last_ip[ip] = t
        if len(self.last_ip) > 65536:
            self.last_ip = {k: v for k, v in self.last_ip.items() if t - v < self.cooldown}
        h = t // 3600
        if h != self.hour:
            self.hour, self.sent_this_hour = h, 0
        if self.sent_this_hour < self.max_per_hour:
            self.sent_this_hour += 1
            if not getattr(self.alerter, "enabled", True):
                outcome = "disabled"
            else:
                outcome = "sent" if self.alerter.send_incident(incident) else "failed"
            self.log.append(("email", h, [incident["incident_id"]], outcome))
            return outcome
        self.digest.append(incident)
        self.digest_hour = h
        return "digest"

    def flush(self, t=None):
        """Send the pending digest once its hour has closed (t=None: now)."""
        if not self.digest or (t is not None and t // 3600 <= self.digest_hour):
            return None
        items, hour = self.digest, self.digest_hour
        self.digest, self.digest_hour = [], None
        if not getattr(self.alerter, "enabled", True):
            outcome = "disabled"
        else:
            outcome = "sent" if self.alerter.send_digest(hour, items) else "failed"
        self.log.append(("digest", hour, [i["incident_id"] for i in items], outcome))
        return outcome
