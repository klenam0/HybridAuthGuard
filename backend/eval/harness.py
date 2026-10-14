# backend/eval/harness.py
"""
Evaluation harness that replays a time-sorted event stream through the REAL
pipeline objects: DetectionAgent (rules + ML gating), AnalysisAgent (severity
and MITRE) and ResponseAgent (response policy). Email and persistence are
stubbed; nothing is sent and nothing is written.

The ML step takes an injected scorer, which DetectionAgent sees as its
anomaly_detector (it only calls score_event() and explain_event()):

  LiveScorer         the deployed AnomalyDetector, one event at a time.
  PrecomputedScorer  the same model, scored in one batch from features built
                     causally over exactly the events the live agent would
                     score, with the same failed_rate counter semantics.

Why PrecomputedScorer is exact rather than an approximation: whether an
event reaches score_event() depends only on rule state (suspicious_last_fired,
user_last_login, rule_blocked_ips, failure counts) and the internal-IP guard,
none of which the ML branch writes. A dry pass with a recording stub therefore
finds the same events, in the same order, that a live run scores. Runtime
failed_rate counters only advance on those events, so the batch features use
cumulative counts over that subset. replay() asserts the order matches.
"""

import contextlib
import io
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

import config
from agents.analysis_agent import AnalysisAgent
from agents.detection_agent import DetectionAgent
from agents.response_agent import ResponseAgent

TS_FMT = "%Y-%m-%d %H:%M:%S"


class NullEmailAlerter:
    """Records what would have been emailed."""

    enabled = True

    def __init__(self):
        self.sent = []

    def send_alert(self, alert):
        self.sent.append(alert.get("alert_id"))
        return True

    def send_incident(self, incident):
        self.sent.append(incident.get("incident_id"))
        return True

    def send_digest(self, hour, incidents):
        self.sent.append(("digest", hour, len(incidents)))
        return True


# ── Scorers ──────────────────────────────────────────────────────────────────

class LiveScorer:
    """Delegates to the deployed AnomalyDetector, one event at a time."""

    def __init__(self, detector):
        self.detector = detector
        self.calls = []          # (event_key, result) per score_event call

    def prepare(self, events):
        return self

    def score_event(self, log_event):
        r = self.detector.score_event(log_event)
        self.calls.append((event_key(log_event), r))
        return r

    def explain_event(self, log_event, anomaly_score, confidence):
        return self.detector.explain_event(log_event, anomaly_score, confidence)


class _RecordingStub:
    """Dry-pass anomaly_detector: records which events reach score_event()."""

    def __init__(self):
        self.reached = []

    def score_event(self, log_event):
        self.reached.append(log_event)
        return {"is_anomaly": False, "anomaly_score": 0.0,
                "confidence": "Low", "feature_count": 10}


class PrecomputedScorer:
    """Batch-scores, from causally built features, the events a live run scores."""

    def __init__(self, detector, threshold=config.BRUTE_FORCE_THRESHOLD):
        if detector.encoding_scheme != "frequency":
            raise ValueError("PrecomputedScorer supports frequency-encoded models only")
        self.detector = detector
        self.threshold = threshold
        self.keys = []
        self.raw = None          # (n, 10) unscaled features, row i = i-th scored event
        self.pred = None
        self.decision = None
        self._i = 0
        self.calls = []

    def prepare(self, events):
        stub = _RecordingStub()
        agent = DetectionAgent(threshold=self.threshold, anomaly_detector=stub,
                               mode="legacy")
        with contextlib.redirect_stdout(io.StringIO()):
            for e in events:
                agent.analyze_event(dict(e))
        reached = stub.reached
        self.keys = [event_key(e) for e in reached]
        self.raw = build_features(reached, self.detector)
        d = self.detector
        X = d.scaler.transform(self.raw) if d.scaler is not None else self.raw
        self.decision = d.model.decision_function(X)
        self.pred = np.where(self.decision < 0, -1, 1)   # == model.predict(X)
        self._i = 0
        return self

    def score_event(self, log_event):
        i = self._i
        if i >= len(self.keys) or self.keys[i] != event_key(log_event):
            raise RuntimeError(
                f"PrecomputedScorer out of step at scored event {i}: the replay "
                f"reached an event the dry pass did not predict")
        self._i += 1
        r = self.detector.classify_score(self.pred[i], self.decision[i])
        self.calls.append((self.keys[i], r))
        return r

    def explain_event(self, log_event, anomaly_score, confidence):
        if self.detector.explainer is None:
            return None
        return self.detector.explainer.explain(
            self.raw[self._i - 1:self._i], anomaly_score, confidence)


def event_key(e):
    return (e.get("timestamp"), e.get("ip"), e.get("user"), e.get("status"))


def build_features(events, detector):
    """
    Vectorised counterpart of AnomalyDetector._extract_features_v2_frequency()
    for the events that reach score_event(), in order. failed_rate is the
    inclusive cumulative per-IP rate over these events only, which is what the
    runtime counters hold (they advance inside score_event()).
    """
    n = len(events)
    if n == 0:
        return np.zeros((0, 10), dtype=np.float64)
    ts = pd.Series([e.get("timestamp") for e in events])
    hour = pd.to_datetime(ts, format=TS_FMT, errors="coerce").dt.hour
    hour = hour.fillna(12).astype(np.int64).to_numpy()
    ip = pd.Series([str(e.get("ip", "0.0.0.0")).strip() for e in events])
    user = [str(e.get("user", "unknown")).strip() for e in events]
    country = [str(e.get("country", "XX")).strip() for e in events]
    device = [str(e.get("device_type", "Unknown")).strip() for e in events]
    is_failed = np.array([1 if e.get("status", "SUCCESS") == "FAILED" else 0
                          for e in events], dtype=np.int64)

    fail_cum = pd.Series(is_failed).groupby(ip).cumsum().to_numpy()
    total_cum = ip.groupby(ip).cumcount().to_numpy() + 1
    failed_rate = fail_cum / total_cum

    d = detector
    out = np.empty((n, 10), dtype=np.float64)
    for i in range(n):
        h = hour[i]
        out[i, 0] = np.sin(2 * np.pi * h / 24)
        out[i, 1] = np.cos(2 * np.pi * h / 24)
    out[:, 2] = is_failed
    out[:, 3] = [d.ip_freq_map.get(x, 0.0) for x in ip]
    out[:, 4] = [d.user_freq_map.get(x, 0.0) for x in user]
    out[:, 5] = failed_rate
    out[:, 6] = [d.country_freq_map.get(x, 0.0) for x in country]
    out[:, 7] = [d.device_freq_map.get(x, 0.0) for x in device]
    out[:, 8] = [int(x not in d.known_ips_set) for x in ip]
    out[:, 9] = [int(x not in d.known_countries_set) for x in country]
    return out


# ── Replay ───────────────────────────────────────────────────────────────────

@dataclass
class ReplayResult:
    n_events: int
    alert_type: list            # per event: alert type or None
    severity: list              # per event: severity or None
    confidence: list            # per event: ML confidence on ML alerts, else None
    ml_scored: np.ndarray       # per event: reached score_event()
    rule_block_idx: dict        # ip -> event index it entered rule_blocked_ips
    ml_block_idx: dict          # ip -> event index it entered ml_blocked_ips
    response_block_idx: dict    # ip -> event index of its first simulated block
    emails: int
    scorer_calls: list = field(default_factory=list)

    @property
    def flagged(self):
        return np.array([t is not None for t in self.alert_type], dtype=bool)


def replay(events, scorer=None, threshold=config.BRUTE_FORCE_THRESHOLD):
    """The legacy engine needs legacy ML mode, whatever the defaults are."""
    with override_config(ML_MODE="legacy"):
        return _replay(events, scorer, threshold)


def _replay(events, scorer=None, threshold=config.BRUTE_FORCE_THRESHOLD):
    """
    Run events (dicts with timestamp/user/ip/status[/country/device_type],
    already time-sorted) through the real agents. scorer=None runs rules only.
    Always the legacy rule engine (config.RULES_MODE "legacy"); the v3
    engine is replayed by eval/rules_v3_replay.py.
    """
    if scorer is not None:
        scorer.prepare(events)
    agent = DetectionAgent(threshold=threshold, anomaly_detector=scorer, mode="legacy")
    analysis = AnalysisAgent(mode="legacy")
    email = NullEmailAlerter()
    response = ResponseAgent(email_alerter=email, mode="legacy")

    n = len(events)
    types, sevs, confs = [None] * n, [None] * n, [None] * n
    scored = np.zeros(n, dtype=bool)
    rule_idx, ml_idx, resp_idx = {}, {}, {}
    calls_before = 0

    with contextlib.redirect_stdout(io.StringIO()) as sink:
        for i, e in enumerate(events):
            ip = e.get("ip")
            alert = agent.analyze_event(dict(e))
            if scorer is not None:
                scored[i] = len(scorer.calls) > calls_before
                calls_before = len(scorer.calls)
            if alert:
                alert["timestamp"] = e.get("timestamp")
                analyzed = analysis.evaluate_alert(alert)
                response.take_action(analyzed)
                types[i] = analyzed["type"]
                sevs[i] = analyzed["severity"]
                confs[i] = analyzed.get("confidence")
                if (analyzed["severity"] in config.SIMULATED_BLOCK_SEVERITIES
                        and ip not in resp_idx):
                    resp_idx[ip] = i
            if ip not in rule_idx and ip in agent.rule_blocked_ips:
                rule_idx[ip] = i
            if ip not in ml_idx and ip in agent.ml_blocked_ips:
                ml_idx[ip] = i
            if i % 2000 == 0:            # keep the captured output small
                sink.seek(0)
                sink.truncate()
        response.actions_log.clear()

    if isinstance(scorer, PrecomputedScorer) and scorer._i != len(scorer.keys):
        raise RuntimeError(f"PrecomputedScorer: {len(scorer.keys) - scorer._i} "
                           f"precomputed events were never requested")
    return ReplayResult(n, types, sevs, confs, scored, rule_idx, ml_idx, resp_idx,
                        len(email.sent), scorer.calls if scorer is not None else [])


# ── Metrics ──────────────────────────────────────────────────────────────────

def summarize(result, events, truth):
    """Detection, alert-quality and blocking metrics against ground truth."""
    truth = np.asarray(truth, dtype=bool)
    flagged = result.flagged
    ips = [e["ip"] for e in events]
    users = [e["user"] for e in events]

    per_ip = defaultdict(bool)
    for ip, f, t in zip(ips, flagged, truth):
        if t:
            per_ip[ip] |= bool(f)

    breakdown = Counter()
    for t, s, c, a in zip(result.alert_type, result.severity, result.confidence, truth):
        if t:
            label = f"{t} | {s}" + (f" | {c}" if c else "")
            breakdown[(label, "attack" if a else "benign")] += 1

    attack_ips = {ip for ip, t in zip(ips, truth) if t}
    benign_ips = {ip for ip, t in zip(ips, truth) if not t} - attack_ips

    def block_cost(block_idx):
        blocked_benign = {ip for ip in block_idx if ip in benign_ips}
        after = [i for i, (ip, t) in enumerate(zip(ips, truth))
                 if not t and ip in block_idx and i > block_idx[ip]]
        return {
            "benign_ips_blocked": len(blocked_benign),
            "attack_ips_blocked": len({ip for ip in block_idx if ip in attack_ips}),
            "benign_events_after_block": len(after),
            "benign_successes_after_block": sum(
                1 for i in after if events[i]["status"] == "SUCCESS"),
            "benign_users_affected": len({users[i] for i in after}),
        }

    suppression = {**result.rule_block_idx}
    for ip, i in result.ml_block_idx.items():
        suppression[ip] = min(i, suppression.get(ip, i))

    return {
        "events": int(len(events)),
        "attack_events": int(truth.sum()),
        "benign_events": int((~truth).sum()),
        "attacking_ips": len(per_ip),
        "benign_ips": len(benign_ips),
        "benign_users": len({u for u, t in zip(users, truth) if not t}),
        "ml_scored_events": int(result.ml_scored.sum()),
        "alerts": int(flagged.sum()),
        "event_recall": float(flagged[truth].mean()) if truth.any() else 0.0,
        "campaign_recall": float(np.mean(list(per_ip.values()))) if per_ip else 0.0,
        "fpr": float(flagged[~truth].mean()) if (~truth).any() else 0.0,
        "precision": float(truth[flagged].mean()) if flagged.any() else 0.0,
        "emails": result.emails,
        "breakdown": {f"{k[0]} [{k[1]}]": v for k, v in sorted(breakdown.items())},
        "detector_suppression": block_cost(suppression),
        "response_blocks": block_cost(result.response_block_idx),
    }


@contextlib.contextmanager
def override_config(**values):
    """Temporarily set config attributes (e.g. ML_ALERT_MARGIN=0.0)."""
    old = {k: getattr(config, k) for k in values}
    try:
        for k, v in values.items():
            setattr(config, k, v)
        yield
    finally:
        for k, v in old.items():
            setattr(config, k, v)
