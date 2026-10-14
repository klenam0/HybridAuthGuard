# backend/agents/detection_agent.py
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime
from functools import lru_cache

import config

log = logging.getLogger(__name__)


_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in config.INTERNAL_NETWORKS)


@lru_cache(maxsize=65536)
def is_internal_ip(ip):
    """True if ip parses and falls inside config.INTERNAL_NETWORKS."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS if net.version == addr.version)


class LegacyDetectionAgent:
    """
    Reviewer-revision fixes applied here (see docs/DECISIONS.md, ADR-16 on
    the block-state split for Fixes A-B and ADR-17 on cooldown and the
    internal-IP guard for Fixes C-D):

      Fix A: removed a duplicate timestamp append that made Slow Brute
             Force fire at ~2 real failures instead of its documented 4+.
      Fix B: rule-confirmed blocks (rule_blocked_ips) and ML-flagged-once
             markers (ml_blocked_ips) are now tracked separately. Only
             rule_blocked_ips gates the FAILED-event block, so an ML
             alert on a SUCCESS event no longer silently stops rule-based
             failure counting for that same IP.
      Fix C: the ML re-alert throttle for FAILED events is now a
             configurable cooldown (ML_REALERT_COOLDOWN_SECONDS, default
             0 = always allowed to re-alert) instead of a permanent
             "once, ever" block. A validation-only sweep found shorter
             cooldowns strictly improve detection; 0 won outright.
      Fix D: the internal-IP guard (skip ML scoring for 192.168.x/
             10.0.x/172.16.x) is now gated by INTERNAL_IP_GUARD_ENABLED,
             default False. Testing found the guard, built for this
             project's own office network, costs real detection coverage
             (457 missed attacking IPs in testing) for no offsetting
             benefit against the RBA benchmark. Re-enable only after
             confirming it fits wherever this is actually deployed.
    """

    # Settled after reviewer-revision testing. Change these, not the
    # logic below, if a future revision needs different behaviour.
    ML_REALERT_COOLDOWN_SECONDS = config.ML_REALERT_COOLDOWN_SECONDS
    INTERNAL_IP_GUARD_ENABLED = config.INTERNAL_IP_GUARD_ENABLED

    def __init__(self, threshold=config.BRUTE_FORCE_THRESHOLD, anomaly_detector=None):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold
        self.rule_blocked_ips = set()   # Fix B: rule-confirmed blocks only
        self.ml_blocked_ips = set()     # Fix B: ML SUCCESS-event blocks, kept separate
        self.user_last_login = {}
        self.ip_attempt_times = defaultdict(list)
        self.anomaly_detector = anomaly_detector
        self.ip_users_tried = defaultdict(set)
        self.suspicious_last_fired = {}  # ip → last datetime it triggered suspicious time
        self.ml_last_alerted = {}        # Fix C: ip → timestamp of last FAILED-event ML alert

    def analyze_event(self, log_event):
        ip        = log_event["ip"]
        user      = log_event["user"]
        timestamp = datetime.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour      = timestamp.hour

        self.ip_users_tried[ip].add(user)

        # ── 1. Suspicious Login Time ───────────────────────────────────────
        start, end = config.SUSPICIOUS_HOUR_START, config.SUSPICIOUS_HOUR_END
        if log_event["status"] == "SUCCESS" and start <= hour <= end:
            last_fired = self.suspicious_last_fired.get(ip)
            cooldown   = config.SUSPICIOUS_COOLDOWN_SECONDS
            if last_fired is None or (timestamp - last_fired).total_seconds() > cooldown:
                self.suspicious_last_fired[ip] = timestamp
                return {
                    "type": "Suspicious Login Time",
                    "ip":   ip,
                    "user": user,
                    "description": f"User {user} logged in at unusual hour ({timestamp.strftime('%H:%M')})",
                    "trigger_details": {
                        "rule":      "Off-hours login detected",
                        "threshold": f"Logins between {start:02d}:00–{end:02d}:59 flagged",
                        "actual":    f"Login at {timestamp.strftime('%H:%M')} (hour {hour})",
                        "values":    {"login_hour": hour, "restricted_window": f"{start:02d}:00–{end:02d}:59"},
                    }
                }

        # ── 2. Multiple IP Login ───────────────────────────────────────────
        if log_event["status"] == "SUCCESS":
            prev = self.user_last_login.get(user)
            # Update FIRST so chain breaks after one alert fires
            self.user_last_login[user] = (ip, timestamp)

            if prev is not None:
                last_ip, last_time = prev
                time_diff = abs((timestamp - last_time).total_seconds())
                window = config.MULTI_IP_WINDOW_SECONDS
                if ip != last_ip and time_diff < window:
                    return {
                        "type": "Multiple IP Login",
                        "ip":   ip,
                        "user": user,
                        "description": (
                            f"User {user} logged in from {last_ip} and {ip} "
                            f"within {int(time_diff)} seconds"
                        ),
                        "trigger_details": {
                            "rule":      f"Same user authenticated from two IPs within {window // 60} minutes",
                            "threshold": f"Maximum {window} seconds between logins from different IPs",
                            "actual":    f"{user} logged from {last_ip} then {ip} within {int(time_diff)}s",
                            "values": {
                                "first_ip":    last_ip,
                                "second_ip":   ip,
                                "time_diff_s": int(time_diff),
                                "threshold_s": window,
                            },
                        }
                    }
           

        # ── 3, 4, 5 all inside one FAILED block ───────────────────────────
        # ── FAILED event processing — ORDER MATTERS ────────────────────────
        # Detectors run in this specific sequence:
        #   1. Slow Brute Force  — checked BEFORE fast brute force
        #      (needs time_spread_minutes >= 5 to distinguish from fast)
        #   2. Credential Stuffing — checked BEFORE fast brute force
        #      (needs unique_users >= 5 to distinguish from single-account BF)
        #   3. Fast Brute Force — catches anything remaining above threshold
        #
        # Changing this order will cause misclassification:
        #   - Credential stuffing will be caught as brute force
        #   - Slow brute force will fire on rapid attacks
        if log_event["status"] == "FAILED":
            # Fix B: gate only on rule-confirmed blocks, not ML's.
            if ip in self.rule_blocked_ips:
                return None

            # Fix A: track failure timestamps ONCE per event (this used to
            # append twice, once here and once more a few lines below,
            # making Slow Brute Force fire at ~2 real failures instead of
            # its documented 4+; the second append has been removed).
            self.ip_attempt_times[ip].append(timestamp)
            self.failed_attempts[ip] += 1
            unique_users = len(self.ip_users_tried[ip])
            log.debug("FAILED count for %s: %d | unique users: %d",
                      ip, self.failed_attempts[ip], unique_users)

           # ── 3. Slow Brute Force ────────────────────────────────────────
            # Checked BEFORE fast brute force and credential stuffing guards
            # unique_users_for_ip < 3 prevents misfiring on credential stuffing
            recent_failures = [
                t for t in self.ip_attempt_times[ip]
                if abs((timestamp - t).total_seconds()) <= config.SLOW_BF_WINDOW_SECONDS
            ]

            unique_users_for_ip = len(self.ip_users_tried[ip])

            time_spread_minutes = (
                (timestamp - recent_failures[0]).total_seconds() / 60
            ) if recent_failures else 0

            if (
                len(recent_failures) >= config.SLOW_BF_MIN_FAILURES
                and self.failed_attempts[ip] < self.threshold
                and time_spread_minutes >= config.SLOW_BF_MIN_SPREAD_MINUTES
                and unique_users_for_ip < config.SLOW_BF_UNIQUE_USERS_BELOW
            ):
                self.rule_blocked_ips.add(ip)
                return {
                    "type": "Slow Brute Force",
                    "ip":   ip,
                    "user": user,
                    "description": (
                        f"{len(recent_failures)} failed attempts from {ip} "
                        f"spread over {int(time_spread_minutes)} minutes — "
                        f"evasive brute force pattern"
                    ),
                    "trigger_details": {
                        "rule":      "Slow brute force evasion pattern",
                        "threshold": (f"{config.SLOW_BF_MIN_FAILURES}+ failures within "
                                      f"{config.SLOW_BF_WINDOW_SECONDS // 60} min, spread over "
                                      f"{config.SLOW_BF_MIN_SPREAD_MINUTES}+ min"),
                        "actual":    f"{len(recent_failures)} failures over {int(time_spread_minutes)} minutes from {ip}",
                        "values": {
                            "failure_count":        len(recent_failures),
                            "spread_minutes":       int(time_spread_minutes),
                            "min_spread_threshold": config.SLOW_BF_MIN_SPREAD_MINUTES,
                            "window_minutes":       config.SLOW_BF_WINDOW_SECONDS // 60,
                            "unique_users":         unique_users_for_ip,
                        },
                    }
                }

            # ── 4. Credential Stuffing ─────────────────────────────────────
            # Many different usernames from one IP
            if (unique_users >= config.CRED_STUFFING_MIN_USERS
                    and self.failed_attempts[ip] >= config.CRED_STUFFING_MIN_FAILURES):
                self.rule_blocked_ips.add(ip)
                total_ip  = self.failed_attempts[ip]
                return {
                    "type": "Credential Stuffing",
                    "ip": ip,
                    "user": user,
                    "description": (
                        f"IP {ip} attempted {unique_users} different usernames — "
                        f"consistent with automated credential stuffing"
                    ),
                    "trigger_details": {
                        "rule":      "Multiple unique usernames from single IP",
                        "threshold": f"{config.CRED_STUFFING_MIN_USERS}+ unique usernames with high failure rate",
                        "actual":    f"{unique_users} unique usernames tried from {ip}, {total_ip} total attempts",
                        "values":    {
                            "unique_usernames":    unique_users,
                            "total_attempts":      total_ip,
                            "unique_threshold":    config.CRED_STUFFING_MIN_USERS,
                        },
                    }
                }

            # ── 5. Fast Brute Force ────────────────────────────────────────
            if self.failed_attempts[ip] >= self.threshold:
                self.rule_blocked_ips.add(ip)
                return {
                    "type": "Brute Force Attack",
                    "ip": ip,
                    "user": user,
                    "description": (
                        f"{self.failed_attempts[ip]} failed login attempts "
                        f"detected from {ip}"
                    ),
                    "trigger_details": {
                        "rule":      "Rapid failed login threshold exceeded",
                        "threshold": f"{self.threshold} failed attempts triggers alert",
                        "actual":    f"{self.failed_attempts[ip]} failed attempts from {ip}",
                        "values":    {
                            "failed_count": self.failed_attempts[ip],
                            "threshold":    self.threshold,
                            "excess":       self.failed_attempts[ip] - self.threshold,
                        },
                    }
                }

        # ── 6. ML Anomaly ─────────────────────────────────────────────────
        if self.anomaly_detector:
            # Fix D: guard disabled by default (INTERNAL_IP_GUARD_ENABLED =
            # False). Re-enable only after confirming these address ranges
            # mean "trusted" wherever this is actually deployed.
            is_internal = self.INTERNAL_IP_GUARD_ENABLED and is_internal_ip(ip)
            if not is_internal:
                result = self.anomaly_detector.score_event(log_event)
                if result and result["is_anomaly"]:
                    is_failed_event = log_event.get("status") == "FAILED"

                    if is_failed_event:
                        # FAILED events: alert once per cooldown window but
                        # DO NOT block via rule_blocked_ips. Blocking would
                        # prevent rule-based detectors from accumulating the
                        # failure count they need to fire (Fix B).
                        # Fix C: ML_REALERT_COOLDOWN_SECONDS replaces the old
                        # permanent "alert once, ever" throttle. At the
                        # settled value of 0, this never suppresses a
                        # re-alert; raise it to reintroduce a cooldown.
                        last_alerted = self.ml_last_alerted.get(ip)
                        if (last_alerted is not None
                                and (timestamp - last_alerted).total_seconds()
                                < self.ML_REALERT_COOLDOWN_SECONDS):
                            return None
                        self.ml_last_alerted[ip] = timestamp
                        # Note: NOT adding to rule_blocked_ips here
                    else:
                        # SUCCESS events: alert once per IP. ml_blocked_ips
                        # records that this IP already produced an ML SUCCESS
                        # alert, and later ML SUCCESS alerts from it are
                        # suppressed. This is detection-side de-duplication,
                        # not a network block: the response layer's
                        # (simulated) block depends only on severity
                        # (config.SIMULATED_BLOCK_SEVERITIES). Fix B keeps it
                        # separate from rule_blocked_ips, so it never silences
                        # the FAILED-event rule checks above.
                        if ip in self.rule_blocked_ips or ip in self.ml_blocked_ips:
                            return None
                        self.ml_blocked_ips.add(ip)

                    feature_explanation = None
                    if hasattr(self.anomaly_detector, "explain_event"):
                        feature_explanation = self.anomaly_detector.explain_event(
                            log_event,
                            result["anomaly_score"],
                            result["confidence"]
                        )

                    return {
                        "type":                "ML Anomaly Detected",
                        "ip":                  ip,
                        "user":                user,
                        "anomaly_score":       result["anomaly_score"],
                        "confidence":          result["confidence"],
                        "feature_explanation": feature_explanation,
                        "description": (
                            f"Unusual login behaviour detected for user {user} "
                            f"from {ip}. "
                            f"Anomaly score: {result['anomaly_score']} "
                            f"(confidence: {result['confidence']}). "
                            + (feature_explanation["summary"]
                               if feature_explanation else "")
                        ),
                        "trigger_details": {
                            "rule": (
                                "Isolation Forest — FAILED event; rule-based failure counting continues for this IP"
                                if is_failed_event else
                                "Isolation Forest — SUCCESS event; later ML alerts on successful logins from this IP are suppressed"
                            ),
                            "threshold": (f"Score < {config.CONFIDENCE_HIGH_CUTOFF:.2f} = High, "
                                          f"< {config.CONFIDENCE_MEDIUM_CUTOFF:.2f} = Medium confidence"),
                            "actual":    f"Score {result['anomaly_score']} ({result['confidence']} confidence)",
                            "values": {
                                "anomaly_score":   result["anomaly_score"],
                                "confidence":      result["confidence"],
                                "is_failed_event": is_failed_event,
                                "suppresses_later_ml_success_alerts": not is_failed_event,
                            },
                        }
                    }

        return None

    def analyze_all(self, log_event):
        """The alerts for one event as a list (the legacy engine raises at
        most one). Same call shape as the v3 engine's analyze_all()."""
        alert = self.analyze_event(log_event)
        return [alert] if alert else []


def DetectionAgent(threshold=None, anomaly_detector=None, mode=None):
    """
    The rule engine selected by config.RULES_MODE (or mode):

      "legacy"  LegacyDetectionAgent above: the Phase 0-2 rules, unchanged,
                kept for the reproduction gate. threshold is its lifetime
                Brute Force count (default config.BRUTE_FORCE_THRESHOLD).
      "v3"      agents.rules_v3.V3DetectionAgent: windowed state, every
                detector and the ML step on every event (Phase 3). Its
                thresholds come from the V3_* settings in config.py;
                threshold is ignored. With config.ML_MODE = "v4" its ML
                step is ml.model_v4.V4Scorer (Phase 4).
    """
    mode = mode or config.RULES_MODE
    if mode == "legacy" and config.ML_MODE != "legacy":
        raise ValueError("ML_MODE 'v4' requires RULES_MODE 'v3'")
    if mode == "legacy":
        return LegacyDetectionAgent(
            threshold=config.BRUTE_FORCE_THRESHOLD if threshold is None else threshold,
            anomaly_detector=anomaly_detector)
    if mode == "v3":
        from agents.rules_v3 import V3DetectionAgent
        if config.ML_MODE == "v4":
            # Phase 4 ML step: causal features + the val_a choice. A scorer
            # passed in (replays, tests) is used as it is. Otherwise, with
            # the forest retired (amendment 6) there is no ML step.
            if anomaly_detector is None:
                if config.ML_V4_IFOREST == "on":
                    from ml.model_v4 import V4Scorer
                    anomaly_detector = V4Scorer.load(config.ML_V4_MODEL_PATH)
                elif config.ML_V4_IFOREST != "retired":
                    raise ValueError(f"unknown ML_V4_IFOREST {config.ML_V4_IFOREST!r}")
        elif config.ML_MODE != "legacy":
            raise ValueError(f"unknown ML_MODE {config.ML_MODE!r} (expected 'legacy' or 'v4')")
        return V3DetectionAgent(anomaly_detector=anomaly_detector)
    raise ValueError(f"unknown RULES_MODE {mode!r} (expected 'legacy' or 'v3')")
