# backend/config.py
"""
Single source of truth for every detection threshold, ML cut-off, severity
and response policy value. The agents, the ML module, the explainer and the
API all import from here, and /api/config exposes public_config() to the
dashboard, so the UI can no longer drift from what the backend does.

Changing a value in the RULES, ML or SEVERITY sections changes detection or
response behaviour and therefore any published evaluation number; rerun the
evaluation (backend/eval/harness.py) after doing so.
"""

import os

try:   # RULES_MODE / ML_MODE etc. may be set in backend/.env (see .env.example)
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# ── Rules (agents/detection_agent.py) ──────────────────────────────────────
# Rule engine: "v3" (default since Phase 5) = the Phase 3 engine
# (agents/rules_v3.py, V3_* settings below) with the incident response tiers;
# "legacy" = the Phase 0-2 rules (agents/detection_agent.py
# LegacyDetectionAgent), kept unchanged and still selectable for the
# reproduction gate (eval/gate.py sets it explicitly). Override with the
# RULES_MODE environment variable. The legacy settings directly below apply
# to "legacy" only.
RULES_MODE = os.environ.get("RULES_MODE", "v3")

BRUTE_FORCE_THRESHOLD = 5              # lifetime FAILED events from one IP

SUSPICIOUS_HOUR_START = 0              # SUCCESS logins in [START:00, END:59]
SUSPICIOUS_HOUR_END = 5                # are flagged as off-hours
SUSPICIOUS_COOLDOWN_SECONDS = 600      # per IP, between off-hours alerts

MULTI_IP_WINDOW_SECONDS = 120          # same user, two IPs, within this window

SLOW_BF_WINDOW_SECONDS = 3600          # failures counted within this window
SLOW_BF_MIN_FAILURES = 4
SLOW_BF_MIN_SPREAD_MINUTES = 5
SLOW_BF_UNIQUE_USERS_BELOW = 3         # fires only if users tried from IP < this

CRED_STUFFING_MIN_USERS = 5            # distinct usernames seen from one IP
CRED_STUFFING_MIN_FAILURES = 5         # lifetime FAILED events from that IP

# ML re-alert throttle for FAILED events (ADR-17). 0 = always re-alert.
ML_REALERT_COOLDOWN_SECONDS = 0

# Skip ML scoring for internal addresses (ADR-17). Off by default.
INTERNAL_IP_GUARD_ENABLED = False
# RFC 1918 private ranges, checked with ipaddress (audit F37: the old string
# prefixes "10.0." and "172.16." covered only a /16 of 10/8 and 172.16/12).
INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

# ── v3 rules (agents/rules_v3.py; RULES_MODE = "v3") ──────────────────────
# Every window is a sliding window over event time, in seconds. "Failures"
# are FAILED logins against real accounts. Values chosen on val_a (dev_val,
# 30 Mar to 14 Apr 2020) under eval/PROTOCOL.md amendment 3 (see
# audit_scratch/PHASE3B_REPORT.md). Every v3 detector is alert-only.

# User IDs that stand for "no such account" (the RBA dataset's apparent
# pseudonym for unknown usernames, 37% of rows). Attempts on them never
# enter per-account state, never count as a distinct account, and are
# counted per IP for Invalid Account Spraying only.
UNKNOWN_ACCOUNT_IDS = ["-4324475583306591935"]

V3_BF_WINDOW_SECONDS = 60              # Brute Force: failures from one IP
V3_BF_MIN_FAILURES = 5

V3_SLOW_BF_WINDOW_SECONDS = 7 * 86400  # Slow Brute Force: failures from one
V3_SLOW_BF_MIN_FAILURES = 3            # IP over the longer window, spread
V3_SLOW_BF_MIN_SPREAD_SECONDS = 300    # out, below the Brute Force count

V3_CS_WINDOW_SECONDS = 7 * 86400       # Credential Stuffing: distinct real
V3_CS_MIN_ACCOUNTS = 2                 # accounts with FAILED logins, one IP

V3_INVALID_WINDOW_SECONDS = 7 * 86400  # Invalid Account Spraying: unknown-
V3_INVALID_MIN_ATTEMPTS = 3            # account attempts from one IP

V3_DIST_WINDOW_SECONDS = 2 * 86400     # Distributed Brute Force: distinct IPs
V3_DIST_MIN_IPS = 3                    # failing against one real account

V3_SAF_WINDOW_SECONDS = 7 * 86400      # Success After Failures: a SUCCESS with
V3_SAF_MIN_FAILURES = 3                # this many failures before it on the
                                       # account or from the IP

V3_MULTI_IP_WINDOW_SECONDS = 120       # Multiple IP Login (legacy rule)
# Pairs exempted: "known_ip" (second IP had a SUCCESS on the account within
# V3_KNOWN_IP_TTL_SECONDS), "same_prefix" (same /24 or /64), "same_asn".
V3_MULTI_IP_EXEMPT = ("known_ip",)     # fails the criterion (val_a 14.6%)
V3_KNOWN_IP_TTL_SECONDS = 30 * 86400

# Alert de-duplication per (detector, key): a match inside the cooldown
# after the last alert for the same key updates state but raises nothing.
# Keys: the IP, or (account, IP) for Distributed Brute Force, Success After
# Failures and Multiple IP Login. Suspicious Login Time keeps its legacy
# 600 s per-IP cooldown.
V3_DEDUP_SECONDS = {"default": 3600, "Suspicious Login Time": SUSPICIOUS_COOLDOWN_SECONDS}

# The same event delivered again within this many seconds is counted once
# (same event_id, or the same fields when the event has no id).
V3_DUPLICATE_WINDOW_SECONDS = 300

# v3 ML scorer: failed_rate per IP over the last N calendar days of event
# time (day buckets) instead of a lifetime counter (audit F20, F23).
ML_FAILED_RATE_WINDOW_DAYS = 30

# ── ML mode (Phase 4, eval/PROTOCOL.md amendment 4) ───────────────────────
# "v4" (default since Phase 5) = the Phase 4 design: no label-filtered model;
# with ML_V4_IFOREST "on", ml/model_v4.V4Scorer scores every event with the
# bundle at ML_V4_MODEL_PATH (never model.pkl) and, as the amendment 4
# fallback applied, raises no ML alert. Requires RULES_MODE = "v3".
# "legacy" = the Phase 2 Isolation Forest (data/model.pkl, unchanged,
# trained on label-filtered rows; results/README.md). Override with the
# ML_MODE environment variable.
ML_MODE = os.environ.get("ML_MODE", "v4")
ML_V4_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "model_v4.pkl")
# The v4 Isolation Forest (model_v4.pkl, Phase 4 fallback, alerting off).
# "retired" (eval/PROTOCOL.md amendment 6): the chosen triage score T2 reads
# the ASN prior failure ratio itself (agents/triage.AsnReputation), the
# forest makes no decision, so v4 runs no ML step and loads no model; the
# only v4 feature computed is the one the triage needs. "on" restores the
# Phase 4 behaviour (score every event, never alert).
ML_V4_IFOREST = "retired"

# ── ML (ml/anomaly_model.py, ml/train_from_dataset.py, main.py) ───────────
ML_CONTAMINATION = 0.4                     # deployed RBA model (ADR-13)
SYNTHETIC_FALLBACK_CONTAMINATION = 0.15    # main.py synthetic fallback
DEFAULT_CONTAMINATION = 0.05               # AnomalyDetector() constructor default

CONFIDENCE_HIGH_CUTOFF = -0.10             # decision_function < this -> "High"
CONFIDENCE_MEDIUM_CUTOFF = -0.02           # decision_function < this -> "Medium"

# Runtime alert margin: an event is anomalous only if predict() == -1 AND
# decision_function < ML_ALERT_MARGIN. -0.02 is the deployed value (it equals
# "confidence is High or Medium"); 0.0 reproduces the evaluated policy
# (predict() == -1 alone). See audit F09.
ML_ALERT_MARGIN = -0.02

# Optional integrity pin for data/model.pkl (audit F31). Loading a pickle
# runs code from it, so when MODEL_SHA256 is set the file's SHA-256 must
# match before it is unpickled.
MODEL_SHA256 = os.environ.get("MODEL_SHA256") or None

# ── Explainer (ml/explainer.py) ───────────────────────────────────────────
EXPLAINER_DEVIATION_FLAG = 1.5             # |z| above this marks a feature anomalous
EXPLAINER_STRONG_CUTOFF = -0.15            # score context: "strongly anomalous"

# ── Severity (agents/analysis_agent.py) ───────────────────────────────────
SEVERITY_MAP = {
    "Brute Force Attack":    "HIGH",
    "Multiple IP Login":     "HIGH",
    "Suspicious Login Time": "MEDIUM",
    "ML Anomaly Detected":   "MEDIUM",
    "Credential Stuffing":   "HIGH",
    "Slow Brute Force":      "HIGH",
}
DEFAULT_SEVERITY = "LOW"
# ML alerts with this confidence are raised to ML_UPGRADE_SEVERITY.
ML_UPGRADE_CONFIDENCE = "High"
ML_UPGRADE_SEVERITY = "HIGH"

MITRE_MAPPING = {
    "Brute Force Attack": {
        "technique_id":   "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
    },
    "Slow Brute Force": {
        "technique_id":   "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
    },
    "Credential Stuffing": {
        "technique_id":   "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/004/",
    },
    "Multiple IP Login": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "Suspicious Login Time": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "ML Anomaly Detected": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "Invalid Account Spraying": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/",
    },
    "Distributed Brute Force": {
        "technique_id":   "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic":         "Credential Access",
        "url":            "https://attack.mitre.org/techniques/T1110/001/",
    },
    "Success After Failures": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Initial Access",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
}

# An ML alert on a FAILED login is not use of a valid account; it is
# evidence of password guessing (audit F28).
MITRE_ML_FAILED = {
    "technique_id":   "T1110",
    "technique_name": "Brute Force",
    "tactic":         "Credential Access",
    "url":            "https://attack.mitre.org/techniques/T1110/",
}

# /api/threat-level considers alerts saved within this many minutes.
THREAT_LEVEL_WINDOW_MINUTES = 60

# ── Alert store (utils/alert_store_sqlite.py, v3) ─────────────────────────
# Alerts saved more than this many days ago (wall clock) are pruned, with
# the incidents left without alerts, on open and daily. 0 keeps everything.
ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", "30"))

# ── Response (agents/response_agent.py) ───────────────────────────────────
# Severities that trigger the (simulated) IP block and the email.
# In-memory history of response actions kept by ResponseAgent (audit F23).
ACTIONS_LOG_MAX = 1000
SIMULATED_BLOCK_SEVERITIES = ("HIGH",)
EMAIL_SEVERITIES = ("HIGH",)
ADMIN_NOTIFY_SEVERITIES = ("MEDIUM",)

# v3 response policy (RULES_MODE = "v3"): the incident tiers below
# (agents/triage.py, eval/PROTOCOL.md amendment 6). Blocking is a
# response-layer block list with a TTL in event time; detection never
# consults it. V3_BLOCK_DETECTORS (per-detector blocking, amendments 2-3) is
# superseded by the tiers and stays empty.
BLOCK_TTL_SECONDS = 3600
V3_BLOCK_DETECTORS = ()

# ── Incident triage and response tiers (agents/triage.py; RULES_MODE "v3") ─
# eval/PROTOCOL.md amendment 6. An incident is (source IP, calendar day);
# its score is TRIAGE_SCORE ("T0".."T3", agents/triage.py). Tiers are
# rate-based: a tier's cutoff on day d is the k-th highest final incident
# score of the previous day with incidents (k = RESPONSE_TIER_RATES[tier];
# 0 = the tier is off), and at most k incidents enter the tier per day, first
# come (amendment 7). Highest tier wins: block > step_up > queue > log.
# Chosen on val_a (results/phase5_selection.json): T2 = (detector tier,
# max ASN prior failure ratio). Block: no rate reached the 0.80 lower bound,
# so there is no block tier. Step-up (results/phase5b_selection.json): the
# rate with the most attacking IPs challenged whose band met 0.2149 with at
# most U = 200 legitimate users challenged per day on val_a.
TRIAGE_SCORE = "T2"
RESPONSE_TIER_RATES = {"block": 0, "step_up": 200, "queue": 500}
# val_a alert precision (point estimate) of each rule detector at its
# amendment 3 setting: the T0/T2 detector tier (results/phase3b_selection.json).
TRIAGE_DETECTOR_PRECISION = {
    "Brute Force Attack":       0.296875,
    "Slow Brute Force":         0.26303378128817795,
    "Credential Stuffing":      0.2734399587994621,
    "Invalid Account Spraying": 0.2312331060221457,
    "Distributed Brute Force":  0.25163256421419244,
    "Success After Failures":   0.24568661971830985,
    "Multiple IP Login":        0.1455357142857143,
    "Suspicious Login Time":    0.13086334010043807,
}
# T3 (logistic regression, dev_train incidents) parameters, if chosen.
TRIAGE_T3 = None
STEP_UP_TTL_SECONDS = 3600


def triage_t3_params():
    if TRIAGE_T3 is None:
        raise ValueError("TRIAGE_SCORE 'T3' needs TRIAGE_T3 parameters")
    return TRIAGE_T3


# Email for the v3 tiers: one per incident on entering an EMAIL_TIERS tier,
# at most one per IP per EMAIL_IP_COOLDOWN_SECONDS, at most
# EMAIL_MAX_PER_HOUR per clock hour of event time; the rest go into that
# hour's digest, sent when the hour closes.
EMAIL_TIERS = ("block", "step_up")
EMAIL_MAX_PER_HOUR = int(os.environ.get("EMAIL_MAX_PER_HOUR", "20"))
EMAIL_IP_COOLDOWN_SECONDS = int(os.environ.get("EMAIL_IP_COOLDOWN_SECONDS", "86400"))

# Severity of a v3 alert = its incident tier's (derived, not hand-set):
# the email tiers are HIGH, the analyst queue MEDIUM, log only LOW.
V3_SEVERITY_MAP = {tier: ("HIGH" if tier in EMAIL_TIERS else "MEDIUM" if tier == "queue" else "LOW")
                   for tier in ("block", "step_up", "queue", "log")}

# Incident precision of each tier measured on val_a (the deployed causal
# run, eval/phase5b.py `response`; 95% IP-clustered bootstrap interval) and
# the bar its rate was chosen against. Source: results/phase5b_response.json.
RESPONSE_TIER_VAL_A = {
    "block":   {"incidents": 0, "precision": None, "ci_low": None, "ci_high": None, "bar": 0.80},
    "step_up": {"incidents": 3143, "precision": 0.45529748647788737,
                "ci_low": 0.4267034165160253, "ci_high": 0.48310723715143405, "bar": 0.2149},
    "queue":   {"incidents": 7935, "precision": 0.2838059231253938,
                "ci_low": 0.265716433623392, "ci_high": 0.3032622786276811, "bar": None},
    "log":     {"incidents": 103866, "precision": 0.15971540253788535,
                "ci_low": 0.15331378609441376, "ci_high": 0.16633562562914908, "bar": None},
}


def response_policy_table():
    """The v3 policy table (tier, threshold, measured val_a precision)."""
    actions = {
        "block": f"block the IP for {BLOCK_TTL_SECONDS} s (simulated)",
        "step_up": f"step-up challenge (simulated MFA) for {STEP_UP_TTL_SECONDS} s, not enforced",
        "queue": "analyst queue",
        "log": "log only",
    }
    rows = []
    for tier in ("block", "step_up", "queue", "log"):
        k = RESPONSE_TIER_RATES.get(tier, 0)
        if tier == "log":
            threshold = "every incident below the tiers above"
        elif k:
            threshold = (f"running {TRIAGE_SCORE} score >= the {k}th highest final score "
                         f"of the previous day with incidents, first {k} incidents a day")
        else:
            threshold = "off: no rate met the bar on val_a"
        rows.append({"tier": tier, "enabled": bool(k) or tier == "log", "rate_per_day": k or None,
                     "threshold": threshold, "action": actions[tier],
                     "email": tier in EMAIL_TIERS, "severity": V3_SEVERITY_MAP[tier],
                     "val_a": dict(RESPONSE_TIER_VAL_A[tier])})
    return rows

# ── Email (utils/email_alerter.py) ────────────────────────────────────────
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465                            # implicit TLS (SMTP_SSL)
SMTP_TIMEOUT_SECONDS = 10                  # connect/read timeout per email

# ── LLM enrichment (utils/llm_analyzer.py) ────────────────────────────────
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "phi3:mini"
LLM_TIMEOUT_SECONDS = 300                  # per generate request
LLM_MAX_CONCURRENT = 2
LLM_SCAN_INTERVAL_SECONDS = 10
LLM_RECHECK_SECONDS = 60                   # re-check Ollama while unavailable
LLM_MAX_ATTEMPTS = 3                       # then the alert is marked failed
LLM_RETRY_AFTER_SECONDS = 60               # doubled after each failure

# ── API access (api.py) ───────────────────────────────────────────────────
# Browser origins allowed by CORS. Override with a comma-separated
# DASHBOARD_ORIGINS environment variable.
DASHBOARD_ORIGINS = tuple(
    o.strip() for o in os.environ.get(
        "DASHBOARD_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",") if o.strip()
)
# Secrets are read from the environment at request time, never stored here.
# ADMIN_TOKEN guards /api/run, clear/restore and queue clear (CLEAR_TOKEN is
# accepted as the older name). INGEST_TOKEN guards /api/ingest.
ADMIN_TOKEN_ENV = ("ADMIN_TOKEN", "CLEAR_TOKEN")
ADMIN_TOKEN_HEADERS = ("X-Admin-Token", "X-Clear-Token")
INGEST_TOKEN_ENV = ("INGEST_TOKEN",)
INGEST_TOKEN_HEADERS = ("X-Ingest-Token",)
RUN_MAX_DELAY_SECONDS = 5.0
RUN_THRESHOLD_RANGE = (1, 100)

# ── Live ingest (api.py /api/ingest, agents/monitoring_agent.py) ─────────
INGEST_MAX_BODY_BYTES = 16 * 1024          # Flask MAX_CONTENT_LENGTH
INGEST_MAX_FIELD_CHARS = {
    "user": 256,
    "ip": 64,
    "status": 16,
    "country": 64,
    "device_type": 64,
    "region": 128,
    "user_agent": 1024,
    "browser": 128,
    "os": 128,
}

DETECTORS = [
    "Suspicious Login Time",
    "Multiple IP Login",
    "Slow Brute Force",
    "Credential Stuffing",
    "Brute Force Attack",
    "ML Anomaly Detected",
]

V3_DETECTORS = [
    "Brute Force Attack",
    "Slow Brute Force",
    "Credential Stuffing",
    "Invalid Account Spraying",
    "Distributed Brute Force",
    "Success After Failures",
    "Multiple IP Login",
    "Suspicious Login Time",
    "ML Anomaly Detected",
]


def active_detectors():
    """The detectors of the configured engine (the ML step only if it runs)."""
    if RULES_MODE == "legacy":
        return list(DETECTORS)
    if ML_MODE == "v4" and ML_V4_IFOREST == "retired":
        return [d for d in V3_DETECTORS if d != "ML Anomaly Detected"]
    return list(V3_DETECTORS)


def public_config():
    """Read-only view served at /api/config. No secrets belong here."""
    return {
        "rules_mode": RULES_MODE,
        "ml_mode": ML_MODE,
        "ml_v4_iforest": ML_V4_IFOREST,
        "rules": {
            "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
            "suspicious_hour_start": SUSPICIOUS_HOUR_START,
            "suspicious_hour_end": SUSPICIOUS_HOUR_END,
            "suspicious_cooldown_seconds": SUSPICIOUS_COOLDOWN_SECONDS,
            "multi_ip_window_seconds": MULTI_IP_WINDOW_SECONDS,
            "slow_bf_window_seconds": SLOW_BF_WINDOW_SECONDS,
            "slow_bf_min_failures": SLOW_BF_MIN_FAILURES,
            "slow_bf_min_spread_minutes": SLOW_BF_MIN_SPREAD_MINUTES,
            "slow_bf_unique_users_below": SLOW_BF_UNIQUE_USERS_BELOW,
            "cred_stuffing_min_users": CRED_STUFFING_MIN_USERS,
            "cred_stuffing_min_failures": CRED_STUFFING_MIN_FAILURES,
            "ml_realert_cooldown_seconds": ML_REALERT_COOLDOWN_SECONDS,
            "internal_ip_guard_enabled": INTERNAL_IP_GUARD_ENABLED,
            "internal_networks": list(INTERNAL_NETWORKS),
        },
        "ml": {
            "contamination": ML_CONTAMINATION,
            "confidence_high_cutoff": CONFIDENCE_HIGH_CUTOFF,
            "confidence_medium_cutoff": CONFIDENCE_MEDIUM_CUTOFF,
            "alert_margin": ML_ALERT_MARGIN,
        },
        "severity": {
            "map": dict(SEVERITY_MAP),
            "default": DEFAULT_SEVERITY,
            "ml_upgrade_confidence": ML_UPGRADE_CONFIDENCE,
            "ml_upgrade_severity": ML_UPGRADE_SEVERITY,
        },
        "mitre": {k: dict(v) for k, v in MITRE_MAPPING.items()},
        "mitre_ml_failed": dict(MITRE_ML_FAILED),
        "threat_level_window_minutes": THREAT_LEVEL_WINDOW_MINUTES,
        "response": {
            "simulated_block_severities": list(SIMULATED_BLOCK_SEVERITIES),
            "email_severities": list(EMAIL_SEVERITIES),
            "admin_notify_severities": list(ADMIN_NOTIFY_SEVERITIES),
            "v3_policy": {
                "triage_score": TRIAGE_SCORE,
                "tier_rates": dict(RESPONSE_TIER_RATES),
                "table": response_policy_table(),
                "block_ttl_seconds": BLOCK_TTL_SECONDS,
                "step_up_ttl_seconds": STEP_UP_TTL_SECONDS,
                "email": {"tiers": list(EMAIL_TIERS), "max_per_hour": EMAIL_MAX_PER_HOUR,
                          "ip_cooldown_seconds": EMAIL_IP_COOLDOWN_SECONDS,
                          "over_limit": "hourly digest"},
            },
        },
        "detectors": active_detectors(),
        "v3": {
            "unknown_account_ids": list(UNKNOWN_ACCOUNT_IDS),
            "brute_force": {"window_s": V3_BF_WINDOW_SECONDS, "min_failures": V3_BF_MIN_FAILURES},
            "slow_brute_force": {"window_s": V3_SLOW_BF_WINDOW_SECONDS,
                                 "min_failures": V3_SLOW_BF_MIN_FAILURES,
                                 "min_spread_s": V3_SLOW_BF_MIN_SPREAD_SECONDS},
            "credential_stuffing": {"window_s": V3_CS_WINDOW_SECONDS,
                                    "min_accounts": V3_CS_MIN_ACCOUNTS},
            "invalid_account_spraying": {"window_s": V3_INVALID_WINDOW_SECONDS,
                                         "min_attempts": V3_INVALID_MIN_ATTEMPTS},
            "distributed_brute_force": {"window_s": V3_DIST_WINDOW_SECONDS,
                                        "min_ips": V3_DIST_MIN_IPS},
            "success_after_failures": {"window_s": V3_SAF_WINDOW_SECONDS,
                                       "min_failures": V3_SAF_MIN_FAILURES},
            "multiple_ip_login": {"window_s": V3_MULTI_IP_WINDOW_SECONDS,
                                  "exempt": list(V3_MULTI_IP_EXEMPT)},
            "dedup_seconds": dict(V3_DEDUP_SECONDS),
            "block_ttl_seconds": BLOCK_TTL_SECONDS,
            "block_detectors": list(V3_BLOCK_DETECTORS),
            "severity_by_tier": dict(V3_SEVERITY_MAP),
            "ml_failed_rate_window_days": ML_FAILED_RATE_WINDOW_DAYS,
        },
    }
