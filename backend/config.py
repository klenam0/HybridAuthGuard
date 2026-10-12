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

# ── Rules (agents/detection_agent.py) ──────────────────────────────────────
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
INTERNAL_IP_PREFIXES = ("192.168.", "10.0.", "172.16.")

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
        "tactic":         "Defense Evasion / Persistence",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "Suspicious Login Time": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Persistence",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
    "ML Anomaly Detected": {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Persistence",
        "url":            "https://attack.mitre.org/techniques/T1078/",
    },
}

# ── Response (agents/response_agent.py) ───────────────────────────────────
# Severities that trigger the (simulated) IP block and the email.
SIMULATED_BLOCK_SEVERITIES = ("HIGH",)
EMAIL_SEVERITIES = ("HIGH",)
ADMIN_NOTIFY_SEVERITIES = ("MEDIUM",)

DETECTORS = [
    "Suspicious Login Time",
    "Multiple IP Login",
    "Slow Brute Force",
    "Credential Stuffing",
    "Brute Force Attack",
    "ML Anomaly Detected",
]


def public_config():
    """Read-only view served at /api/config. No secrets belong here."""
    return {
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
        "response": {
            "simulated_block_severities": list(SIMULATED_BLOCK_SEVERITIES),
            "email_severities": list(EMAIL_SEVERITIES),
            "admin_notify_severities": list(ADMIN_NOTIFY_SEVERITIES),
        },
        "detectors": list(DETECTORS),
    }
