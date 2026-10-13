# backend/agents/analysis_agent.py

import uuid
from datetime import datetime

import config


class AnalysisAgent:
    """
    Enriches raw alerts with:
    - Severity classification
    - MITRE ATT&CK mapping
    - Alert ID and timestamp
    - LLM-generated or template explanation
    - Feature-level ML explainability (for ML Anomaly alerts)
    """

    def __init__(self, llm_analyzer=None):
        self.llm_analyzer = llm_analyzer

        self.severity_mapping = config.SEVERITY_MAP
        self.mitre_mapping    = config.MITRE_MAPPING

    def evaluate_alert(self, alert):
        alert = alert.copy()  
        alert_type = alert.get("type", "Unknown Threat")
        severity   = self.severity_mapping.get(alert_type, config.DEFAULT_SEVERITY)

        # Upgrade ML anomaly severity if model confidence is High
        if alert_type == "ML Anomaly Detected":
            if alert.get("confidence") == config.ML_UPGRADE_CONFIDENCE:
                severity = config.ML_UPGRADE_SEVERITY

        alert["severity"]    = severity
        alert["alert_id"]    = str(uuid.uuid4()).upper()   # full UUID (audit F38)
        alert["detected_at"] = alert.get(
            "timestamp",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        # MITRE ATT&CK mapping. ML alerts on FAILED logins map to T1110.
        mitre = self.mitre_mapping.get(alert_type)
        values = (alert.get("trigger_details") or {}).get("values") or {}
        if alert_type == "ML Anomaly Detected" and values.get("is_failed_event"):
            mitre = config.MITRE_ML_FAILED
        if mitre:
            alert["mitre"] = mitre

        # Get feature explanation for ML alerts
        feature_explanation = alert.pop("feature_explanation", None)

        # Generate explanation — LLM if available, template if not
        if self.llm_analyzer:
            alert["explanation"] = self.llm_analyzer.generate_explanation(
                alert, feature_explanation
            )
        else:
            alert["explanation"] = self._template_explanation(alert)

        # Attach feature explanation to alert for dashboard transparency
        if feature_explanation:
            alert["feature_explanation"] = {
                "summary":       feature_explanation.get("summary", ""),
                "score_context": feature_explanation.get("score_context", ""),
                "contributions": feature_explanation.get("contributions", []),
                "anomalous_count": feature_explanation.get("anomalous_count", 0),
            }

        return alert

    def _template_explanation(self, alert):
        """Template fallback when LLM is not available."""
        t    = alert.get("type",        "Unknown")
        user = alert.get("user",        "unknown")
        ip   = alert.get("ip",          "unknown")
        desc = alert.get("description", "")

        templates = {
            "Brute Force Attack": (
                f"HIGH: Repeated failed logins from {ip} indicate an automated "
                f"brute force attack targeting '{user}'. "
                f"A simulated block is recorded for this IP (nothing is enforced in this prototype)."
            ),
            "Slow Brute Force": (
                f"HIGH: IP {ip} is making deliberate slow-paced login attempts "
                f"against '{user}', staying below rapid-detection thresholds. "
                f"This is a known evasion technique. Details: {desc}"
            ),
            "Multiple IP Login": (
                f"HIGH: '{user}' authenticated from multiple IPs in rapid succession. "
                f"Possible stolen credentials or active session hijacking. "
                f"Details: {desc}"
            ),
            "Suspicious Login Time": (
                f"MEDIUM: '{user}' logged in from {ip} during off-hours. "
                f"May be legitimate but warrants admin review. "
                f"Details: {desc}"
            ),
            "ML Anomaly Detected": (
                f"ML DETECTION: Isolation Forest flagged unusual behaviour for "
                f"'{user}' from {ip}. Score: {alert.get('anomaly_score', 'N/A')} "
                f"(confidence: {alert.get('confidence', 'N/A')}). "
                f"Review recommended."
            ),
            "Credential Stuffing": (
                f"HIGH: {ip} attempted logins across multiple accounts. "
                f"Consistent with automated credential stuffing. Details: {desc}"
            ),
        }
        return templates.get(
            t, f"{alert.get('severity','LOW')} alert for '{user}' from {ip}. {desc}"
        )