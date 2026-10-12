# backend/ml/explainer.py
"""
Feature-level explainability for Isolation Forest predictions.

Uses the fitted StandardScaler to compute how many standard deviations
each feature deviates from the normal training baseline.
Features with high deviation are the primary drivers of the anomaly flag.

This is mathematically grounded explainability - no black box,
no additional libraries required beyond what is already installed.

Value descriptions match the settled frequency-encoded feature scheme
(anomaly_model._extract_features_v2_frequency): IP, user, country and
device are the share of training logins with that exact value, and 0.0
means the value never appeared in the 561,464-event training partition.
"""

import numpy as np

import config


TRAINING_EVENTS = "561,464"

# Human-readable labels for each feature position
FEATURE_LABELS = {
    0: "Login hour (sin)",
    1: "Login hour (cos)",
    2: "Login failure",
    3: "Source IP",
    4: "User account",
    5: "IP failure rate",
    6: "Country",
    7: "Device type",
    8: "New/unknown IP",
    9: "New/unknown country",
}


def _freq_desc(entity):
    """Description for a frequency-encoded identity feature."""
    def describe(v, mean, std):
        if v <= 0:
            return f"{entity} never seen in the {TRAINING_EVENTS} training logins"
        return f"{entity} seen in {v:.4%} of training logins"
    return describe


# What each feature value means in plain English
FEATURE_DESCRIPTIONS = {
    0: lambda v, mean, std: (
        f"Cyclic hour component (sin): {v:.3f} - "
        + ("late night / early morning pattern" if v < -0.5
           else "business hours pattern" if v > 0.5
           else "transition hour pattern")
    ),
    1: lambda v, mean, std: (
        f"Cyclic hour component (cos): {v:.3f} - "
        + ("midnight / noon alignment" if abs(v) > 0.8
           else "morning / evening alignment")
    ),
    2: lambda v, mean, std: (
        "Login failed" if v == 1 else "Login succeeded"
    ),
    3: _freq_desc("Source IP"),
    4: _freq_desc("User account"),
    5: lambda v, mean, std: (
        f"{v:.1%} cumulative failure rate from this IP"
    ),
    6: _freq_desc("Country"),
    7: _freq_desc("Device type"),
    8: lambda v, mean, std: (
        f"IP address was NEVER seen in the {TRAINING_EVENTS} normal training logins - strong anomaly signal"
        if v == 1 else "IP address seen in training data (known)"
    ),
    9: lambda v, mean, std: (
        f"Country was NEVER seen in the {TRAINING_EVENTS} normal training logins - strong anomaly signal"
        if v == 1 else "Country seen in training data (known)"
    ),
}


class AlertExplainer:
    """
    Explains why the Isolation Forest flagged a specific event
    by computing per-feature standard deviation scores against
    the normal training baseline captured in the StandardScaler.
    """

    def __init__(self, scaler):
        """
        Args:
            scaler: fitted StandardScaler from model.pkl
                    contains mean_ and scale_ from normal training data
        """
        self.scaler = scaler
        self.means  = scaler.mean_    # normal baseline per feature
        self.stds   = scaler.scale_   # normal spread per feature

    def explain(self, raw_features, anomaly_score, confidence):
        """
        Explain a flagged event by computing feature deviations.

        Args:
        raw_features: numpy array of shape (1, 10) - unscaled 10-feature vector
        anomaly_score: float from model.decision_function()
        confidence: str - "High", "Medium", or "Low"

        Returns:
            dict with:
              - contributions: list of feature dicts sorted by deviation
              - anomaly_score: float
              - confidence: str
              - summary: one-sentence plain English summary
              - score_context: explanation of what the score means
        """
        features = raw_features.flatten()
        n        = len(features)

        contributions = []
        for i in range(min(n, len(self.means))):
            raw_val   = features[i]
            mean      = self.means[i]
            std       = self.stds[i] if self.stds[i] > 0 else 1.0
            deviation = abs(raw_val - mean) / std

            # Get human-readable value description
            desc_fn = FEATURE_DESCRIPTIONS.get(i)
            value_str = desc_fn(raw_val, mean, std) if desc_fn else str(raw_val)

            contributions.append({
                "feature_index": i,
                "feature_label": FEATURE_LABELS.get(i, f"Feature {i}"),
                "raw_value":     float(raw_val),
                "normal_mean":   float(mean),
                "normal_std":    float(std),
                "deviation":     float(deviation),
                "value_display": value_str,
                "is_anomalous":  bool(deviation > config.EXPLAINER_DEVIATION_FLAG),
            })

        # Sort by deviation - most anomalous features first
        contributions.sort(key=lambda x: x["deviation"], reverse=True)

        # Build a plain-English summary from the top anomalous features
        anomalous = [c for c in contributions if c["is_anomalous"]]
        summary   = self._build_summary(anomalous, anomaly_score, confidence)

        # Score context
        if anomaly_score < config.EXPLAINER_STRONG_CUTOFF:
            score_context = (
                f"Score {anomaly_score:.4f} indicates a strongly anomalous pattern - "
                f"this event is far outside the normal login behaviour baseline."
            )
        elif anomaly_score < config.CONFIDENCE_HIGH_CUTOFF:
            score_context = (
                f"Score {anomaly_score:.4f} indicates a clearly anomalous pattern - "
                f"this event deviates significantly from normal behaviour."
            )
        else:
            score_context = (
                f"Score {anomaly_score:.4f} indicates a moderately anomalous pattern - "
                f"this event is unusual but not extreme."
            )

        return {
            "contributions": contributions,
            "anomaly_score": float(anomaly_score),
            "confidence": str(confidence),
            "summary": str(summary),
            "score_context": str(score_context),
            "anomalous_count": int(len(anomalous)),
            "total_features": int(n),
        }

    def _build_summary(self, anomalous_features, score, confidence):
        """Build a one-sentence plain English summary of why the event was flagged."""
        if not anomalous_features:
            return (
                f"This event was flagged with {confidence.lower()} confidence "
                f"(score: {score:.4f}) based on a combination of subtle deviations "
                f"across multiple features."
            )

        top = anomalous_features[:3]
        parts = []
        for f in top:
            parts.append(
                f"{f['feature_label']} ({f['value_display']}, "
                f"{f['deviation']:.1f}σ from normal)"
            )

        return (
            f"Flagged with {confidence.lower()} confidence (score: {score:.4f}) "
            f"primarily due to: {'; '.join(parts)}."
        )
