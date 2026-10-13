# backend/ml/anomaly_model.py

import os
import json
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from collections import defaultdict
from datetime import datetime
from ml.explainer import AlertExplainer
import config

# (Optional) If you have an explainer module, uncomment the next line
# from ml.explainer import AlertExplainer


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for login events.

    Supports two modes:
    - 5‑feature synthetic fallback (trained via train())
    - 10‑feature RBA dataset model (trained via train_from_dataset.py)

    The model detects which mode it's in from the loaded payload.
    """

    def __init__(self, contamination=config.DEFAULT_CONTAMINATION):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        # Base encoders
        self.user_encoder = LabelEncoder()
        self.ip_encoder   = LabelEncoder()

        # Extended encoders (only for RBA-trained model, legacy raw-ID scheme)
        self.country_encoder = None
        self.device_encoder  = None

        # Reviewer-revision fix (M6): raw LabelEncoder IDs let the model
        # substantially memorise specific identities rather than learn
        # generalisable behaviour (confirmed: ROC-AUC collapsed to chance
        # level, 0.511, under a strict held-out-user test). Replaced with
        # training-set frequency for any model trained after this fix,
        # which recovered ROC-AUC to 0.755. encoding_scheme distinguishes
        # which payload shape was loaded; legacy raw-ID models still work
        # via the untouched code path above.
        self.encoding_scheme = "raw_id"   # or "frequency", set by load_model()
        self.ip_freq_map      = {}
        self.user_freq_map    = {}
        self.country_freq_map = {}
        self.device_freq_map  = {}

        self.is_trained    = False
        self.scaler        = None
        self.explainer     = None
        self.feature_count = 5      # 5=synthetic, 7=old RBA, 10=new RBA
        self.known_ips     = []
        self.known_users   = []
        self.known_countries = []
        self.known_devices   = []

        # For runtime failure rates
        self.ip_failure_counts = defaultdict(int)
        self.ip_total_counts   = defaultdict(int)

        # For 10‑feature model (sets of known values)
        self.known_ips_set       = set()
        self.known_countries_set = set()

    # ── Feature Extraction (Synthetic / Legacy) ──────────────────────────

    def _extract_features(self, log_events):
        """
        Legacy 5‑feature extraction (for synthetic training).
        """
        features = []
        ip_fail  = defaultdict(int)
        ip_total = defaultdict(int)

        for event in log_events:
            from datetime import datetime

            try:
                ts   = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                hour = ts.hour
            except Exception:
                hour = 12

            is_failed = 1 if event.get("status", "SUCCESS") == "FAILED" else 0
            ip        = str(event.get("ip",   "0.0.0.0")).strip()
            user      = str(event.get("user", "unknown")).strip()

            ip_total[ip] += 1
            if is_failed:
                ip_fail[ip] += 1
            failed_rate = ip_fail[ip] / ip_total[ip]

            try:
                ip_enc = self.ip_encoder.transform([ip])[0]
            except ValueError:
                ip_enc = -1

            try:
                user_enc = self.user_encoder.transform([user])[0]
            except ValueError:
                user_enc = -1

            row = [hour, is_failed, ip_enc, user_enc, failed_rate]

            # If we have country/device encoders, add them (7‑feature mode)
            if self.feature_count >= 7 and self.country_encoder is not None:
                country = str(event.get("country", "XX")).strip()
                device  = str(event.get("device_type", "Unknown")).strip()
                try:
                    country_enc = self.country_encoder.transform([country])[0]
                except ValueError:
                    country_enc = -1
                try:
                    device_enc = self.device_encoder.transform([device])[0]
                except ValueError:
                    device_enc = -1
                row.extend([country_enc, device_enc])

            features.append(row)

        return np.array(features)

    # ── Feature Extraction (10‑feature RBA pipeline) ──────────────────────

    def _extract_features_v2(self, log_event):
        """
        Extract the 10 features used by the RBA-trained model for a single event.
        Uses the stored encoders and cumulative failure rates.
        """
        from datetime import datetime as dt
        import numpy as np

        # 1. Parse timestamp
        try:
            ts = dt.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour = ts.hour
        except Exception:
            hour = 12

        # 2. Cyclic hour encoding
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)

        # 3. is_failed
        is_failed = 1 if log_event.get("status", "SUCCESS") == "FAILED" else 0

        # 4. IP encoding
        ip = str(log_event.get("ip", "0.0.0.0")).strip()
        try:
            ip_enc = self.ip_encoder.transform([ip])[0]
        except ValueError:
            ip_enc = -1

        # 5. User encoding
        user = str(log_event.get("user", "unknown")).strip()
        try:
            user_enc = self.user_encoder.transform([user])[0]
        except ValueError:
            user_enc = -1

        # 6. Cumulative failure rate (using instance state)
        total = self.ip_total_counts[ip]
        failed = self.ip_failure_counts.get(ip, 0)
        failed_rate = failed / total if total > 0 else 0.0
        

        # 7. Country encoding
        country = str(log_event.get("country", "XX")).strip()
        if self.country_encoder is not None:
            try:
                country_enc = self.country_encoder.transform([country])[0]
            except ValueError:
                country_enc = -1
        else:
            country_enc = -1

        # 8. Device encoding
        device = str(log_event.get("device_type", "Unknown")).strip()
        if self.device_encoder is not None:
            try:
                device_enc = self.device_encoder.transform([device])[0]
            except ValueError:
                device_enc = -1
        else:
            device_enc = -1

        # 9. is_new_ip
        known_ips_set = getattr(self, "known_ips_set", set())
        is_new_ip = int(ip not in known_ips_set)

        # 10. is_new_country
        known_countries_set = getattr(self, "known_countries_set", set())
        is_new_country = int(country not in known_countries_set)

        # Return as 2D array for scaler compatibility
        return np.array([[
            hour_sin, hour_cos,
            is_failed,
            ip_enc, user_enc,
            failed_rate,
            country_enc, device_enc,
            is_new_ip, is_new_country
        ]], dtype=np.float64)

    def _extract_features_v2_frequency(self, log_event):
        """
        Frequency-encoded counterpart to _extract_features_v2(). Same 10
        feature slots, same order, same causal failed_rate semantics;
        only ip_enc/user_enc/country_enc/device_enc are replaced with
        training-set frequency lookups. An entity absent from training
        correctly gets 0.0, not a special case, since rarity itself is
        the informative signal (see docs/DECISIONS.md, ADR-15 on frequency encoding).
        """
        from datetime import datetime as dt
        import numpy as np

        try:
            ts = dt.strptime(log_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            hour = ts.hour
        except Exception:
            hour = 12
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)

        is_failed = 1 if log_event.get("status", "SUCCESS") == "FAILED" else 0

        ip      = str(log_event.get("ip", "0.0.0.0")).strip()
        user    = str(log_event.get("user", "unknown")).strip()
        country = str(log_event.get("country", "XX")).strip()
        device  = str(log_event.get("device_type", "Unknown")).strip()

        total = self.ip_total_counts[ip]
        failed = self.ip_failure_counts.get(ip, 0)
        failed_rate = failed / total if total > 0 else 0.0

        ip_freq      = self.ip_freq_map.get(ip, 0.0)
        user_freq    = self.user_freq_map.get(user, 0.0)
        country_freq = self.country_freq_map.get(country, 0.0)
        device_freq  = self.device_freq_map.get(device, 0.0)

        is_new_ip = int(ip not in self.known_ips_set)
        is_new_country = int(country not in self.known_countries_set)

        return np.array([[
            hour_sin, hour_cos,
            is_failed,
            ip_freq, user_freq,
            failed_rate,
            country_freq, device_freq,
            is_new_ip, is_new_country
        ]], dtype=np.float64)

    # ── Offline Training (Synthetic Fallback) ─────────────────────────────

    def train(self, training_file):
        """
        Train on synthetic normal-only JSON dataset.
        Used as fallback when no RBA-trained model.pkl exists.
        Produces a 5‑feature model.
        """
        try:
            with open(training_file, "r") as f:
                log_events = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠ AnomalyDetector: Could not load {training_file} - {e}")
            print("  Running in rules-only mode.")
            return False

        if len(log_events) < 10:
            print("⚠ AnomalyDetector: Not enough training data.")
            return False

        all_ips   = list({e["ip"]   for e in log_events})
        all_users = list({e["user"] for e in log_events})
        self.ip_encoder.fit(all_ips)
        self.user_encoder.fit(all_users)
        self.known_ips   = all_ips
        self.known_users = all_users
        self.feature_count = 5

        X = self._extract_features(log_events)
        self.model.fit(X)
        self.is_trained = True

        print(f"✅ AnomalyDetector trained on {len(log_events)} synthetic events.")
        print(f"   Known IPs: {len(all_ips)} | Known users: {len(all_users)}")
        return True

    # ── Model Persistence ──────────────────────────────────────────────────

    def save_model(self, model_path):
        """Save synthetic-trained model to disk."""
        if not self.is_trained:
            print("⚠ Cannot save - model not trained yet.")
            return False

        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        payload = {
            "model":          self.model,
            "ip_encoder":     self.ip_encoder,
            "user_encoder":   self.user_encoder,
            "known_ips":      self.known_ips,
            "known_users":    self.known_users,
            "contamination":  self.contamination,
            "feature_count":  self.feature_count,
        }
        joblib.dump(payload, model_path)
        print(f"💾 Model saved → {model_path}")
        return True

    def load_model(self, model_path):
        """
        Load pre-trained model from disk.
        Handles 5‑feature (synthetic), 7‑feature (old RBA), and 10‑feature (new RBA) payloads.
        """
        try:
            payload = joblib.load(model_path)

            self.model        = payload["model"]
            self.scaler       = payload.get("scaler", None)
            self.explainer = AlertExplainer(self.scaler) if self.scaler is not None else None
            self.contamination = payload.get("contamination", config.DEFAULT_CONTAMINATION)

            # Detect encoding scheme FIRST: frequency-encoded payloads carry
            # no ip_encoder/user_encoder at all, so those must not be read
            # unconditionally before this check.
            if payload.get("encoding_scheme") == "frequency":
                self.encoding_scheme    = "frequency"
                self.ip_freq_map        = payload.get("ip_freq_map", {})
                self.user_freq_map      = payload.get("user_freq_map", {})
                self.country_freq_map   = payload.get("country_freq_map", {})
                self.device_freq_map    = payload.get("device_freq_map", {})
                self.known_ips_set       = payload.get("known_ips_set", set())
                self.known_countries_set = payload.get("known_countries_set", set())
                self.known_ips    = payload.get("known_ips", list(self.ip_freq_map.keys()))
                self.known_users  = payload.get("known_users", list(self.user_freq_map.keys()))
                self.known_countries = payload.get("known_countries", list(self.country_freq_map.keys()))
                self.known_devices   = payload.get("known_devices", list(self.device_freq_map.keys()))
                self.feature_count   = payload.get("feature_count", 10)

                trained_on = payload.get("trained_on", "RBA Dataset")
                metrics    = payload.get("metrics", {})
                print(f"✅ RBA-trained model loaded from {model_path} (frequency encoding)")
                print(f"   Training data: {trained_on}")
                print(f"   Known IPs: {len(self.known_ips):,} | "
                      f"Users: {len(self.known_users):,} | "
                      f"Countries: {len(self.known_countries)} | "
                      f"Devices: {len(self.known_devices)}")
                if metrics:
                    print(f"   Evaluation - Precision: {metrics.get('precision',0):.1%} | "
                          f"Recall: {metrics.get('recall',0):.1%} | "
                          f"F1: {metrics.get('f1',0):.1%}")

                self.is_trained = True
                return True

            # Legacy raw-ID path: these keys only exist on pre-fix payloads.
            self.ip_encoder   = payload["ip_encoder"]
            self.user_encoder = payload["user_encoder"]
            self.known_ips    = payload.get("known_ips",   [])
            self.known_users  = payload.get("known_users", [])
            self.feature_count = payload.get("feature_count", 5)

            # Detect if this is an RBA-trained model (has country/device encoders)
            if "country_encoder" in payload and "device_encoder" in payload:
                self.country_encoder  = payload["country_encoder"]
                self.device_encoder   = payload["device_encoder"]
                self.known_countries  = payload.get("known_countries", [])
                self.known_devices    = payload.get("known_devices",   [])
                # For 10‑feature model, also load the known sets
                self.known_ips_set       = payload.get("known_ips_set",       set())
                self.known_countries_set = payload.get("known_countries_set", set())
                self.feature_count       = payload.get("feature_count", 7)   # could be 7 or 10

                trained_on = payload.get("trained_on", "RBA Dataset")
                metrics    = payload.get("metrics", {})
                print(f"✅ RBA-trained model loaded from {model_path}")
                print(f"   Training data: {trained_on}")
                print(f"   Known IPs: {len(self.known_ips):,} | "
                      f"Users: {len(self.known_users):,} | "
                      f"Countries: {len(self.known_countries)} | "
                      f"Devices: {len(self.known_devices)}")
                if metrics:
                    print(f"   Evaluation - Precision: {metrics.get('precision',0):.1%} | "
                          f"Recall: {metrics.get('recall',0):.1%} | "
                          f"F1: {metrics.get('f1',0):.1%}")
            else:
                # Legacy 5‑feature synthetic model
                self.country_encoder = None
                self.device_encoder  = None
                self.feature_count   = payload.get("feature_count", 5)
                print(f"✅ Synthetic model loaded from {model_path}")
                print(f"   Known IPs: {len(self.known_ips)} | "
                      f"Known users: {len(self.known_users)}")

            self.is_trained = True
            return True

        except (FileNotFoundError, KeyError) as e:
            print(f"⚠ Could not load model from {model_path} - {e}")
            return False

    # ── Runtime Inference ──────────────────────────────────────────────────

    def score_event(self, log_event):
        """
        Score a single login event using the loaded model.
        Returns a dict with anomaly flag, score, confidence, and feature_count.
        """
        if not self.is_trained:
            return None

        ip = str(log_event.get("ip", "0.0.0.0")).strip()

        # ── Update runtime failure-rate counters BEFORE feature extraction ──
        # failed_rate must reflect the cumulative rate INCLUDING this event,
        # matching the inclusive groupby cumsum()/cumcount()+1 semantics used
        # during offline training (see train_from_dataset.py::extract_features).
        # This must happen exactly once per real event - here in score_event(),
        # not inside _extract_features_v2() - because explain_event() calls
        # _extract_features_v2() a second time for anomalous events, which
        # would otherwise double-count.
        is_failed_event = log_event.get("status", "SUCCESS") == "FAILED"
        self.ip_total_counts[ip] += 1
        if is_failed_event:
            self.ip_failure_counts[ip] += 1

        try:
            # Use frequency encoding if that's the loaded model's scheme,
            # the legacy raw-ID 10-feature extraction if it's an older RBA
            # model, otherwise fall back to legacy extraction for 5/7-feature
            # synthetic models.
            if self.encoding_scheme == "frequency":
                features = self._extract_features_v2_frequency(log_event)
            elif self.feature_count >= 10 and hasattr(self, "known_ips_set"):
                features = self._extract_features_v2(log_event)
            else:
                # For 5 or 7 features, we need a list of one event
                features = self._extract_features([log_event])

            if self.scaler is not None:
                features = self.scaler.transform(features)

            # One pass over the forest (audit F21). IsolationForest.predict()
            # is defined as decision_function() < 0 -> -1, so deriving it here
            # is exact and halves the per-event cost.
            raw_score  = self.model.decision_function(features)[0]
            prediction = -1 if raw_score < 0 else 1

        except Exception as e:
            print(f"⚠ Scoring error for {ip}: {e}")
            return None

        return self.classify_score(prediction, raw_score)

    def classify_score(self, prediction, raw_score):
        """
        Turn one (predict, decision_function) pair into the score_event()
        result. Shared with backend/eval/harness.py's PrecomputedScorer so the
        live and batch paths cannot drift apart.
        """
        # Determine confidence based on anomaly score (negative = more anomalous)
        if raw_score < config.CONFIDENCE_HIGH_CUTOFF:
            confidence = "High"
        elif raw_score < config.CONFIDENCE_MEDIUM_CUTOFF:
            confidence = "Medium"
        else:
            confidence = "Low"

        # At the deployed margin (-0.02, equal to the Medium cut-off) this is
        # exactly "prediction == -1 and confidence in (High, Medium)".
        is_anomaly = bool(prediction == -1 and raw_score < config.ML_ALERT_MARGIN)

        return {
            "is_anomaly":    is_anomaly,
            "anomaly_score": float(round(raw_score, 4)),
            "confidence":    confidence,
            "feature_count": self.feature_count,
        }

    def explain_event(self, log_event, anomaly_score, confidence):
        """
        (Optional) Generate feature-level explanation if an explainer is available.
        """
        if self.explainer is None or not self.is_trained:
            return None

        try:
            if self.encoding_scheme == "frequency":
                raw_features = self._extract_features_v2_frequency(log_event)
            elif self.feature_count >= 10:
                raw_features = self._extract_features_v2(log_event)
            else:
                raw_features = self._extract_features([log_event])
            return self.explainer.explain(raw_features, anomaly_score, confidence)
        except Exception as e:
            print(f"⚠ Explainer error: {e}")
            return None

    # ── Credential Stuffing (Rule‑based) ──────────────────────────────────

    def check_credential_stuffing(self, ip, users_tried):
        """
        Heuristic rule for credential stuffing:
        - >5 distinct usernames tried from same IP
        - failure rate > 70%
        """
        unique_users = len(users_tried.get(ip, set()))
        total        = self.ip_total_counts.get(ip, 0)
        failed       = self.ip_failure_counts.get(ip, 0)
        failure_rate = failed / total if total > 0 else 0

        if unique_users >= 5 and failure_rate > 0.7:
            return {
                "type":               "Credential Stuffing",
                "confidence":         "High",
                "unique_users_tried": unique_users,
                "failure_rate":       round(failure_rate, 2)
            }
        return None