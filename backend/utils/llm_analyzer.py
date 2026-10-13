# backend/utils/llm_analyzer.py
"""
LLM-powered alert enrichment using local Ollama.

Runs as a background service inside api.py (the persistent process).
Scans alerts.json every 10 seconds for unenriched alerts.
main.py never touches the LLM - it just saves alerts and exits.
"""

import json
import threading
import time
import requests
import os
import re

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"
TIMEOUT      = 300   # Per-request timeout in seconds.
MAX_CONCURRENT_ENRICH = 2


class LLMAnalyzer:
    """
    Background enrichment service.
    Scans alerts.json for unenriched alerts and updates them with
    LLM-generated explanations. Runs inside the Flask API process.
    """

    def __init__(self, alerts_path, metrics_path=None):
        self.alerts_path  = alerts_path
        self.available    = self._check_ollama()
        self._shutdown    = threading.Event()
        self._processing  = set()  # alert IDs currently being processed
        self._slots       = threading.BoundedSemaphore(MAX_CONCURRENT_ENRICH)

        if self.available:
            print(f"✅ LLM Analyzer ready ({OLLAMA_MODEL} via Ollama)")
            print("   Scanning alerts.json for unenriched alerts every 10s")
            self._worker = threading.Thread(
                target=self._scan_loop,
                daemon=True,
                name="LLMEnrichmentWorker"
            )
            self._worker.start()
        else:
            print("⚠ Ollama not available - LLM enrichment disabled")

    def _check_ollama(self):
        try:
            r = requests.get(
                "http://localhost:11434/api/tags",
                timeout=3
            )
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                return any(
                    "phi3" in m or "mistral" in m or "llama" in m
                    for m in models
                )
        except Exception:
            pass
        return False

    def _scan_loop(self):
        """
        Runs every 10 seconds inside the Flask API process.
        Finds unenriched alerts and enriches them one by one.
        """
        print("🔄 LLM enrichment scanner started")
        while not self._shutdown.is_set():
            try:
                self._scan_and_enrich()
            except Exception as e:
                print(f"⚠ Scan error: {e}")
            # Wait 10 seconds before next scan
            self._shutdown.wait(timeout=10)

    def _scan_and_enrich(self):
        """Find unenriched alerts and process them."""
        try:
            with open(self.alerts_path, "r", encoding="utf-8") as f:
                alerts = json.load(f)
        except UnicodeDecodeError:
            with open(self.alerts_path, "r", encoding="utf-8", errors="replace") as f:
                alerts = json.load(f)
        except Exception:
            return

        for alert in alerts:
            if not self._slots.acquire(blocking=False):
                # Worker capacity reached for this scan cycle.
                break

            alert_id = alert.get("alert_id")
            # Skip if already enriched or currently being processed
            if alert.get("enriched") or alert_id in self._processing:
                self._slots.release()
                continue
            if not alert_id:
                self._slots.release()
                continue

            # Mark as processing to prevent duplicate work
            self._processing.add(alert_id)

            # Enrich in a separate thread so scan loop isn't blocked
            t = threading.Thread(
                target=self._enrich_one,
                args=(alert,),
                daemon=True
            )
            t.start()

    def _enrich_one(self, alert):
        """Enrich a single alert with LLM explanation."""
        alert_id = alert.get("alert_id", "?")
        print(f"🤖 Enriching alert #{alert_id}...")

        try:
            explanation = self._generate(alert)

            if explanation:
                self._update_alert(alert_id, explanation)
                print(f"✅ Alert #{alert_id} enriched with LLM explanation")
            else:
                # Mark as enriched anyway with None to stop retrying
                self._update_alert(alert_id, None)
        finally:
            # Always remove from processing set, even if enrichment fails.
            self._processing.discard(alert_id)
            self._slots.release()

    def _build_prompt(self, alert):
        """Concise prompt - enough structure for a complete response."""
        feature_summary = ""
        fe = alert.get("feature_explanation")
        if fe and fe.get("summary"):
            feature_summary = f"\nML: {fe['summary']}"

        mitre = alert.get("mitre", {})
        mitre_str = ""
        if mitre:
            mitre_str = (
                f"\nMITRE: {mitre.get('technique_id','?')} - "
                f"{mitre.get('technique_name','?')}"
            )

        return f"""You are a SOC analyst. Write a complete security alert explanation.
Use these exact headers on separate lines:
WHAT HAPPENED:
WHY SUSPICIOUS:
ATTACKER OBJECTIVE:
RECOMMENDED ACTION:

    Keep each section concise, but do not omit any header or end mid-sentence.
    Use 2-4 sentences per section.

Alert: {alert.get('type')} | Severity: {alert.get('severity')}
IP: {alert.get('ip')} | User: {alert.get('user')}
Time: {alert.get('detected_at','?')}
Details: {alert.get('description','')}{mitre_str}{feature_summary}

Write the explanation:"""

    def _generate(self, alert):
        """Call Ollama and return explanation string."""
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model":  OLLAMA_MODEL,
                    "prompt": self._build_prompt(alert),
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 420,
                        "top_p":       0.85,
                        "stop":        ["---", "###", "\n\n\n"],
                    }
                },
                timeout=TIMEOUT
            )
            if response.status_code == 200:
                result = response.json().get("response", "").strip()
                if result and len(result) > 50:
                    return self._sanitize(result)
        except requests.exceptions.Timeout:
            print(f"⚠ LLM timeout - model may be slow on this hardware")
        except Exception as e:
            print(f"⚠ LLM error: {e}")
        return None

    def _sanitize(self, text):
        """
        Clean LLM output before storing in JSON.
        Removes characters that break JSON serialization.
        """
        if not text:
            return text
        # Remove any stray control characters except newlines and tabs
        cleaned = "".join(
            ch for ch in text
            if ch == "\n" or ch == "\t" or (ord(ch) >= 32 and ord(ch) != 127)
        )
        # Normalize multiple blank lines to single blank line
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        # Strip leading/trailing whitespace
        return cleaned.strip()

    def _update_alert(self, alert_id, explanation):
        """Write the explanation through the shared alert store (lock +
        atomic replace), the same path every other writer uses."""
        from utils.alert_manager import AlertManager
        try:
            AlertManager(self.alerts_path).update_explanation(alert_id, explanation)
        except Exception as e:
            print(f"⚠ Could not update alert #{alert_id}: {e}")

    def shutdown(self):
        self._shutdown.set()