# backend/agents/monitoring_agent.py
import json
import logging
import os
import time
from datetime import datetime

import config
from .detection_agent import DetectionAgent
from .analysis_agent  import AnalysisAgent
from .response_agent  import ResponseAgent
from utils.alert_manager import open_alert_store
from utils.event_schema import normalize_event

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger(__name__)


class MonitoringAgent:

    def __init__(self, log_file=None, threshold=None, anomaly_detector=None,
                 alert_manager=None, responder=None):
        self.log_file        = log_file
        self.detector        = DetectionAgent(
            threshold=threshold,
            anomaly_detector=anomaly_detector
        )
        self.analyzer        = AnalysisAgent()
        self.responder       = responder if responder is not None else ResponseAgent()
        # v3: SQLite (data/alerts.db); legacy: data/alerts.json.
        self.alert_manager   = alert_manager if alert_manager is not None else open_alert_store()
        self.alerts_generated = 0
        self.events_processed = 0
        self.blocked_source_events = 0     # v3: events from an IP on the block list
        self.challenged_source_events = 0  # v3: events from an IP under step-up
        self.duplicate_events = 0          # v3: repeated deliveries, ignored
        self.start_time       = None

        self._stats_path = os.path.join(BASE, "data", "pipeline_stats.json")
        self._queue_path = os.path.join(BASE, "data", "live_queue.jsonl")
        self._cursor_path = self._queue_path + ".cursor"
        self._deadletter_path = os.path.join(BASE, "data", "live_queue.deadletter.jsonl")

    # ── Shared event processor ────────────────────────────────────────────────

    def _process_event(self, event):
        """
        Run a single log event through the full detection pipeline. Every
        alert the engine raises for the event is analysed, saved and acted
        on. The v3 engine has its own path (_process_event_v3).
        """
        if self.responder.mode == "v3":
            return self._process_event_v3(event)
        alerts = self.detector.analyze_all(event)
        self.events_processed += 1

        ts   = event.get("timestamp", "")
        user = event.get("user", "?")
        ip   = event.get("ip", "?")
        st   = event.get("status", "?")
        log.info("🟢 %s | %s @ %s | %s", ts, user, ip, st)

        for alert in alerts:
            alert["timestamp"] = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            analyzed = self.analyzer.evaluate_alert(alert)
            # Store what the response layer will do, then the real outcome
            # (e.g. whether the email was actually sent) once it has run.
            analyzed["response"] = self.responder.decide(analyzed)
            log.info(f"🚨 ALERT: {analyzed.get('type')} | {analyzed.get('severity')} | #{analyzed.get('alert_id','?')}")
            self.alert_manager.save_alert(analyzed)
            self.responder.take_action(analyzed)
            outcome = self.responder.last_response
            if outcome is not None and outcome != analyzed["response"]:
                self.alert_manager.update_fields(analyzed["alert_id"], {"response": outcome})
            self.alerts_generated += 1

    def _process_event_v3(self, event):
        """
        v3: the IP's block / step-up state before the event, detection, the
        incident's triage (agents/triage.py), then every alert analysed
        (severity from the incident's tier), saved and acted on. An event
        from a blocked or challenged address is still detected as usual;
        it is counted, logged, and its alerts carry blocked_source /
        challenged_source. A repeated delivery is counted and skipped.
        """
        state = self.responder.status(event)
        det = self.detector.analyze(event)
        self.events_processed += 1

        ts, ip = event.get("timestamp", ""), event.get("ip", "?")
        log.info("🟢 %s | %s @ %s | %s", ts, event.get("user", "?"), ip, event.get("status", "?"))
        if det.duplicate:
            self.duplicate_events += 1
            return
        self.responder.observe(event)
        if state["blocked"]:
            self.blocked_source_events += 1
            log.info("⛔ Event from blocked source %s (detection still applied)", ip)
        elif state["challenged"]:
            self.challenged_source_events += 1
            log.info("🔐 Step-up challenge (simulated, not enforced) for login from %s", ip)
        if not det.alerts:
            return

        incident = self.responder.assess(event, det.alerts)
        for alert in det.alerts:
            alert["timestamp"] = event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            alert["blocked_source"] = state["blocked"]
            alert["challenged_source"] = state["challenged"]
            if incident is not None:
                alert["incident"] = dict(incident)
            analyzed = self.analyzer.evaluate_alert(alert)
            analyzed["response"] = self.responder.decide(analyzed)
            log.info(f"🚨 ALERT: {analyzed.get('type')} | {analyzed.get('severity')} | "
                     f"{analyzed['response']['tier']} | #{analyzed.get('alert_id','?')}")
            self.alert_manager.save_alert(analyzed)
            self.responder.take_action(analyzed)
            self.alerts_generated += 1

    # ── Batch mode ────────────────────────────────────────────────────────────

    def stream_logs(self, delay=1):
        """
        Batch mode: read parsed_logs.json once and process all events.
        Used by: python main.py
        """
        with open(self.log_file, "r") as f:
            logs = json.load(f)

        self.start_time = datetime.now()
        log.info(f"📡 MonitoringAgent: Streaming {len(logs)} log events...\n")

        for event in logs:
            time.sleep(delay)
            try:
                self._process_event(event)
            except Exception as e:
                # One bad event must not end the run (audit F05).
                log.error("Skipping event that failed processing: %s: %s",
                          type(e).__name__, e)

        self.responder.flush()
        self._save_stats()
        log.info(f"\n📊 Processed {self.events_processed} events → {self.alerts_generated} alerts")

    # ── Live streaming mode ───────────────────────────────────────────────────

    def stream_live(self, poll_interval=1.0):
        """
        Live mode: continuously read new events from live_queue.jsonl.
        Runs indefinitely until Ctrl+C.
        Used by: python main.py --live

        The cursor is a byte offset into the queue, saved after every event,
        so a crash or restart resumes at the next unprocessed line. An event
        that fails validation or processing is written to the dead-letter
        file and skipped instead of stopping the loop (audit F05, F24).
        """
        offset = self._load_cursor()

        self.start_time = datetime.now()
        log.info("📡 Live streaming mode active")
        log.info(f"   Queue file: {self._queue_path}")
        log.info(f"   Resumed from byte offset {offset}")
        log.info("   Press Ctrl+C to stop\n")
        log.info("-" * 55)

        last_stats = 0.0
        try:
            while True:
                offset, handled = self._poll_queue(offset)
                # Stats while running, not only at shutdown, so the
                # dashboard shows live progress (LIVE_STATS_INTERVAL_SECONDS).
                now = time.monotonic()
                if handled and now - last_stats >= config.LIVE_STATS_INTERVAL_SECONDS:
                    self._save_stats()
                    last_stats = now
                if not handled:
                    time.sleep(poll_interval)

        except KeyboardInterrupt:
            elapsed = (datetime.now() - self.start_time).seconds
            log.info(f"\n\n⏹ Live streaming stopped after {elapsed}s")
            log.info(f"   Events processed: {self.events_processed:,}")
            log.info(f"   Alerts generated: {self.alerts_generated}")
            self.responder.flush()
            self._save_stats()

    def _poll_queue(self, offset):
        """
        Process every complete line after `offset`. Returns (new_offset,
        lines_handled). A trailing line without a newline is still being
        written by /api/ingest and is left for the next poll.
        """
        try:
            size = os.path.getsize(self._queue_path)
        except FileNotFoundError:
            return offset, 0
        if size < offset:
            # The queue was truncated or replaced (e.g. /api/queue/clear).
            log.warning("Queue shorter than cursor (%d < %d bytes); restarting at 0",
                        size, offset)
            offset = 0
            self._save_cursor(0)

        handled = 0
        with open(self._queue_path, "rb") as f:
            f.seek(offset)
            for raw_line in f:
                if not raw_line.endswith(b"\n"):
                    break
                line_start = offset
                offset += len(raw_line)
                handled += 1
                text = raw_line.decode("utf-8", errors="replace").strip()
                if text:
                    self._handle_queue_line(text, line_start)
                self._save_cursor(offset)
        return offset, handled

    def _handle_queue_line(self, text, line_start):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as e:
            self._dead_letter(text, line_start, f"invalid JSON: {e}")
            return
        event, error = normalize_event(raw)
        if error:
            self._dead_letter(raw, line_start, f"invalid event: {error}")
            return
        try:
            self._process_event(event)
        except Exception as e:
            self._dead_letter(event, line_start, f"processing failed: {type(e).__name__}: {e}")

    def _dead_letter(self, payload, line_start, reason):
        log.warning("Dead-lettered queue entry at byte %d: %s", line_start, reason)
        record = {
            "dead_lettered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "queue_offset": line_start,
            "reason": reason,
            "entry": payload,
        }
        try:
            with open(self._deadletter_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            log.error("Could not write dead-letter file: %s", e)

    def _load_cursor(self):
        """
        Byte offset to resume from. Older versions stored a line count as a
        bare integer; that is converted to the byte offset of the same line.
        """
        try:
            with open(self._cursor_path, "r") as f:
                text = f.read().strip()
        except OSError:
            return 0
        try:
            return int(json.loads(text)["offset"])
        except (ValueError, KeyError, TypeError):
            pass
        try:
            lines = int(text)
        except ValueError:
            return 0
        offset = 0
        try:
            with open(self._queue_path, "rb") as f:
                for _ in range(lines):
                    line = f.readline()
                    if not line:
                        break
                    offset += len(line)
        except FileNotFoundError:
            return 0
        return offset

    def _save_cursor(self, offset):
        tmp = self._cursor_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"offset": offset}, f)
            os.replace(tmp, self._cursor_path)
        except OSError as e:
            log.error("Could not save queue cursor: %s", e)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def _save_stats(self):
        if not self.start_time:
            return
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        stats = {
            "events_processed":   self.events_processed,
            "alerts_generated":   self.alerts_generated,
            "start_time":         self.start_time.isoformat(),
            "end_time":           end_time.isoformat(),
            "duration_seconds":   round(duration, 2),
            "last_run":           end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "avg_event_time_ms":  round(
                (duration / self.events_processed) * 1000, 1
            ) if self.events_processed > 0 else 0,
        }

        os.makedirs(os.path.dirname(self._stats_path), exist_ok=True)
        tmp = self._stats_path + ".tmp"          # atomic: the API reads it concurrently
        with open(tmp, "w") as f:
            json.dump(stats, f, indent=2)
        os.replace(tmp, self._stats_path)
        log.info(f"📊 Pipeline stats saved")