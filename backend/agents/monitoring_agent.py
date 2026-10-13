# backend/agents/monitoring_agent.py
import json
import logging
import os
import time
from datetime import datetime
from .detection_agent import DetectionAgent
from .analysis_agent  import AnalysisAgent
from .response_agent  import ResponseAgent
from utils.alert_manager import AlertManager
from utils.event_schema import normalize_event

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger(__name__)


class MonitoringAgent:

    def __init__(self, log_file=None, threshold=5, anomaly_detector=None):
        self.log_file        = log_file
        self.detector        = DetectionAgent(
            threshold=threshold,
            anomaly_detector=anomaly_detector
        )
        self.analyzer        = AnalysisAgent()
        self.responder       = ResponseAgent()
        self.alert_manager   = AlertManager()
        self.alerts_generated = 0
        self.events_processed = 0
        self.start_time       = None

        self._stats_path = os.path.join(BASE, "data", "pipeline_stats.json")
        self._queue_path = os.path.join(BASE, "data", "live_queue.jsonl")
        self._cursor_path = self._queue_path + ".cursor"
        self._deadletter_path = os.path.join(BASE, "data", "live_queue.deadletter.jsonl")

    # ── Shared event processor ────────────────────────────────────────────────

    def _process_event(self, event):
        """Run a single log event through the full detection pipeline."""
        alert = self.detector.analyze_event(event)
        self.events_processed += 1

        ts   = event.get("timestamp", "")
        user = event.get("user", "?")
        ip   = event.get("ip", "?")
        st   = event.get("status", "?")
        log.info("🟢 %s | %s @ %s | %s", ts, user, ip, st)

        if alert:
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

        try:
            while True:
                offset, handled = self._poll_queue(offset)
                if not handled:
                    time.sleep(poll_interval)

        except KeyboardInterrupt:
            elapsed = (datetime.now() - self.start_time).seconds
            log.info(f"\n\n⏹ Live streaming stopped after {elapsed}s")
            log.info(f"   Events processed: {self.events_processed:,}")
            log.info(f"   Alerts generated: {self.alerts_generated}")
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
        with open(self._stats_path, "w") as f:
            json.dump(stats, f, indent=2)
        log.info(f"📊 Pipeline stats saved")