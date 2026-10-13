# backend/utils/alert_manager.py
"""
The alert store: data/alerts.json, a JSON list of alert dicts.

Every write path (save, LLM update, clear, restore, backup) goes through
this class (audit F07, F25):
  - it holds the cross-process FileLock for the whole read-modify-write;
  - it writes a temp file in the same directory and os.replace()s it over
    the store, so a reader never sees a half-written file;
  - clear() writes the backup BEFORE emptying the store.

Readers do not need the lock: thanks to the atomic replace they always see
a complete file. load_cached() re-parses only when the file's mtime or
size changes, which is what the API's polled endpoints use.
"""

import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime

from filelock import FileLock

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "alerts.json"
)
LOCK_TIMEOUT_SECONDS = 10

log = logging.getLogger(__name__)


def _replace_with_retry(src, dst, timeout=5.0):
    # On Windows os.replace() fails while another process has dst open
    # (e.g. an API request reading it). Those reads are brief, so retry
    # with a growing back-off for up to `timeout` seconds.
    deadline = time.monotonic() + timeout
    wait = 0.002
    while True:
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(wait)
            wait = min(wait * 2, 0.05)


def atomic_write_json(path, data):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".alerts-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        _replace_with_retry(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


class AlertManager:

    def __init__(self, file_path=None):
        self.file_path = file_path or DEFAULT_PATH
        self.lock_path = self.file_path + ".lock"
        self.backup_path = self.file_path + ".bak"
        self._cache_key = None
        self._cache = []
        self._cache_guard = threading.Lock()
        self._ensure_file()

    def _lock(self):
        return FileLock(self.lock_path, timeout=LOCK_TIMEOUT_SECONDS)

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        if not os.path.exists(self.file_path):
            with self._lock():
                if not os.path.exists(self.file_path):
                    atomic_write_json(self.file_path, [])

    def _read_unlocked(self, attempts=20):
        # On Windows, opening the file during another process's os.replace()
        # raises PermissionError for a moment; retry briefly.
        for i in range(attempts):
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
            except FileNotFoundError:
                return []
            except PermissionError:
                if i == attempts - 1:
                    raise
                time.sleep(0.005)
            except json.JSONDecodeError as e:
                log.error("alerts.json is not valid JSON (%s); treating it as empty", e)
                return []

    def _read_for_write(self):
        """Like _read_unlocked, but never lets a write erase a corrupt store:
        an unreadable file is moved aside first. Call with the lock held."""
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except FileNotFoundError:
            return []
        except json.JSONDecodeError as e:
            aside = f"{self.file_path}.corrupt-{datetime.now():%Y%m%d-%H%M%S}"
            _replace_with_retry(self.file_path, aside)
            log.error("alerts.json was not valid JSON (%s); moved to %s", e, aside)
            return []

    # ── Writes ───────────────────────────────────────────────────────────────

    def save_alert(self, alert):
        """Append one alert."""
        if "llm_explanation" not in alert:
            alert["llm_explanation"] = None
            alert["enriched"]        = False
        # Wall-clock time the alert entered the store (detected_at is the
        # event's own timestamp). Used for the time-windowed threat level.
        alert.setdefault("saved_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        with self._lock():
            alerts = self._read_for_write()
            alerts.append(alert)
            atomic_write_json(self.file_path, alerts)

        log.info("Alert saved to alerts.json")

    def update_fields(self, alert_id, fields):
        """Merge fields into a saved alert. Returns True if found."""
        with self._lock():
            alerts = self._read_for_write()
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    alert.update(fields)
                    atomic_write_json(self.file_path, alerts)
                    return True
        return False

    def update_explanation(self, alert_id, llm_explanation):
        """Attach an LLM explanation to a saved alert. Returns True if found."""
        with self._lock():
            alerts = self._read_for_write()
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    alert["llm_explanation"] = llm_explanation
                    alert["enriched"]        = True
                    alert["enriched_at"]     = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    atomic_write_json(self.file_path, alerts)
                    log.info("Alert #%s updated with LLM explanation", alert_id)
                    return True
        return False

    def mark_enrichment_failed(self, alert_id, reason, final_after):
        """
        Record a failed enrichment attempt without marking the alert as
        enriched. After `final_after` attempts it is flagged
        enrichment_failed so the scanner stops retrying. Returns the
        attempt count, or None if the alert no longer exists.
        """
        with self._lock():
            alerts = self._read_for_write()
            for alert in alerts:
                if alert.get("alert_id") == alert_id:
                    attempts = alert.get("enrichment_attempts", 0) + 1
                    alert["enrichment_attempts"]  = attempts
                    alert["enrichment_error"]     = str(reason)[:300]
                    alert["enrichment_failed_at"] = datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    if attempts >= final_after:
                        alert["enrichment_failed"] = True
                    atomic_write_json(self.file_path, alerts)
                    return attempts
        return None

    def backup(self):
        """Copy the current store to alerts.json.bak. Returns alerts backed up."""
        with self._lock():
            alerts = self._read_for_write()
            atomic_write_json(self.backup_path, alerts)
        return len(alerts)

    def clear(self, backup=True):
        """Empty the store, writing the backup first. Returns alerts cleared."""
        with self._lock():
            alerts = self._read_for_write()
            if backup:
                atomic_write_json(self.backup_path, alerts)
            atomic_write_json(self.file_path, [])
        return len(alerts)

    def restore(self):
        """Replace the store with the backup. Returns alerts restored."""
        with self._lock():
            with open(self.backup_path, "r", encoding="utf-8") as f:
                alerts = json.load(f)
            if not isinstance(alerts, list):
                raise ValueError("backup is not a JSON list")
            atomic_write_json(self.file_path, alerts)
        return len(alerts)

    # ── Reads ────────────────────────────────────────────────────────────────

    def load_alerts(self):
        return self._read_unlocked()

    def load_cached(self):
        """
        Parsed alerts, re-read only when the file changes. Callers must treat
        the returned list as read-only; it is shared between requests.
        """
        try:
            st = os.stat(self.file_path)
            key = (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return []
        with self._cache_guard:
            if key != self._cache_key:
                try:
                    self._cache = self._read_unlocked()
                    self._cache_key = key
                except OSError as e:
                    # Keep serving the last good copy; retry on the next call.
                    log.warning("Could not read alerts.json (%s); serving cached copy", e)
            return self._cache
