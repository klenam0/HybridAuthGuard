# backend/utils/alert_store_sqlite.py
"""
The v3 alert store: SQLite at data/alerts.db (audit F07). The legacy JSON
store (utils/alert_manager.AlertManager) stays for RULES_MODE "legacy".

Same interface as AlertManager (save_alert, update_fields,
update_explanation, mark_enrichment_failed, backup, clear, restore,
load_alerts, load_cached) plus indexed queries for the API. Each alert is
one row: indexed columns (event time, IP, incident, tier, type, severity)
and the full alert as JSON. The incidents table keeps one row per incident
with its latest tier and score.

WAL journal: readers (the API process) never block the writer (the
pipeline). Every write is one transaction; save_alerts() batches.

Retention (config.ALERT_RETENTION_DAYS, default 30; 0 keeps everything):
alerts saved (wall clock, saved_at) more than that many days ago are
deleted, with the incidents left without alerts, when the store opens and
then at most once a day (checked on writes and cached reads). Wall clock,
not event time, so replaying old data does not prune what it just wrote.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta

from utils.event_schema import epoch_seconds

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "alerts.db")
# load_cached() (what the polled list endpoints and the LLM scanner read)
# returns at most this many of the most recent alerts.
CACHED_LIMIT = 2000

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY,
    alert_id     TEXT NOT NULL UNIQUE,
    ts           INTEGER,
    detected_at  TEXT,
    saved_at     TEXT,
    ip           TEXT,
    user         TEXT,
    type         TEXT,
    severity     TEXT,
    incident_id  TEXT,
    tier         TEXT,
    enriched     INTEGER NOT NULL DEFAULT 0,
    body         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts       ON alerts (ts);
CREATE INDEX IF NOT EXISTS ix_alerts_ip       ON alerts (ip, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts (incident_id);
CREATE INDEX IF NOT EXISTS ix_alerts_tier     ON alerts (tier, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_tier_id  ON alerts (tier, id);
CREATE INDEX IF NOT EXISTS ix_alerts_saved    ON alerts (saved_at);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id  TEXT PRIMARY KEY,
    ip           TEXT,
    day          TEXT,
    tier         TEXT,
    score        TEXT,
    detectors    TEXT,
    alerts       INTEGER,
    email        TEXT,
    first_ts     INTEGER,
    last_ts      INTEGER
);
CREATE INDEX IF NOT EXISTS ix_incidents_tier ON incidents (tier, last_ts);
CREATE INDEX IF NOT EXISTS ix_incidents_ip   ON incidents (ip, last_ts);
CREATE INDEX IF NOT EXISTS ix_incidents_last ON incidents (last_ts);
"""

_TIER_RANK = {"log": 0, "queue": 1, "step_up": 2, "block": 3}


def _ts(alert):
    try:
        return epoch_seconds(alert.get("detected_at") or alert.get("timestamp"))
    except (TypeError, ValueError):
        return None


class SqliteAlertStore:

    def __init__(self, file_path=None, retention_days=None):
        self.file_path = file_path or DEFAULT_PATH
        self.backup_path = self.file_path + ".bak"
        os.makedirs(os.path.dirname(self.file_path) or ".", exist_ok=True)
        if retention_days is None:
            import config
            retention_days = config.ALERT_RETENTION_DAYS
        self.retention_days = int(retention_days)
        self._guard = threading.RLock()
        self._con = self._connect(self.file_path)
        self._cache_key = None
        self._cache = []
        self._last_prune = None
        self._maybe_prune()

    @staticmethod
    def _connect(path):
        con = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.executescript(SCHEMA)
        return con

    def close(self):
        with self._guard:
            self._con.close()

    # ── Writes ──────────────────────────────────────────────────────────

    def _row(self, alert):
        if "llm_explanation" not in alert:
            alert["llm_explanation"] = None
            alert["enriched"] = False
        alert.setdefault("saved_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        inc = alert.get("incident") or {}
        return (alert.get("alert_id"), _ts(alert), alert.get("detected_at"), alert["saved_at"],
                alert.get("ip"), alert.get("user"), alert.get("type"), alert.get("severity"),
                inc.get("incident_id"), inc.get("tier") or (alert.get("response") or {}).get("tier"),
                int(bool(alert.get("enriched"))), json.dumps(alert, ensure_ascii=False, default=str))

    def _upsert_incident(self, cur, alert):
        inc = alert.get("incident")
        if not inc or not inc.get("incident_id"):
            return
        ts = _ts(alert)
        cur.execute(
            "INSERT INTO incidents (incident_id, ip, day, tier, score, detectors, alerts, email, first_ts, last_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(incident_id) DO UPDATE SET tier = excluded.tier, score = excluded.score, "
            "detectors = excluded.detectors, alerts = excluded.alerts, last_ts = excluded.last_ts, "
            "email = CASE WHEN excluded.email = 'not_required' THEN incidents.email ELSE excluded.email END",
            (inc["incident_id"], inc.get("ip"), (alert.get("detected_at") or "")[:10], inc.get("tier"),
             json.dumps(inc.get("score")), json.dumps(inc.get("detectors")), inc.get("alerts"),
             inc.get("email", "not_required"), ts, ts))

    def save_alert(self, alert):
        """Append one alert (one transaction)."""
        self.save_alerts([alert])

    def save_alerts(self, alerts):
        self._maybe_prune()
        with self._guard:
            cur = self._con.cursor()
            cur.execute("BEGIN")
            try:
                for a in alerts:
                    cur.execute("INSERT INTO alerts (alert_id, ts, detected_at, saved_at, ip, user, type, "
                                "severity, incident_id, tier, enriched, body) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", self._row(a))
                    self._upsert_incident(cur, a)
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise

    # ── Retention ───────────────────────────────────────────────────────

    def prune(self, now=None):
        """Delete alerts saved more than retention_days before now (epoch
        seconds, default the current time) and incidents left without
        alerts. Returns (alerts, incidents) deleted."""
        if self.retention_days <= 0:
            return 0, 0
        now = time.time() if now is None else now
        cutoff = (datetime.fromtimestamp(now) - timedelta(days=self.retention_days)
                  ).strftime("%Y-%m-%d %H:%M:%S")
        with self._guard:
            cur = self._con.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                n_alerts = cur.execute("DELETE FROM alerts WHERE saved_at < ?", (cutoff,)).rowcount
                n_inc = 0
                if n_alerts:
                    n_inc = cur.execute(
                        "DELETE FROM incidents WHERE NOT EXISTS (SELECT 1 FROM alerts a "
                        "WHERE a.incident_id = incidents.incident_id)").rowcount
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        if n_alerts:
            log.info("Alert retention (%d days): pruned %d alerts, %d incidents",
                     self.retention_days, n_alerts, n_inc)
        return n_alerts, n_inc

    def _maybe_prune(self):
        """prune() on open and then at most once a day (monotonic clock)."""
        if self.retention_days <= 0:
            return
        t = time.monotonic()
        if self._last_prune is not None and t - self._last_prune < 86400:
            return
        self._last_prune = t
        try:
            self.prune()
        except sqlite3.Error as e:          # never break the pipeline over housekeeping
            log.warning("Alert retention prune failed: %s", e)

    def _update(self, alert_id, mutate):
        with self._guard:
            cur = self._con.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute("SELECT body FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
                if row is None:
                    cur.execute("ROLLBACK")
                    return None
                alert = json.loads(row[0])
                result = mutate(alert)
                cur.execute("UPDATE alerts SET body = ?, severity = ?, enriched = ? WHERE alert_id = ?",
                            (json.dumps(alert, ensure_ascii=False, default=str), alert.get("severity"),
                             int(bool(alert.get("enriched"))), alert_id))
                cur.execute("COMMIT")
                return result
            except BaseException:
                cur.execute("ROLLBACK")
                raise

    def update_fields(self, alert_id, fields):
        return self._update(alert_id, lambda a: a.update(fields) or True) is not None

    def update_explanation(self, alert_id, llm_explanation):
        def mutate(a):
            a["llm_explanation"] = llm_explanation
            a["enriched"] = True
            a["enriched_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return True
        return self._update(alert_id, mutate) is not None

    def mark_enrichment_failed(self, alert_id, reason, final_after):
        def mutate(a):
            attempts = a.get("enrichment_attempts", 0) + 1
            a["enrichment_attempts"] = attempts
            a["enrichment_error"] = str(reason)[:300]
            a["enrichment_failed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if attempts >= final_after:
                a["enrichment_failed"] = True
            return attempts
        return self._update(alert_id, mutate)

    def backup(self):
        """Copy the store to alerts.db.bak. Returns alerts backed up."""
        with self._guard:
            dst = sqlite3.connect(self.backup_path)
            try:
                self._con.backup(dst)
            finally:
                dst.close()
            return self.count()

    def clear(self, backup=True):
        """Empty the store, writing the backup first. Returns alerts cleared."""
        with self._guard:
            n = self.count()
            if backup:
                self.backup()
            self._con.execute("BEGIN IMMEDIATE")
            self._con.execute("DELETE FROM alerts")
            self._con.execute("DELETE FROM incidents")
            self._con.execute("COMMIT")
            return n

    def restore(self):
        """Replace the store with the backup. Returns alerts restored."""
        with self._guard:
            if not os.path.exists(self.backup_path):
                raise FileNotFoundError(self.backup_path)
            src = sqlite3.connect(self.backup_path)
            try:
                src.backup(self._con)
            finally:
                src.close()
            return self.count()

    # ── Reads ───────────────────────────────────────────────────────────

    def count(self):
        with self._guard:
            return self._con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def query(self, limit=CACHED_LIMIT, tier=None, ip=None, incident_id=None, since_ts=None,
              until_ts=None, alert_type=None):
        """Alerts, newest first, filtered on the indexed columns."""
        where, args = [], []
        for col, val in (("tier", tier), ("ip", ip), ("incident_id", incident_id), ("type", alert_type)):
            if val is not None:
                where.append(f"{col} = ?")
                args.append(val)
        if since_ts is not None:
            where.append("ts >= ?")
            args.append(int(since_ts))
        if until_ts is not None:
            where.append("ts < ?")
            args.append(int(until_ts))
        sql = "SELECT body FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._guard:
            return [json.loads(r[0]) for r in self._con.execute(sql, args)]

    def incidents(self, limit=500, tier=None, ip=None, day=None):
        where, args = [], []
        for col, val in (("tier", tier), ("ip", ip), ("day", day)):
            if val is not None:
                where.append(f"{col} = ?")
                args.append(val)
        sql = ("SELECT incident_id, ip, day, tier, score, detectors, alerts, email, first_ts, last_ts "
               "FROM incidents" + (" WHERE " + " AND ".join(where) if where else "")
               + " ORDER BY last_ts DESC LIMIT ?")
        args.append(int(limit))
        with self._guard:
            rows = self._con.execute(sql, args).fetchall()
        keys = ("incident_id", "ip", "day", "tier", "score", "detectors", "alerts", "email",
                "first_ts", "last_ts")
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["score"], d["detectors"] = json.loads(d["score"] or "null"), json.loads(d["detectors"] or "[]")
            out.append(d)
        return out

    def stats(self):
        """Aggregates for /api/stats (whole store)."""
        with self._guard:
            c = self._con
            sev = dict(c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            types = c.execute("SELECT type, COUNT(*) FROM alerts GROUP BY type ORDER BY 2 DESC").fetchall()
            tiers = dict(c.execute("SELECT tier, COUNT(*) FROM incidents GROUP BY tier").fetchall())
            blocked = [r[0] for r in c.execute("SELECT DISTINCT ip FROM incidents WHERE tier = 'block'")]
            stepped = [r[0] for r in c.execute("SELECT DISTINCT ip FROM incidents WHERE tier = 'step_up'")]
            email = dict(c.execute("SELECT email, COUNT(*) FROM incidents GROUP BY email").fetchall())
            total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        return {"severity_counts": sev, "type_counts": types, "incident_tiers": tiers,
                "blocked_ips": blocked, "step_up_ips": stepped, "email": email, "total_alerts": total}

    def hourly(self):
        """Alert counts per hour of day (event time) and severity."""
        with self._guard:
            return self._con.execute(
                "SELECT (ts / 3600) % 24 AS h, severity, COUNT(*) FROM alerts "
                "WHERE ts IS NOT NULL GROUP BY h, severity").fetchall()

    def by_type(self):
        with self._guard:
            return self._con.execute(
                "SELECT type, COUNT(*), MAX(detected_at) FROM alerts GROUP BY type").fetchall()

    def saved_since(self, stamp):
        """Severities of alerts saved at or after stamp ('%Y-%m-%d %H:%M:%S')."""
        with self._guard:
            return [r[0] for r in self._con.execute(
                "SELECT severity FROM alerts WHERE saved_at >= ?", (stamp,))]

    def enrichment_counts(self):
        with self._guard:
            total, enriched = self._con.execute(
                "SELECT COUNT(*), COALESCE(SUM(enriched), 0) FROM alerts").fetchone()
            failed = self._con.execute(
                "SELECT COUNT(*) FROM alerts WHERE enriched = 0 AND "
                "json_extract(body, '$.enrichment_failed') = 1").fetchone()[0]
        return {"total": total, "enriched": enriched, "failed": failed}

    def load_alerts(self):
        """Every alert, oldest first (small stores and tests)."""
        with self._guard:
            return [json.loads(r[0]) for r in self._con.execute("SELECT body FROM alerts ORDER BY id")]

    def load_cached(self):
        """The most recent CACHED_LIMIT alerts, oldest first; re-read only
        when the database changed (PRAGMA data_version + own writes).
        Callers must treat the list as read-only."""
        self._maybe_prune()
        with self._guard:
            key = (self._con.execute("PRAGMA data_version").fetchone()[0], self._con.total_changes)
            if key != self._cache_key:
                rows = self._con.execute(
                    "SELECT body FROM alerts ORDER BY id DESC LIMIT ?", (CACHED_LIMIT,)).fetchall()
                self._cache = [json.loads(r[0]) for r in reversed(rows)]
                self._cache_key = key
            return self._cache
