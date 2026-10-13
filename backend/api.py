# backend/api.py

import os
import sys
import json
import subprocess
import threading
from datetime import datetime, timezone
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from flask import Flask, jsonify, request
from flask_cors import CORS
from utils.llm_analyzer import LLMAnalyzer
import config
from utils.event_schema import normalize_event

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.INGEST_MAX_BODY_BYTES
CORS(app)


@app.errorhandler(413)
def body_too_large(_e):
    return jsonify({"error": f"Body larger than {config.INGEST_MAX_BODY_BYTES} bytes"}), 413

BASE         = os.path.dirname(os.path.abspath(__file__))
ALERTS_PATH  = os.path.join(BASE, "data", "alerts.json")
STATS_PATH   = os.path.join(BASE, "data", "pipeline_stats.json")
METRICS_PATH = os.path.join(BASE, "data", "model_metrics.json")
QUEUE_PATH = os.path.join(BASE, "data", "live_queue.jsonl")

SERVER_START_TIME = datetime.now(timezone.utc)

# ── LLM enrichment service ─────────────────────────────────────────────────────
# Defined AFTER ALERTS_PATH so the path is available when start_llm_service runs
_llm_analyzer = None

def start_llm_service():
    global _llm_analyzer
    try:
        _llm_analyzer = LLMAnalyzer(alerts_path=ALERTS_PATH)
    except Exception as e:
        print(f"⚠ LLM service failed to start: {e}")


# ── Pipeline status ────────────────────────────────────────────────────────────
pipeline_status = {
    "running":    False,
    "started_at": None,
}


def run_pipeline_thread(delay=0.3, threshold=5):
    """Run main.py in background so API stays responsive."""
    pipeline_status["running"]    = True
    pipeline_status["started_at"] = datetime.now(timezone.utc).isoformat()
    subprocess.run(
        [
            sys.executable,
            os.path.join(BASE, "main.py"),
            "--delay",     str(delay),
            "--threshold", str(threshold),
        ],
        cwd=BASE
    )
    pipeline_status["running"] = False


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def get_alerts():
    """Return all alerts from alerts.json."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
        try:
            alerts = json.loads(content)
        except json.JSONDecodeError:
            print("⚠ alerts.json corrupted - returning empty list")
            return jsonify([])
        return jsonify(alerts)
    except FileNotFoundError:
        return jsonify([])


@app.route("/api/status")
def get_status():
    """Return system status."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        alert_count = len(alerts)
    except Exception:
        alert_count = 0

    uptime_seconds = int(
        (datetime.now(timezone.utc) - SERVER_START_TIME).total_seconds()
    )

    return jsonify({
        "running":           pipeline_status["running"],
        "alert_count":       alert_count,
        "model_loaded":      os.path.exists(os.path.join(BASE, "data", "model.pkl")),
        "server_start_time": SERVER_START_TIME.isoformat(),
        "uptime_seconds":    uptime_seconds,
        "detectors": [
            "ML Anomaly Detection" if d == "ML Anomaly Detected" else d
            for d in config.DETECTORS
        ],
    })


@app.route("/api/config")
def get_config():
    """Read-only detection, severity and response policy (backend/config.py)."""
    return jsonify(config.public_config())


@app.route("/api/run", methods=["POST"])
def run_pipeline():
    """Trigger a fresh pipeline run."""
    if pipeline_status["running"]:
        return jsonify({"message": "Pipeline already running"})

    body      = request.get_json(silent=True) or {}
    delay     = float(body.get("delay",     0.3))
    threshold = int(body.get("threshold",   5))

    thread = threading.Thread(
        target=run_pipeline_thread,
        args=(delay, threshold),
        daemon=True
    )
    thread.start()
    return jsonify({
        "message":   "Pipeline started",
        "delay":     delay,
        "threshold": threshold,
    })


@app.route("/api/stats")
def get_stats():
    """Return aggregated stats for charts."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        alerts = []

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_counts     = {}
    blocked_ips     = set()

    for alert in alerts:
        severity = alert.get("severity", "LOW")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        alert_type = alert.get("type", "Unknown")
        type_counts[alert_type] = type_counts.get(alert_type, 0) + 1

        if severity == "HIGH":
            blocked_ips.add(alert.get("ip", ""))

    return jsonify({
        "severity_counts": severity_counts,
        "type_counts": [
            {"name": k, "count": v}
            for k, v in type_counts.items()
        ],
        "blocked_ips":  list(blocked_ips),
        "total_alerts": len(alerts),
    })


@app.route("/api/timeline")
def get_timeline():
    """
    Returns alert counts grouped by hour for timeline chart.
    Always returns all 24 hours - empty hours return zero.
    """
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        alerts = []

    hours = {
        h: {"hour": h, "total": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for h in range(24)
    }

    for alert in alerts:
        detected_at = alert.get("detected_at", "")
        if not detected_at:
            continue
        try:
            dt       = datetime.strptime(detected_at, "%Y-%m-%d %H:%M:%S")
            hour     = dt.hour
            severity = alert.get("severity", "LOW")
            hours[hour]["total"]    += 1
            hours[hour][severity]   += 1
        except Exception:
            continue

    return jsonify(list(hours.values()))


@app.route("/api/model-info")
def get_model_info():
    """Return real ML model metrics from training."""
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})


@app.route("/api/pipeline-stats")
def get_pipeline_stats():
    """Return real pipeline execution stats."""
    try:
        with open(STATS_PATH, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({})


@app.route("/api/agents")
def get_agents():
    """Return agent stats from pipeline stats + alerts."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        alerts = []

    try:
        with open(STATS_PATH, "r", encoding="utf-8") as f:
            stats = json.load(f)
    except Exception:
        stats = {}

    processed = stats.get("events_processed", 0)
    generated = stats.get("alerts_generated", len(alerts))
    last_run  = stats.get("last_run", "-")

    return jsonify([
        {
            "name":     "Monitoring Stage",
            "role":     "Orchestrator",
            "status":   "active",
            "processed": processed,
            "alerts":   generated,
            "queue":    0,
            "success":  100,
            "last_run": last_run,
        },
        {
            "name":     "Detection Stage",
            "role":     "Threat Detection Engine",
            "status":   "active",
            "processed": processed,
            "alerts":   generated,
            "queue":    0,
            "success":  100,
            "last_run": last_run,
        },
        {
            "name":     "Analysis Stage",
            "role":     "Alert Intelligence",
            "status":   "active",
            "processed": generated,
            "alerts":   generated,
            "queue":    0,
            "success":  100,
            "last_run": last_run,
        },
    ])


@app.route("/api/detectors")
def get_detectors():
    """Return per-detector stats from real alert data."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        alerts = []

    DETECTOR_CONFIG = [
        ("Suspicious Login Time", False),
        ("Multiple IP Login",     False),
        ("Brute Force Attack",    False),
        ("Slow Brute Force",      False),
        ("Credential Stuffing",   False),
        ("ML Anomaly Detected",   True),
    ]

    type_data = {}
    for alert in alerts:
        t = alert.get("type", "Unknown")
        if t not in type_data:
            type_data[t] = {"count": 0, "last": None}
        type_data[t]["count"] += 1
        detected_at = alert.get("detected_at", "")
        if detected_at:
            if type_data[t]["last"] is None or detected_at > type_data[t]["last"]:
                type_data[t]["last"] = detected_at

    now    = datetime.now()
    result = []

    for name, is_ml in DETECTOR_CONFIG:
        d        = type_data.get(name, {"count": 0, "last": None})
        count    = d["count"]
        last_str = "Never"

        if d["last"]:
            try:
                last_dt  = datetime.strptime(d["last"], "%Y-%m-%d %H:%M:%S")
                diff = (now - last_dt).total_seconds()
                if diff < 0:
                    last_str = "just now"
                elif diff < 60:
                    last_str = f"{int(diff)}s ago"
                elif diff < 3600:
                    last_str = f"{int(diff / 60)}m ago"
                elif diff < 86400:
                    last_str = f"{int(diff / 3600)}h ago"
                else:
                    last_str = d["last"].split(" ")[0]
            except Exception:
                last_str = "-"

        result.append({
            "name":   name,
            "alerts": count,
            "last":   last_str,
            "is_ml":  is_ml,
        })

    return jsonify(result)


@app.route("/api/threat-level")
def get_threat_level():
    """Compute real threat level from current alerts."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
    except Exception:
        alerts = []

    if not alerts:
        return jsonify({"level": "NORMAL", "color": "green"})

    severities = {a.get("severity", "LOW") for a in alerts}

    if "HIGH" in severities:
        return jsonify({"level": "HIGH",   "color": "orange"})
    elif "MEDIUM" in severities:
        return jsonify({"level": "MEDIUM", "color": "amber"})
    else:
        return jsonify({"level": "LOW",    "color": "blue"})


@app.route("/api/enrichment-status")
def get_enrichment_status():
    """Return how many alerts are pending LLM enrichment."""
    try:
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        total    = len(alerts)
        enriched = sum(1 for a in alerts if a.get("enriched"))
        pending  = total - enriched
        return jsonify({
            "total":         total,
            "enriched":      enriched,
            "pending":       pending,
            "llm_available": _llm_analyzer.available if _llm_analyzer else False,
        })
    except Exception:
        return jsonify({
            "total": 0, "enriched": 0, "pending": 0, "llm_available": False
        })


@app.route("/api/clear-alerts", methods=["POST"])
def clear_alerts():
    """Clear all alerts - requires X-Clear-Token header."""
    token          = request.headers.get("X-Clear-Token", "")
    expected_token = os.environ.get("CLEAR_TOKEN")
    if not expected_token or token != expected_token:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        with open(ALERTS_PATH, "w", encoding="utf-8") as f:
            f.write("[]")
        return jsonify({"message": "Alerts cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/restore-alerts", methods=["POST"])
def restore_alerts():
    """Restore alerts.json from the most recent backup."""
    token = request.headers.get("X-Clear-Token", "")
    expected_token = os.environ.get("CLEAR_TOKEN")
    if not expected_token or token != expected_token:
        return jsonify({"error": "Unauthorized"}), 401

    backup_path = ALERTS_PATH + ".bak"
    try:
        if not os.path.exists(backup_path):
            return jsonify({"error": "No backup found"}), 404
        import shutil
        shutil.copy2(backup_path, ALERTS_PATH)
        with open(ALERTS_PATH, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        return jsonify({
            "message": f"Restored {len(alerts)} alerts from backup"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ingest", methods=["POST"])
def ingest_event():
    """
    Accept a single login event and append it to the live queue.
    Used by live_simulator.py and any external log source.
    """
    raw = request.get_json(silent=True)
    if raw is None:
        return jsonify({"error": "Body must be JSON"}), 400

    # Validate and normalise (utils/event_schema.py, audit F05/F32/F36).
    event, error = normalize_event(raw)
    if error:
        return jsonify({"error": error}), 400

    try:
        from filelock import FileLock
        with FileLock(QUEUE_PATH + ".lock", timeout=5):
            with open(QUEUE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        return jsonify({"status": "queued", "timestamp": event["timestamp"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/queue/stats")
def queue_stats():
    """Return live queue statistics."""
    try:
        with open(QUEUE_PATH, "r", encoding="utf-8") as f:
            total_lines = sum(1 for line in f if line.strip())
    except FileNotFoundError:
        total_lines = 0

    # The live consumer stores a byte offset ({"offset": N}); count the
    # non-empty lines before it.
    try:
        with open(QUEUE_PATH + ".cursor", "r") as f:
            offset = int(json.loads(f.read())["offset"])
    except Exception:
        offset = 0
    processed = 0
    try:
        with open(QUEUE_PATH, "rb") as f:
            consumed = f.read(offset)
        processed = sum(1 for line in consumed.split(b"\n") if line.strip())
    except FileNotFoundError:
        pass

    return jsonify({
        "total_queued": total_lines,
        "processed":    processed,
        "pending":      max(0, total_lines - processed),
        "live_mode":    True,
    })


@app.route("/api/queue/clear", methods=["POST"])
def clear_queue():
    """Clear the live event queue."""
    token = request.headers.get("X-Clear-Token", "")
    expected_token = os.environ.get("CLEAR_TOKEN")
    if not expected_token or token != expected_token:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with open(QUEUE_PATH, "w") as f:
            f.write("")
        with open(QUEUE_PATH + ".cursor", "w") as f:
            json.dump({"offset": 0}, f)
        return jsonify({"message": "Queue cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ── Startup ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🚀 HybridAuthGuard API running at http://localhost:5000")
    print("   Open frontend in browser to view dashboard")
    start_llm_service()
    app.run(debug=False, port=5000)