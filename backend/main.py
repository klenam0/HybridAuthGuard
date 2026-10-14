# backend/main.py
import logging
import os
import sys
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.log_generator import generate_logs, generate_training_data
from utils.log_parser     import parse_logs
from agents.monitoring_agent import MonitoringAgent
from ml.anomaly_model        import AnomalyDetector
from utils.alert_manager     import open_alert_store
from utils.logging_setup     import configure_logging
import config

log = logging.getLogger(__name__)


def clear_alerts():
    """Back up the alert store (alerts.json or alerts.db), then empty it (audit F25)."""
    store = open_alert_store()
    cleared = store.clear(backup=True)
    log.info(f"🗑️  Cleared previous alerts ({cleared} backed up to "
             f"{os.path.basename(store.backup_path)}).\n")


def ensure_data_dir():
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)


class ModelError(SystemExit):
    """Raised (exits non-zero) when no usable model can be loaded."""


def _model_paths(base):
    data = os.path.join(base, "data")
    return (os.path.join(data, "model.pkl"),
            os.path.join(data, "training_logs.json"),
            os.path.join(data, "model_metrics.json"))


def sync_model_metrics(detector, metrics_path):
    """
    Keep data/model_metrics.json (what the dashboard shows) describing the
    model actually loaded. Writes only when the contents differ.
    """
    wanted = detector.model_metrics()
    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            current = json.load(f)
    except (OSError, ValueError):
        current = None
    if current != wanted:
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(wanted, f, indent=2)
        log.info(f"📝 model_metrics.json updated to match the loaded model "
              f"({wanted.get('trained_on')}, trained {wanted.get('trained_at')})")


def get_or_train_model(base):
    """
    Load data/model.pkl. Never trains or overwrites a model implicitly
    (audit F14): a missing or unloadable model is an error. Train the RBA
    model with ml/train_from_dataset.py, or a synthetic demo model with
    `python main.py --retrain`.
    """
    model_path, _, metrics_path = _model_paths(base)
    detector = AnomalyDetector(contamination=config.SYNTHETIC_FALLBACK_CONTAMINATION)

    if not os.path.exists(model_path):
        raise ModelError(
            f"❌ No model at {model_path}.\n"
            "   Train the RBA model:        python ml/train_from_dataset.py\n"
            "   or a synthetic demo model:  python main.py --retrain"
        )

    log.info("🔄 Loading pre-trained anomaly model...")
    if not detector.load_model(model_path):
        raise ModelError(
            f"❌ {model_path} exists but could not be loaded (see the error above).\n"
            "   Nothing was retrained or overwritten. Fix or replace the file, or\n"
            "   retrain explicitly (python ml/train_from_dataset.py, or\n"
            "   python main.py --retrain --force for the synthetic demo model)."
        )
    sync_model_metrics(detector, metrics_path)
    log.info("🧠 Model ready (offline-trained, inference only).\n")
    return detector


def load_ml(base):
    """
    The ML step for the configured mode. data/model.pkl is loaded only in
    legacy ML mode; in v4 the detection factory loads data/model_v4.pkl
    itself, or runs no ML step when the forest is retired
    (config.ML_V4_IFOREST, eval/PROTOCOL.md amendment 6).
    """
    if config.ML_MODE == "legacy":
        return get_or_train_model(base)
    log.info(f"🧠 ML_MODE {config.ML_MODE!r}: data/model.pkl not loaded "
             f"(v4 forest: {config.ML_V4_IFOREST}).\n")
    return None


def train_synthetic_model(base, force=False):
    """
    Explicit, opt-in: train the small synthetic fallback model and save it
    as data/model.pkl. Refuses to replace an RBA-trained model unless
    force=True, in which case the old file is renamed, not deleted.
    """
    model_path, training_path, metrics_path = _model_paths(base)
    if os.path.exists(model_path):
        existing = AnomalyDetector()
        loaded = existing.load_model(model_path)
        if loaded and existing.is_rba_model() and not force:
            raise ModelError(
                f"❌ Refusing to overwrite the RBA-trained model at {model_path}\n"
                "   with a synthetic demo model. Pass --force to replace it (the old\n"
                "   file is kept as model.pkl.replaced-<timestamp>)."
            )
        if not loaded and not force:
            raise ModelError(
                f"❌ {model_path} exists but could not be loaded; not overwriting it\n"
                "   without --force."
            )
        aside = f"{model_path}.replaced-{datetime.now():%Y%m%d-%H%M%S}"
        os.replace(model_path, aside)
        log.info(f"📦 Existing model moved to {aside}")

    detector = AnomalyDetector(contamination=config.SYNTHETIC_FALLBACK_CONTAMINATION)
    log.info("📚 Generating synthetic training dataset...")
    generate_training_data(output_path=training_path, n=10000)
    log.info("\n🏋️  Training synthetic anomaly model...")
    if not detector.train(training_path):
        raise ModelError("❌ Synthetic training failed; no model written.")
    detector.save_model(model_path)
    detector.metadata = {"model_kind": "synthetic",
                         "trained_on": "Synthetic fallback data (utils/log_generator.py)",
                         "trained_at": datetime.now().isoformat()}
    sync_model_metrics(detector, metrics_path)
    log.info("🧠 Synthetic model trained and saved.\n")


def run_batch(delay=0.5, threshold=5, fresh=True, retrain=False, force=False):
    """
    Batch mode: generate logs → parse → detect → respond → exit.
    """
    base             = os.path.dirname(os.path.abspath(__file__))
    raw_logs_path    = os.path.join(base, "data", "raw_logs.txt")
    parsed_logs_path = os.path.join(base, "data", "parsed_logs.json")

    ensure_data_dir()

    if fresh:
        clear_alerts()            # backs up first
    else:
        open_alert_store().backup()   # keep a restore point for this run

    if retrain:
        train_synthetic_model(base, force=force)

    log.info("=" * 55)
    log.info("  HYBRIDAUTHGUARD")
    log.info("=" * 55)

    log.info("\n[1/3] Generating synthetic log data...")
    generate_logs(output_path=raw_logs_path)

    log.info("\n[2/3] Parsing logs to structured JSON...")
    parse_logs(input_file=raw_logs_path, output_file=parsed_logs_path)

    log.info(f"\n[3/3] Starting Monitoring Agent (delay={delay}s, threshold={threshold})...")
    detector = load_ml(base)

    log.info("-" * 55)
    agent = MonitoringAgent(
        log_file=parsed_logs_path,
        threshold=threshold,
        anomaly_detector=detector,
    )
    agent.stream_logs(delay=delay)
    log.info("-" * 55)
    log.info("\n✅ Pipeline complete. Check data/alerts.json for saved alerts.")


def run_live(threshold=5):
    """
    Live streaming mode: continuously read events from /api/ingest queue.
    Runs until Ctrl+C.
    """
    base = os.path.dirname(os.path.abspath(__file__))
    ensure_data_dir()
    clear_alerts()

    log.info("=" * 55)
    log.info("  HYBRIDAUTHGUARD — LIVE MODE")
    log.info("=" * 55)

    detector = load_ml(base)

    log.info("-" * 55)
    agent = MonitoringAgent(
        threshold=threshold,
        anomaly_detector=detector,
    )
    agent.stream_live(poll_interval=0.5)


if __name__ == "__main__":
    configure_logging()
    parser = argparse.ArgumentParser(
        description="HybridAuthGuard: hybrid rule-based and Isolation Forest authentication threat detection"
    )
    parser.add_argument("--delay",     type=float, default=0.5,
                        help="Seconds between events in batch mode (default: 0.5)")
    parser.add_argument("--threshold", type=int,   default=5,
                        help="Failed login threshold for brute force (default: 5)")
    parser.add_argument("--no-fresh",  action="store_true",
                        help="Keep existing alerts (batch mode only)")
    parser.add_argument("--retrain",   action="store_true",
                        help="Train the synthetic demo model and save it as data/model.pkl "
                             "(refuses to replace an RBA-trained model without --force)")
    parser.add_argument("--force",     action="store_true",
                        help="With --retrain: replace an existing RBA model "
                             "(the old file is renamed, not deleted)")
    parser.add_argument("--live",      action="store_true",
                        help="Run in live streaming mode (reads from /api/ingest queue)")

    args = parser.parse_args()

    if args.live:
        run_live(threshold=args.threshold)
    else:
        run_batch(
            delay=args.delay,
            threshold=args.threshold,
            fresh=not args.no_fresh,
            retrain=args.retrain,
            force=args.force,
        )