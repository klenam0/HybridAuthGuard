# backend/main.py
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.log_generator import generate_logs, generate_training_data
from utils.log_parser     import parse_logs
from agents.monitoring_agent import MonitoringAgent
from ml.anomaly_model        import AnomalyDetector


def clear_alerts():
    alerts_path = os.path.join(os.path.dirname(__file__), "data", "alerts.json")
    with open(alerts_path, "w") as f:
        f.write("[]")
    print("🗑️  Cleared previous alerts.\n")


def ensure_data_dir():
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)


def get_or_train_model(base):
    """
    Load pre-trained model if available.
    Falls back to synthetic training on first run.
    """
    model_path    = os.path.join(base, "data", "model.pkl")
    training_path = os.path.join(base, "data", "training_logs.json")

    detector = AnomalyDetector(contamination=0.15)

    if os.path.exists(model_path):
        print("🔄 Loading pre-trained anomaly model...")
        loaded = detector.load_model(model_path)
        if loaded:
            print("🧠 Model ready (offline-trained, inference only).\n")
            return detector
        print("⚠ Failed to load model - retraining...")

    print("📚 First run - generating offline training dataset...")
    generate_training_data(output_path=training_path, n=10000)

    print("\n🏋️  Training anomaly model...")
    trained = detector.train(training_path)

    if trained:
        detector.save_model(model_path)
        print("🧠 Model trained and saved.\n")
    else:
        print("⚠ Training failed - running in rules-only mode.\n")

    return detector


def run_batch(delay=0.5, threshold=5, fresh=True, retrain=False):
    """
    Batch mode: generate logs → parse → detect → respond → exit.
    """
    base             = os.path.dirname(os.path.abspath(__file__))
    raw_logs_path    = os.path.join(base, "data", "raw_logs.txt")
    parsed_logs_path = os.path.join(base, "data", "parsed_logs.json")
    model_path       = os.path.join(base, "data", "model.pkl")

    ensure_data_dir()

    if fresh:
        clear_alerts()

    if retrain and os.path.exists(model_path):
        os.remove(model_path)
        print("🗑️  Removed existing model - will retrain.\n")

    print("=" * 55)
    print("  HYBRIDAUTHGUARD")
    print("=" * 55)

    print("\n[1/3] Generating synthetic log data...")
    generate_logs(output_path=raw_logs_path)

    print("\n[2/3] Parsing logs to structured JSON...")
    parse_logs(input_file=raw_logs_path, output_file=parsed_logs_path)

    print(f"\n[3/3] Starting Monitoring Agent (delay={delay}s, threshold={threshold})...")
    detector = get_or_train_model(base)

    print("-" * 55)
    agent = MonitoringAgent(
        log_file=parsed_logs_path,
        threshold=threshold,
        anomaly_detector=detector,
    )
    agent.stream_logs(delay=delay)
    print("-" * 55)
    print("\n✅ Pipeline complete. Check data/alerts.json for saved alerts.")


def run_live(threshold=5):
    """
    Live streaming mode: continuously read events from /api/ingest queue.
    Runs until Ctrl+C.
    """
    base = os.path.dirname(os.path.abspath(__file__))
    ensure_data_dir()
    clear_alerts()

    print("=" * 55)
    print("  HYBRIDAUTHGUARD — LIVE MODE")
    print("=" * 55)

    detector = get_or_train_model(base)

    print("-" * 55)
    agent = MonitoringAgent(
        threshold=threshold,
        anomaly_detector=detector,
    )
    agent.stream_live(poll_interval=0.5)


if __name__ == "__main__":
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
                        help="Delete saved model and retrain from scratch")
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
        )