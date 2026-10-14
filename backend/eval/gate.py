# backend/eval/gate.py
"""
Reproduction gate. Replays the seed-42 user-disjoint RBA test stream through
the real agents (eval/harness.py, PrecomputedScorer, data/model.pkl) and
compares with the published references:

  deployed margin (-0.02)  vs audit experiment E8 (deployed DetectionAgent)
  margin 0.0               vs Batch 5 seed 42 (ReplayDetectorV4, full-stream
                           failed_rate; differences are audit finding F20)
  rules only               vs Batch 5 seed 42 rules_only

The output contains no timings or timestamps, so two runs on unchanged
detection logic must be byte-identical.

Run from backend/:  python -m eval.gate --out results/phase0_gate.txt
"""

import argparse
import contextlib
import io
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402
from eval import harness, streams  # noqa: E402
from ml.anomaly_model import AnomalyDetector  # noqa: E402

RESULTS = os.path.join(BACKEND, "results")

# Audit experiment E8 (2026-10-12): deployed DetectionAgent + model.pkl.
E8_DEPLOYED = {"campaign_recall": 0.4829, "fpr": 0.1768, "event_recall": 0.2151}
# Fallbacks if backend/results/batch5*_results.json are not present.
BATCH5_FALLBACK = {
    "hybrid": {"campaign_recall": 0.5998, "fpr": 0.2661, "event_recall": 0.2844},
    "rules_only": {"fpr": 0.0547, "event_recall": 0.0816},
}


def batch5_reference():
    ref = json.loads(json.dumps(BATCH5_FALLBACK))
    source = "built-in fallback values"
    p5 = os.path.join(RESULTS, "batch5_results.json")
    p5b = os.path.join(RESULTS, "batch5b_results.json")
    if os.path.exists(p5) and os.path.exists(p5b):
        b5 = json.load(open(p5))["per_seed"][0]
        b5b = json.load(open(p5b))["per_seed"][0]["evaluated_score_lt_0"]["hybrid"]
        assert json.load(open(p5))["per_seed"][0]["seed"] == 42
        ref = {
            "hybrid": {"campaign_recall": b5b["campaign_recall"],
                       "fpr": b5["hybrid"]["fpr"], "event_recall": b5["hybrid"]["recall"]},
            "rules_only": {"fpr": b5["rules_only"]["fpr"],
                           "event_recall": b5["rules_only"]["recall"]},
        }
        source = "results/batch5_results.json + batch5b_results.json, seed 42"
    return ref, source


def load_detector():
    d = AnomalyDetector()
    with contextlib.redirect_stdout(io.StringIO()):
        if not d.load_model(streams.MODEL_PATH):
            raise SystemExit("could not load data/model.pkl")
    return d


def fmt_summary(name, s, lines):
    lines.append(f"[{name}]")
    for k in ("events", "attack_events", "benign_events", "attacking_ips", "benign_ips",
              "benign_users", "ml_scored_events", "alerts", "emails"):
        lines.append(f"  {k:28s} {s[k]}")
    for k in ("event_recall", "campaign_recall", "fpr", "precision"):
        lines.append(f"  {k:28s} {s[k]:.4f}  ({s[k]!r})")
    lines.append("  alert breakdown (type | severity | confidence [truth]):")
    for k, v in s["breakdown"].items():
        lines.append(f"    {k:60s} {v}")
    for block in ("detector_suppression", "response_blocks"):
        lines.append(f"  {block}:")
        for k, v in s[block].items():
            lines.append(f"    {k:32s} {v}")
    lines.append("")


def compare(label, got, ref, lines):
    ok = True
    for k, v in ref.items():
        match = round(got[k], 4) == round(v, 4)
        ok &= match
        lines.append(f"  {label:34s} {k:16s} got {got[k]:.4f}  ref {v:.4f}  "
                     f"diff {got[k] - v:+.4f}  {'MATCH' if match else 'DIFFERENT'}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(RESULTS, "phase0_gate.txt"))
    args = ap.parse_args()
    # The gate reproduces the legacy engine and model whatever the defaults
    # are (v3 / v4 since Phase 5): legacy is set explicitly.
    with harness.override_config(RULES_MODE="legacy", ML_MODE="legacy"):
        return _run(args)


def _run(args):

    events, truth = streams.rba_test_stream()
    det = load_detector()
    lines = [
        "HybridAuthGuard reproduction gate",
        f"model: data/model.pkl, trained_at {_trained_at()}",
        "stream: RBA sample cache, seed-42 user-disjoint split, test partition, time-sorted",
        f"config: ML_ALERT_MARGIN={config.ML_ALERT_MARGIN} "
        f"CONFIDENCE_HIGH_CUTOFF={config.CONFIDENCE_HIGH_CUTOFF} "
        f"CONFIDENCE_MEDIUM_CUTOFF={config.CONFIDENCE_MEDIUM_CUTOFF} "
        f"BRUTE_FORCE_THRESHOLD={config.BRUTE_FORCE_THRESHOLD}",
        "",
    ]

    deployed = harness.summarize(
        harness.replay(events, harness.PrecomputedScorer(det)), events, truth)
    with harness.override_config(ML_ALERT_MARGIN=0.0):
        margin0 = harness.summarize(
            harness.replay(events, harness.PrecomputedScorer(load_detector())), events, truth)
    rules = harness.summarize(harness.replay(events, None), events, truth)

    fmt_summary(f"hybrid, deployed margin {config.ML_ALERT_MARGIN}", deployed, lines)
    fmt_summary("hybrid, margin 0.0 (evaluated policy)", margin0, lines)
    fmt_summary("rules only", rules, lines)

    ref5, source = batch5_reference()
    lines.append("COMPARISONS (rounded to 4 dp)")
    ok_e8 = compare("deployed vs audit E8", deployed, E8_DEPLOYED, lines)
    lines.append(f"  -> deployed-threshold reproduction of E8: {'PASS' if ok_e8 else 'FAIL'}")
    lines.append(f"  Batch 5 reference source: {source}")
    compare("margin 0 vs Batch 5 hybrid", margin0, ref5["hybrid"], lines)
    lines.append("  -> differences here are expected: Batch 5 computes failed_rate over")
    lines.append("     every event, the real agent only over events that reach the ML")
    lines.append("     step (audit F20). The diff column is the size of that effect.")
    ok_rules = compare("rules only vs Batch 5 rules_only", rules, ref5["rules_only"], lines)
    lines.append(f"  -> rules-only reproduction of Batch 5: {'PASS' if ok_rules else 'FAIL'}")
    lines.append("")

    text = "\n".join(lines) + "\n"
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(text)
    return 0 if (ok_e8 and ok_rules) else 1


def _trained_at():
    import joblib
    return joblib.load(streams.MODEL_PATH).get("trained_at", "unknown")


if __name__ == "__main__":
    sys.exit(main())
