# backend/tests/test_harness_equivalence.py
"""
LiveScorer (deployed AnomalyDetector.score_event, per event) and
PrecomputedScorer (one batch over causally built features) must give the
same is_anomaly, anomaly_score and confidence for every scored event, in the
same order, and therefore the same alerts.

Run from backend/:  python -m unittest tests.test_harness_equivalence -v
Needs data/model.pkl and results/rba_sample_cache.pkl; skips otherwise.
"""

import contextlib
import io
import json
import os
import sys
import unittest

import numpy as np

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from eval import harness, streams  # noqa: E402
from ml.anomaly_model import AnomalyDetector  # noqa: E402

N_EVENTS = 5000


def load_detector():
    d = AnomalyDetector()
    with contextlib.redirect_stdout(io.StringIO()):
        assert d.load_model(streams.MODEL_PATH)
    return d


class _Spy:
    """Wraps the live model/scaler to capture unrounded inputs and outputs."""

    def __init__(self, detector):
        self.raw_rows, self.decisions = [], []
        model, scaler = detector.model, detector.scaler
        spy = self

        class Scaler:
            def transform(self, X):
                spy.raw_rows.append(np.array(X[0], dtype=np.float64))
                return scaler.transform(X)

        class Model:
            def predict(self, X):
                return model.predict(X)

            def decision_function(self, X):
                d = model.decision_function(X)
                spy.decisions.append(float(d[0]))
                return d

        detector.scaler, detector.model = Scaler(), Model()


def compare(test, events):
    live_det = load_detector()
    spy = _Spy(live_det)
    live = harness.replay(events, harness.LiveScorer(live_det))
    pre_scorer = harness.PrecomputedScorer(load_detector())
    pre = harness.replay(events, pre_scorer)
    # Bit-for-bit: unscaled features and unrounded decision_function values.
    test.assertEqual(len(spy.raw_rows), len(pre_scorer.raw))
    raw_live = np.vstack(spy.raw_rows) if spy.raw_rows else np.zeros((0, 10))
    bad_rows = np.where((raw_live != pre_scorer.raw).any(axis=1))[0]
    test.assertEqual(bad_rows[:5].tolist(), [], f"{len(bad_rows)} feature rows differ")
    bad_dec = np.where(np.array(spy.decisions) != pre_scorer.decision)[0]
    test.assertEqual(bad_dec[:5].tolist(), [], f"{len(bad_dec)} decision values differ")
    # Score-once (audit F21): the flag derived from decision_function must
    # equal what model.predict() returns for the same rows.
    det = pre_scorer.detector
    if len(pre_scorer.raw):
        predicted = det.model.predict(det.scaler.transform(pre_scorer.raw))
        test.assertTrue(np.array_equal(predicted, pre_scorer.pred), "derived flag != predict()")
    test.assertEqual(len(live.scorer_calls), len(pre.scorer_calls), "scored-event count")
    mismatches = [
        (i, a, b) for i, ((ka, a), (kb, b))
        in enumerate(zip(live.scorer_calls, pre.scorer_calls))
        if ka != kb or (a["is_anomaly"], a["anomaly_score"], a["confidence"])
        != (b["is_anomaly"], b["anomaly_score"], b["confidence"])
    ]
    test.assertEqual(mismatches[:5], [], f"{len(mismatches)} scored events differ")
    test.assertEqual(live.alert_type, pre.alert_type)
    test.assertEqual(live.severity, pre.severity)
    test.assertEqual(live.rule_block_idx, pre.rule_block_idx)
    test.assertEqual(live.ml_block_idx, pre.ml_block_idx)
    test.assertEqual(live.response_block_idx, pre.response_block_idx)
    return live


@unittest.skipUnless(os.path.exists(streams.MODEL_PATH), "data/model.pkl missing")
class HarnessEquivalence(unittest.TestCase):

    @unittest.skipUnless(os.path.exists(streams.CACHE_PATH), "RBA sample cache missing")
    def test_rba_whole_ip_sample(self):
        events, truth = streams.rba_test_stream()
        sample, _ = streams.ip_sample(events, truth, N_EVENTS)
        self.assertEqual(len(sample), N_EVENTS)
        live = compare(self, sample)
        print(f"\n  sample: {len(sample)} events, {int(live.ml_scored.sum())} ML-scored, "
              f"{int(live.flagged.sum())} alerts, {len(live.rule_block_idx)} rule-blocked IPs, "
              f"{len(live.ml_block_idx)} ML-blocked IPs")
        # The sample must actually exercise the paths that matter.
        self.assertGreater(int(live.ml_scored.sum()), 1000)
        self.assertLess(int(live.ml_scored.sum()), N_EVENTS)   # rules intercept some
        self.assertGreater(len(live.rule_block_idx), 0)
        self.assertGreater(len(live.ml_block_idx), 0)

    def test_batch_demo_stream(self):
        # No country/device fields: exercises the missing-field defaults.
        with open(os.path.join(BACKEND, "data", "parsed_logs.json")) as f:
            events = json.load(f)
        compare(self, events)


if __name__ == "__main__":
    unittest.main()
