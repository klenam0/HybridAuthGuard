# backend/eval/streams.py
"""
Event streams for the harness. The RBA test stream reuses the evaluation's
own split and stream construction (train_from_dataset_v2.user_disjoint_split,
evaluate_hybrid_batch37.sort_stream_df / events_from_sorted_df) so harness
numbers are directly comparable with Batch 5 / 5b and audit experiment E8.
"""

import contextlib
import io
import os
import sys

import numpy as np
import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML_DIR = os.path.join(BACKEND, "ml")
CACHE_PATH = os.path.join(BACKEND, "results", "rba_sample_cache.pkl")
MODEL_PATH = os.path.join(BACKEND, "data", "model.pkl")


def _ml_imports():
    if ML_DIR not in sys.path:
        sys.path.insert(0, ML_DIR)
    from train_from_dataset_v2 import user_disjoint_split
    from evaluate_hybrid_batch37 import sort_stream_df, events_from_sorted_df
    return user_disjoint_split, sort_stream_df, events_from_sorted_df


def rba_test_stream(cache_path=CACHE_PATH):
    """(events, truth) for the seed-42 user-disjoint test split, time-sorted."""
    user_disjoint_split, sort_stream_df, events_from_sorted_df = _ml_imports()
    with contextlib.redirect_stdout(io.StringIO()):
        normal_df, attack_df = pd.read_pickle(cache_path)
        _, _, test_df = user_disjoint_split(normal_df, attack_df)
    events, truth = events_from_sorted_df(sort_stream_df(test_df))
    for e in events:
        e.pop("ts", None)        # the agents parse "timestamp" themselves
    return events, np.asarray(truth, dtype=bool)


def ip_sample(events, truth, n_events, seed=42):
    """
    Whole-IP sample: keeps every event of each chosen IP (so failed_rate
    counters, rule blocks and ML blocks all evolve as in the full stream),
    adding IPs in random order until n_events is reached. Stream order is kept.
    """
    by_ip = {}
    for i, e in enumerate(events):
        by_ip.setdefault(e["ip"], []).append(i)
    ips = sorted(by_ip)
    np.random.RandomState(seed).shuffle(ips)
    chosen, total = set(), 0
    for ip in ips:
        if total >= n_events:
            break
        chosen.add(ip)
        total += len(by_ip[ip])
    idx = sorted(i for ip in chosen for i in by_ip[ip])[:n_events]
    return [events[i] for i in idx], np.asarray(truth)[idx]
