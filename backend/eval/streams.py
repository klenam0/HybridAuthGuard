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


def _shared_strings(series, missing=None):
    """Per-row str values that share one object per distinct value."""
    cat = series.astype("category")
    names = cat.cat.categories.astype(str).to_numpy(dtype=object)
    if missing is not None:
        names = np.where((names == "") | (names == "nan"), missing, names).astype(object)
    out = names[cat.cat.codes.to_numpy()]
    if missing is not None:
        out[cat.cat.codes.to_numpy() < 0] = missing
    return out


def events_from_frame(df):
    """
    (events, truth) for a time-ordered frame from eval/datasets.py, with the
    field mapping of eval/PROTOCOL.md: timestamp truncated to whole seconds,
    user = str(User ID), missing (empty) Country -> "XX" and Device Type ->
    "Unknown", attack = Is Attack IP or Is Account Takeover. Same event shape
    as rba_test_stream().
    """
    secs = df["Login Timestamp"].to_numpy().astype("datetime64[s]")
    stamps = [s.replace("T", " ") for s in np.datetime_as_string(secs, unit="s")]
    ips = _shared_strings(df["IP Address"])
    users = _shared_strings(df["User ID"])
    countries = _shared_strings(df["Country"], missing="XX")
    devices = _shared_strings(df["Device Type"], missing="Unknown")
    status = np.array(["FAILED", "SUCCESS"], dtype=object)[
        df["Login Successful"].to_numpy().astype(np.int8)]
    events = [
        {"ip": ip, "user": u, "timestamp": t, "status": s,
         "country": c, "device_type": d}
        for ip, u, t, s, c, d in zip(ips, users, stamps, status, countries, devices)
    ]
    truth = (df["Is Attack IP"].to_numpy() | df["Is Account Takeover"].to_numpy())
    return events, truth.astype(bool)


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
