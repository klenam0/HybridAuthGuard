# backend/eval/datasets.py
"""
Loaders for the Phase 2 evaluation protocol (eval/PROTOCOL.md). The split
boundaries are fixed here and nowhere else.

  dev_train      2020-02-03 00:00 <= t < 2020-03-30 00:00   (first 8 weeks)
  dev_val        2020-03-30 00:00 <= t < 2020-05-01 00:00   (rest of April)
  dev_val_cold   dev_val rows whose User ID never occurs in dev_train
  test           2020-05-01 00:00 <= t < 2020-06-01 00:00   (LOCKED)

Development rows come from data/rba_parquet (written by eval/convert_rba.py).
The test month lives in a separate file, data/rba_locked/, and load("test")
raises unless the environment variable FINAL_EVAL is exactly "1". Every call
to load("test"), allowed or refused, is logged to results/test_access.log
with its time, process id and command line.

Rows are returned in file order, which is time order: the CSV is
time-ordered (results/rba_conversion_stats.json) and the conversion keeps
row order, so ties keep their CSV order and "index" is increasing.
Low-cardinality string columns and "IP Address" come back as pandas
categoricals.
"""

import datetime as _dt
import logging
import os
import sys

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARQUET_DIR = os.path.join(BACKEND, "data", "rba_parquet")
TEST_FILE = os.path.join(BACKEND, "data", "rba_locked", "test_2020-05.parquet")
ACCESS_LOG = os.path.join(BACKEND, "results", "test_access.log")

DEV_START = pd.Timestamp("2020-02-03 00:00:00")    # first day with data, a Monday
DEV_TRAIN_END = DEV_START + pd.Timedelta(weeks=8)  # 2020-03-30 00:00:00
DEV_END = pd.Timestamp("2020-05-01 00:00:00")
TEST_START = DEV_END
TEST_END = pd.Timestamp("2020-06-01 00:00:00")
DEV_MONTHS = ("2020-02", "2020-03", "2020-04")

TS = "Login Timestamp"
# Stored as plain strings (high cardinality) but read as categoricals, which
# keeps a development-window frame within a few GB.
DICT_ON_READ = ["IP Address"]
SPLITS = ("dev_train", "dev_val", "dev_val_cold", "dev", "test")

log = logging.getLogger(__name__)


class TestSetLocked(PermissionError):
    """Raised when the locked test split is requested without FINAL_EVAL=1."""


def _month_file(month):
    return os.path.join(PARQUET_DIR, f"month={month}", "part-0.parquet")


def _read(paths, start, end, columns):
    cols = None if columns is None else list(dict.fromkeys([*columns, TS]))
    parts = []
    for p in paths:
        t = pq.read_table(p, columns=cols, read_dictionary=DICT_ON_READ)
        ts = t.column(TS)
        mask = pc.and_(pc.greater_equal(ts, start.to_datetime64()),
                       pc.less(ts, end.to_datetime64()))
        parts.append(t.filter(mask))
    df = pa.concat_tables(parts).unify_dictionaries().to_pandas()
    if columns is not None and TS not in columns:
        df = df.drop(columns=TS)
    return df


def _log_test_access(allowed):
    line = (f"{_dt.datetime.now().isoformat(timespec='seconds')}\t"
            f"{'ALLOWED' if allowed else 'REFUSED'}\tpid={os.getpid()}\t"
            f"argv={' '.join(sys.argv)}\n")
    log.warning("test split requested: %s", line.strip())
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    with open(ACCESS_LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(line)


def load(split, columns=None):
    """
    Return the rows of one split as a DataFrame, in time order. columns=None
    reads every column. "dev" is dev_train followed by dev_val, which is the
    causal history for replaying dev_val.
    """
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")

    if split == "test":
        allowed = os.environ.get("FINAL_EVAL") == "1"
        _log_test_access(allowed)
        if not allowed:
            raise TestSetLocked(
                "the test split is locked; set FINAL_EVAL=1 only for the final, "
                "pre-declared evaluation (eval/PROTOCOL.md)")
        return _read([TEST_FILE], TEST_START, TEST_END, columns)

    dev_files = [_month_file(m) for m in DEV_MONTHS]
    if split == "dev_train":
        return _read(dev_files[:2], DEV_START, DEV_TRAIN_END, columns)
    if split == "dev_val":
        return _read(dev_files[1:], DEV_TRAIN_END, DEV_END, columns)
    if split == "dev":
        return _read(dev_files, DEV_START, DEV_END, columns)

    # dev_val_cold: users with no row of any kind in dev_train.
    cols = None if columns is None else list(dict.fromkeys([*columns, "User ID"]))
    val = _read(dev_files[1:], DEV_TRAIN_END, DEV_END, cols)
    seen = set(_read(dev_files[:2], DEV_START, DEV_TRAIN_END, ["User ID"])["User ID"])
    cold = val[~val["User ID"].isin(seen)].reset_index(drop=True)
    if columns is not None and "User ID" not in columns:
        cold = cold.drop(columns="User ID")
    return cold
