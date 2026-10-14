# backend/eval/lanl_data.py
"""
Guarded loader for the LANL splits (eval/PROTOCOL_LANL.md, LA2 and LA1.6).
Split boundaries come from results/lanl_split_la2.json and nowhere else.

  dev_train  [day 0, a)      val_a  [a, b)      val_b  [b, c3)
  test       [c3, test end]  (LOCKED; the test end is fixed in phase L1)

load_lanl("test") raises unless the environment variable FINAL_EVAL is exactly
"1". Every call to load_lanl("test"), allowed or denied, appends a line to
results/lanl_test_access.log with its time, process id and command line. An
allowed call checks the test rows against eval/LANL_TEST_LOCK.json before
returning them.

source="redteam" returns (time, user, src_computer, dst_computer) tuples in
time order. source="auth" returns a pyarrow Table of the converted auth rows
(eval/lanl_convert.py) in file order: dev splits read only the day partitions
under <root>/auth/dev; an allowed test read first checks every file under
<root>/auth/test against the L1 section of eval/LANL_TEST_LOCK.json. columns
selects auth columns (None = all nine).
"""

import datetime as _dt
import hashlib
import json
import logging
import os
import sys

import pyarrow as pa
import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_convert, lanl_inspect, lanl_split, lanl_split_la2  # noqa: E402

ACCESS_LOG = os.path.join(BACKEND, "results", "lanl_test_access.log")
LOCK_FILE = os.path.join(BACKEND, "eval", "LANL_TEST_LOCK.json")
SPLITS = ("dev_train", "val_a", "val_b", "test")
SOURCES = ("redteam", "auth")

log = logging.getLogger(__name__)


class LanlTestLocked(PermissionError):
    """Raised when the LANL test split is requested without FINAL_EVAL=1."""


def _log_test_access(allowed):
    line = (f"{_dt.datetime.now().isoformat(timespec='seconds')}\t"
            f"{'ALLOWED' if allowed else 'DENIED'}\tpid={os.getpid()}\t"
            f"argv={' '.join(sys.argv)}\n")
    log.warning("LANL test split requested: %s", line.strip())
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    with open(ACCESS_LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(line)


def _bounds():
    with open(lanl_split_la2.OUT, encoding="utf-8") as f:
        s = json.load(f)
    if s.get("rule_used") != "LA2.2-LA2.4":
        raise RuntimeError(f"no three-way LA2 split recorded (rule_used={s.get('rule_used')!r})")
    a, b, c3 = s["a"]["time"], s["b"]["time"], s["c3"]["time"]
    return {"dev_train": (s["t0"], a), "val_a": (a, b), "val_b": (b, c3),
            "test": (c3, float("inf"))}


def _auth_days(lo, hi):
    t0 = lanl_split.load_t0()
    return lanl_split.day(lo, t0), lanl_split.day(hi, t0)


def _read_auth(base, days, columns):
    paths = [os.path.join(base, f"day={d:02d}", "part-0.parquet") for d in days]
    paths = [p for p in paths if os.path.exists(p)]
    tables = [pq.read_table(p, columns=columns) for p in paths]
    if not tables:
        return pa.Table.from_batches([], schema=lanl_convert.SCHEMA if columns is None
                                     else pa.schema([lanl_convert.SCHEMA.field(c) for c in columns]))
    return pa.concat_tables(tables)


def _check_test_partitions():
    with open(LOCK_FILE, encoding="utf-8") as f:
        l1 = json.load(f).get("l1_auth_test")
    if l1 is None:
        raise RuntimeError("eval/LANL_TEST_LOCK.json has no l1_auth_test section")
    root = lanl_convert.test_dir(lanl_convert.OUT_ROOT)
    found = {}
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            found[os.path.relpath(p, root).replace(os.sep, "/")] = lanl_inspect.sha256_file(p)
    if found != l1["test_partition_sha256"]:
        raise RuntimeError("LANL test partitions do not match eval/LANL_TEST_LOCK.json")
    return l1


def load_lanl(split, source="redteam", columns=None):
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")
    if source not in SOURCES:
        raise ValueError(f"unknown source {source!r}; expected one of {SOURCES}")

    if split == "test":
        allowed = os.environ.get("FINAL_EVAL") == "1"
        _log_test_access(allowed)
        if not allowed:
            raise LanlTestLocked(
                "the LANL test split is locked; set FINAL_EVAL=1 only for the "
                "final, pre-declared evaluation (eval/PROTOCOL_LANL.md)")

    lo, hi = _bounds()[split]
    if source == "auth":
        if split == "test":
            l1 = _check_test_partitions()
            first = _auth_days(lo, lo)[0]
            return _read_auth(lanl_convert.test_dir(lanl_convert.OUT_ROOT),
                              range(first, l1["test_end_day"] + 1), columns)
        d_lo, d_hi = _auth_days(lo, hi)
        return _read_auth(lanl_convert.dev_dir(lanl_convert.OUT_ROOT),
                          range(d_lo, d_hi), columns)

    rows = [r for r in lanl_split.read_redteam() if lo <= r[0] < hi]
    if split == "test":
        h = hashlib.sha256()
        for r in rows:
            h.update(r[4].encode("utf-8") + b"\n")
        with open(LOCK_FILE, encoding="utf-8") as f:
            if h.hexdigest() != json.load(f)["test_rows_sha256"]:
                raise RuntimeError("LANL test rows do not match eval/LANL_TEST_LOCK.json")
    return [r[:4] for r in rows]
