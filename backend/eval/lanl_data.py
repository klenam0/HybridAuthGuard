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

Only red-team rows can be loaded so far; auth rows come in phase L1. Rows are
(time, user, src_computer, dst_computer) tuples in time order.
"""

import datetime as _dt
import hashlib
import json
import logging
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_split, lanl_split_la2  # noqa: E402

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


def load_lanl(split, source="redteam"):
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

    if source == "auth":
        raise NotImplementedError("LANL auth rows are converted in phase L1")

    lo, hi = _bounds()[split]
    rows = [r for r in lanl_split.read_redteam() if lo <= r[0] < hi]
    if split == "test":
        h = hashlib.sha256()
        for r in rows:
            h.update(r[4].encode("utf-8") + b"\n")
        with open(LOCK_FILE, encoding="utf-8") as f:
            if h.hexdigest() != json.load(f)["test_rows_sha256"]:
                raise RuntimeError("LANL test rows do not match eval/LANL_TEST_LOCK.json")
    return [r[:4] for r in rows]
