# backend/eval/lock_test.py
"""
Records the locked test month's row count and SHA-256 (eval/PROTOCOL.md).

The row count is read from the Parquet footer metadata and the hash from the
file bytes; no row is decoded. Writes results/test_lock.txt, or with
--verify checks the file against it.

Run from backend/:  python -m eval.lock_test [--verify]
"""

import argparse
import hashlib
import os
import sys

import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import datasets  # noqa: E402

LOCK_FILE = os.path.join(BACKEND, "results", "test_lock.txt")


def fingerprint(path=None):
    path = path or datasets.TEST_FILE
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return pq.ParquetFile(path).metadata.num_rows, h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    rows, sha = fingerprint()
    rel = os.path.relpath(datasets.TEST_FILE, BACKEND).replace(os.sep, "/")
    text = f"file: {rel}\nrows: {rows}\nsha256: {sha}\n"
    if args.verify:
        with open(LOCK_FILE, encoding="utf-8") as f:   # universal newlines
            ok = f.read() == text
        print("test lock " + ("MATCHES" if ok else "DOES NOT MATCH"))
        return 0 if ok else 1
    with open(LOCK_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
