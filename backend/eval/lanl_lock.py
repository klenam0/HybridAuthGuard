# backend/eval/lanl_lock.py
"""
Locks the LANL test period (eval/PROTOCOL_LANL.md, LA2.1 and LA1.6).

Records c3 (LA1.1's c3, read from results/lanl_split.json and checked
against results/lanl_split_la2.json), the SHA-256 of redteam.txt.gz, and the
SHA-256 of the test-period red-team rows: every row with time >= c3, in file
order, each raw line encoded as UTF-8 and followed by "\n". No test row,
count or statistic is printed. Writes eval/LANL_TEST_LOCK.json, or with
--verify recomputes everything and checks the file against it.

Phase L1 adds the section "l1_auth_test" once results/lanl_l1_convert.json
exists: the SHA-256 of every file under <root>/auth/test/ (file bytes only;
no partition is opened as Parquet), the test end day and the total test row
count, both taken from results/lanl_l1_convert.json (counted while
streaming). --verify recomputes the file hashes and so also checks that the
set of files is unchanged; the row total is checked against the conversion
record, not re-derived, because test partitions are not opened after writing.

Run from backend/:  python -m eval.lanl_lock [--verify]
"""

import argparse
import hashlib
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_convert, lanl_inspect, lanl_split, lanl_split_la2  # noqa: E402

LOCK_FILE = os.path.join(BACKEND, "eval", "LANL_TEST_LOCK.json")


def test_rows_sha256(rows, c3):
    h = hashlib.sha256()
    for r in rows:
        if r[0] >= c3:
            h.update(r[4].encode("utf-8") + b"\n")
    return h.hexdigest()


def fingerprint():
    t0 = lanl_split.load_t0()
    c3 = lanl_split_la2.load_c3()
    with open(lanl_split_la2.OUT, encoding="utf-8") as f:
        la2_c3 = json.load(f)["c3"]["time"]
    if la2_c3 != c3:
        raise ValueError(f"c3 in lanl_split_la2.json ({la2_c3}) != LA1.1 c3 ({c3})")
    rows = lanl_split.read_redteam()
    fp = {
        "c3": {"time": c3, "day": lanl_split.day(c3, t0)},
        "redteam_file": "redteam.txt.gz",
        "redteam_sha256": lanl_inspect.sha256_file(lanl_split.REDTEAM_GZ),
        "test_rows_sha256": test_rows_sha256(rows, c3),
        "test_rows_hash_definition": "SHA-256 over raw lines with time >= c3, "
                                     "file order, UTF-8, each followed by \\n",
    }
    l1 = l1_section()
    if l1 is not None:
        fp["l1_auth_test"] = l1
    return fp


def test_partition_hashes():
    """SHA-256 of every file under auth/test, keyed by path relative to it."""
    root = lanl_convert.test_dir(lanl_convert.OUT_ROOT)
    files = {}
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            files[os.path.relpath(p, root).replace(os.sep, "/")] = lanl_inspect.sha256_file(p)
    return dict(sorted(files.items()))


def l1_section():
    if not os.path.exists(lanl_convert.FULL_JSON):
        return None
    with open(lanl_convert.FULL_JSON, encoding="utf-8") as f:
        conv = json.load(f)["convert"]
    return {
        "test_partition_root": "auth/test under the LANL Parquet output root",
        "test_partition_sha256": test_partition_hashes(),
        "test_rows_total": conv["rows_written_test"],
        "test_rows_total_source": "results/lanl_l1_convert.json convert.rows_written_test",
        "test_end_day": conv["test_end_day"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    fp = fingerprint()
    if args.verify:
        with open(LOCK_FILE, encoding="utf-8") as f:
            ok = json.load(f) == fp
        print("LANL test lock " + ("MATCHES" if ok else "DOES NOT MATCH"))
        return 0 if ok else 1
    with open(LOCK_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(fp, f, indent=2)
        f.write("\n")
    print(f"wrote {os.path.relpath(LOCK_FILE, BACKEND)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
