# backend/eval/convert_rba.py
"""
One-off conversion of the RBA CSV (RBA_DATASET_PATH) into month-partitioned
Parquet. All 16 CSV columns are kept, including the CSV's own "index" column
(a stable row id).

  data/rba_parquet/month=YYYY-MM/part-0.parquet   every month except the test month
  data/rba_locked/test_2020-05.parquet            the locked test month (PROTOCOL.md)

The test month is written to its own directory so that nothing reading the
month-partitioned dataset can pick it up by accident. This script reads no
label column: per batch it only parses rows, counts them per month, checks
timestamp order and writes them out.

Dtypes: low-cardinality strings are dictionary-encoded (pandas categoricals on
read), ASN is int32, RTT float32 (the CSV writes it as
"1123.0"; float32 holds integers up to 16.7M exactly), User ID int64, timestamps ms precision.
String values are stored exactly as in the CSV (no stripping or case folding).

Run from backend/:  python -m eval.convert_rba
"""

import argparse
import json
import os
import sys
import time

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq
from dotenv import load_dotenv

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BACKEND, ".env"))

PARQUET_DIR = os.path.join(BACKEND, "data", "rba_parquet")
LOCKED_DIR = os.path.join(BACKEND, "data", "rba_locked")
TEST_MONTH = "2020-05"
TEST_FILE = os.path.join(LOCKED_DIR, f"test_{TEST_MONTH}.parquet")
STATS_FILE = os.path.join(BACKEND, "results", "rba_conversion_stats.json")

DICT = pa.dictionary(pa.int32(), pa.string())
SCHEMA = pa.schema([
    ("index", pa.int64()),
    ("Login Timestamp", pa.timestamp("ms")),
    ("User ID", pa.int64()),
    ("Round-Trip Time [ms]", pa.float32()),
    ("IP Address", pa.string()),
    ("Country", DICT),
    ("Region", DICT),
    ("City", DICT),
    ("ASN", pa.int32()),
    ("User Agent String", pa.string()),
    ("Browser Name and Version", DICT),
    ("OS Name and Version", DICT),
    ("Device Type", DICT),
    ("Login Successful", pa.bool_()),
    ("Is Attack IP", pa.bool_()),
    ("Is Account Takeover", pa.bool_()),
])
# The CSV reader parses dictionary columns as plain strings; cast afterwards.
READ_TYPES = {f.name: (pa.string() if pa.types.is_dictionary(f.type) else f.type)
              for f in SCHEMA}

BLOCK_SIZE = 64 << 20          # bytes of CSV per batch; fixed for reproducible files


def month_path(month):
    if month == TEST_MONTH:
        return TEST_FILE
    return os.path.join(PARQUET_DIR, f"month={month}", "part-0.parquet")


def convert(csv_path, limit_batches=None):
    for d in (PARQUET_DIR, LOCKED_DIR):
        if os.path.isdir(d) and any(os.scandir(d)) and limit_batches is None:
            raise SystemExit(f"{d} is not empty; delete it to reconvert")
    reader = pacsv.open_csv(
        csv_path,
        read_options=pacsv.ReadOptions(block_size=BLOCK_SIZE),
        convert_options=pacsv.ConvertOptions(
            column_types=READ_TYPES,
            true_values=["True", "true"], false_values=["False", "false"],
            strings_can_be_null=False),
    )
    writers, counts = {}, {}
    total, batches = 0, 0
    inversions, max_back_ms, null_ts = 0, 0, 0
    prev_last = None
    t0 = time.time()
    try:
        for batch in reader:
            table = pa.Table.from_batches([batch]).cast(SCHEMA)
            ts = table.column("Login Timestamp")
            null_ts += ts.null_count
            t = ts.cast(pa.int64()).to_numpy(zero_copy_only=False)
            if prev_last is not None:
                t = np.concatenate([[prev_last], t])
            d = np.diff(t)
            inversions += int((d < 0).sum())
            if (d < 0).any():
                max_back_ms = max(max_back_ms, int(-d.min()))
            prev_last = int(t[-1])

            month = pc.strftime(ts, format="%Y-%m")
            for m in pc.unique(month).to_pylist():
                part = table.filter(pc.equal(month, m))
                if m not in writers:
                    path = month_path(m)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    writers[m] = pq.ParquetWriter(path, SCHEMA, compression="zstd")
                writers[m].write_table(part)
                counts[m] = counts.get(m, 0) + part.num_rows
            total += table.num_rows
            batches += 1
            if batches % 10 == 0:
                print(f"  {total:>11,} rows  {time.time() - t0:7.1f} s", flush=True)
            if limit_batches and batches >= limit_batches:
                break
    finally:
        for w in writers.values():
            w.close()

    return {
        "csv_path": csv_path,
        "csv_bytes": os.path.getsize(csv_path),
        "rows_total": total,
        "rows_per_month": dict(sorted(counts.items())),
        "null_timestamps": null_ts,
        "time_order_inversions": inversions,
        "max_backward_step_ms": max_back_ms,
        "csv_time_ordered": inversions == 0,
        "block_size_bytes": BLOCK_SIZE,
        "pyarrow_version": pa.__version__,
        "seconds": round(time.time() - t0, 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.environ.get("RBA_DATASET_PATH"))
    ap.add_argument("--limit-batches", type=int, default=None,
                    help="timing probe only: stop after N batches, write no stats")
    args = ap.parse_args()
    if not args.csv or not os.path.exists(args.csv):
        raise SystemExit("set RBA_DATASET_PATH (backend/.env) or pass --csv")
    stats = convert(args.csv, args.limit_batches)
    print(json.dumps(stats, indent=2))
    if args.limit_batches is None:
        with open(STATS_FILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(stats, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
