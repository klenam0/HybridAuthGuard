# backend/eval/lanl_convert.py
"""
LANL phase L1: converts auth.txt.gz to one Parquet partition per day
(eval/PROTOCOL_LANL.md, LA2.1 and LA1.6).

  <root>/auth/dev/day=DD/part-0.parquet    day <  day(c3)
  <root>/auth/test/day=DD/part-0.parquet   day >= day(c3)

The file is streamed once with pyarrow's streaming CSV reader (no header, the
nine documented columns). time is int64; every other field is a string kept
exactly as written ("?" included; nothing is treated as null, quoting is off).
Row order is preserved within each partition. The day index is
eval.lanl_split.day; c3 comes from eval.lanl_split_la2.load_c3.

Checks while streaming:
  - lines read, counted on the decompressed bytes independently of the CSV
    parser, = dev rows + test rows + malformed lines
  - malformed lines (not 9 fields; empty lines are not skipped) are written to
    <root>/malformed_lines.tsv, never dropped silently
  - time non-decreasing over the whole file (yes/no, and the first offending
    row if no)

Over test rows only these are computed: the test end (day of the last row),
the total test row count, and their share of the whole-file time-order check.
Nothing per test day is counted. Test partitions are not opened after writing
(their SHA-256 values are recorded by eval/lanl_lock.py).

Full run: one CONVERT line is appended to results/lanl_test_access.log before
reading; results/lanl_l1_convert.json records the counts.
Smoke run (--smoke N --out DIR): first N lines to a scratch DIR; raises before
writing if any row has day >= day(c3); writes results/lanl_l1_smoke.json.

Run from backend/:  python -m eval.lanl_convert [--smoke N --out DIR]
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import datetime as _dt
import gzip
import hashlib
import json
import os
import shutil
import sys
import time

import numpy as np
import pyarrow as pa
import pyarrow.csv as pcsv
import pyarrow.parquet as pq

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from eval import lanl_inspect, lanl_split, lanl_split_la2  # noqa: E402

AUTH_GZ = lanl_inspect.AUTH_GZ
OUT_ROOT = os.environ.get("LANL_PARQUET", r"C:\Users\Dell\datasets\lanl\parquet")
ACCESS_LOG = os.path.join(BACKEND, "results", "lanl_test_access.log")
FULL_JSON = os.path.join(BACKEND, "results", "lanl_l1_convert.json")
SMOKE_JSON = os.path.join(BACKEND, "results", "lanl_l1_smoke.json")

COLUMNS = ["time", "src_user", "dst_user", "src_computer", "dst_computer",
           "auth_type", "logon_type", "auth_orientation", "success"]
SCHEMA = pa.schema([("time", pa.int64())] + [(c, pa.string()) for c in COLUMNS[1:]])
BLOCK_SIZE = 32 << 20
READ_SIZE = 16 << 20


def dev_dir(root):
    return os.path.join(root, "auth", "dev")


def test_dir(root):
    return os.path.join(root, "auth", "test")


def partition_path(root, d, c3_day):
    base = dev_dir(root) if d < c3_day else test_dir(root)
    return os.path.join(base, f"day={d:02d}", "part-0.parquet")


class _PMC(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]


def peak_working_set():
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(pmc)
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.K32GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(_PMC), wt.DWORD]
    k32.K32GetProcessMemoryInfo.restype = wt.BOOL
    if not k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
        raise OSError(ctypes.get_last_error(), "K32GetProcessMemoryInfo failed")
    return pmc.PeakWorkingSetSize


class _MemStatus(ctypes.Structure):
    _fields_ = [("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def resources(root):
    ms = _MemStatus()
    ms.dwLength = ctypes.sizeof(ms)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    drive = os.path.splitdrive(os.path.abspath(root))[0] + os.sep
    du = shutil.disk_usage(drive)
    return {"output_drive": drive, "disk_free_bytes": du.free, "disk_total_bytes": du.total,
            "mem_total_bytes": ms.ullTotalPhys, "mem_available_bytes": ms.ullAvailPhys}


class CountingGzip:
    """Read-only file object over a gzip file that counts decompressed lines.

    With max_lines, delivery stops right after the max_lines-th newline.
    """

    def __init__(self, path, max_lines=None):
        self._raw = open(path, "rb")
        self._gz = gzip.GzipFile(fileobj=self._raw, mode="rb")
        self.max_lines = max_lines
        self.newlines = 0
        self.bytes_out = 0
        self._last = b"\n"
        self._eof = False
        self.closed = False

    def readable(self):
        return True

    def seekable(self):
        return False

    def read(self, n=-1):
        if self._eof:
            return b""
        data = self._gz.read(READ_SIZE if n is None or n < 0 else n)
        if not data:
            self._eof = True
            return b""
        k = data.count(b"\n")
        if self.max_lines is not None and self.newlines + k >= self.max_lines:
            need, pos = self.max_lines - self.newlines, -1
            for _ in range(need):
                pos = data.index(b"\n", pos + 1)
            data, k, self._eof = data[:pos + 1], need, True
        self.newlines += k
        self.bytes_out += len(data)
        self._last = data[-1:]
        return data

    @property
    def lines(self):
        return self.newlines + (0 if self._last == b"\n" else 1)

    @property
    def compressed_pos(self):
        return self._cpos if self.closed else self._raw.tell()

    def close(self):
        self._cpos = self._raw.tell()
        self._gz.close()
        self._raw.close()
        self.closed = True


def sha256_file(path):
    return lanl_inspect.sha256_file(path)


class SmokeReachedTest(RuntimeError):
    pass


def convert(root, max_lines=None, smoke=False):
    t0 = lanl_split.load_t0()
    c3_day = lanl_split.day(lanl_split_la2.load_c3(), t0)
    os.makedirs(root, exist_ok=True)
    sidecar_path = os.path.join(root, "malformed_lines.tsv")
    sidecar = open(sidecar_path, "w", encoding="utf-8", newline="\n")
    malformed = [0]

    def on_invalid(row):
        malformed[0] += 1
        sidecar.write(f"{row.number}\t{row.actual_columns}\t{row.text}\n")
        return "skip"

    src = CountingGzip(AUTH_GZ, max_lines=max_lines)
    reader = pcsv.open_csv(
        src,
        read_options=pcsv.ReadOptions(column_names=COLUMNS, block_size=BLOCK_SIZE,
                                      use_threads=True),
        parse_options=pcsv.ParseOptions(delimiter=",", quote_char=False, escape_char=False,
                                        newlines_in_values=False, ignore_empty_lines=False,
                                        invalid_row_handler=on_invalid),
        convert_options=pcsv.ConvertOptions(column_types=SCHEMA, null_values=[],
                                            strings_can_be_null=False,
                                            quoted_strings_can_be_null=False,
                                            check_utf8=True))
    writers = {}
    dev_rows_per_day = {}
    test_rows = 0
    rows_seen = 0
    last_time = None
    sorted_ok, first_bad_row = True, None
    last_day = None
    start = time.perf_counter()
    try:
        for batch in reader:
            n = batch.num_rows
            if n == 0:
                continue
            t = batch.column("time").to_numpy()
            if sorted_ok:
                if last_time is not None and t[0] < last_time:
                    sorted_ok, first_bad_row = False, rows_seen + 1
                else:
                    bad = np.flatnonzero(t[1:] < t[:-1])
                    if bad.size:
                        sorted_ok, first_bad_row = False, rows_seen + int(bad[0]) + 2
            last_time = int(t[-1])
            d = lanl_split.day(t, t0)
            if smoke and int(d.max()) >= c3_day:
                raise SmokeReachedTest("a smoke row is at or after c3; stopping")
            if np.all(d[1:] >= d[:-1]):
                cuts = np.flatnonzero(np.diff(d)) + 1
                pieces = [(int(d[lo]), batch.slice(lo, hi - lo))
                          for lo, hi in zip(np.r_[0, cuts], np.r_[cuts, n])]
            else:
                order = list(dict.fromkeys(d.tolist()))
                pieces = [(u, batch.filter(pa.array(d == u))) for u in order]
            for u, piece in pieces:
                w = writers.get(u)
                if w is None:
                    path = partition_path(root, u, c3_day)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    w = writers[u] = pq.ParquetWriter(path, SCHEMA, compression="zstd")
                w.write_table(pa.Table.from_batches([piece]))
                if u < c3_day:
                    dev_rows_per_day[u] = dev_rows_per_day.get(u, 0) + piece.num_rows
                else:
                    test_rows += piece.num_rows
            rows_seen += n
            last_day = int(d[-1])
    finally:
        for w in writers.values():
            w.close()
        sidecar.close()
        src.close()
    elapsed = time.perf_counter() - start

    dev_rows = sum(dev_rows_per_day.values())
    out_bytes = 0
    for dirpath, _, files in os.walk(os.path.join(root, "auth")):
        out_bytes += sum(os.path.getsize(os.path.join(dirpath, f)) for f in files)
    return {
        "t0": t0,
        "c3_day": c3_day,
        "lines_read": src.lines,
        "decompressed_bytes": src.bytes_out,
        "compressed_bytes_consumed": src.compressed_pos,
        "rows_written_dev": dev_rows,
        "rows_written_test": test_rows,
        "rows_written_total": dev_rows + test_rows,
        "malformed_lines": malformed[0],
        "malformed_sidecar": {"path": sidecar_path,
                              "sha256": sha256_file(sidecar_path)},
        "check_lines_eq_rows_plus_malformed": src.lines == dev_rows + test_rows + malformed[0],
        "check_lines_eq_rows_written": src.lines == dev_rows + test_rows,
        "time_non_decreasing": sorted_ok,
        "first_out_of_order_row": first_bad_row,
        "last_row_day": last_day,
        "dev_days_written": sorted(dev_rows_per_day),
        "dev_rows_per_day": {f"{k:02d}": v for k, v in sorted(dev_rows_per_day.items())},
        "output_bytes_total": out_bytes,
        "elapsed_seconds": round(elapsed, 1),
        "rows_per_second": round(rows_seen / elapsed) if elapsed else None,
        "peak_working_set_bytes": peak_working_set(),
        "pyarrow_peak_pool_bytes": pa.default_memory_pool().max_memory(),
    }


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", type=int, default=None, help="convert only the first N lines")
    ap.add_argument("--out", default=None, help="output root (required with --smoke)")
    args = ap.parse_args()

    if args.smoke is not None:
        if not args.out:
            ap.error("--smoke needs --out (a scratch directory)")
        root = args.out
        res_before = resources(OUT_ROOT if os.path.exists(OUT_ROOT) else os.path.dirname(OUT_ROOT))
        r = convert(root, max_lines=args.smoke, smoke=True)
        full_bytes = os.path.getsize(AUTH_GZ)
        scale = full_bytes / r["compressed_bytes_consumed"]
        rows = r["rows_written_total"]
        est = {
            "method": "scale by compressed bytes: auth.txt.gz size / compressed bytes "
                      "consumed by the smoke run (gzip read-ahead included)",
            "scale": round(scale, 2),
            "est_lines": round(r["lines_read"] * scale),
            "est_seconds": round(r["elapsed_seconds"] * scale),
            "est_output_bytes": round(r["output_bytes_total"] * scale),
            "est_peak_working_set_bytes": "bounded by streaming; smoke peak "
                                          f"{r['peak_working_set_bytes']} (not scaled)",
        }
        est["est_output_share_of_free_disk"] = round(
            est["est_output_bytes"] / res_before["disk_free_bytes"], 4)
        out = {"resources": res_before, "smoke": r,
               "output_bytes_per_million_rows": round(r["output_bytes_total"] / rows * 1e6),
               "estimate_full": est}
        _write_json(SMOKE_JSON, out)
        print(json.dumps(out, indent=2))
        return 0

    if os.path.exists(os.path.join(OUT_ROOT, "auth")):
        print(f"refusing: {os.path.join(OUT_ROOT, 'auth')} already exists")
        return 1
    res_before = resources(OUT_ROOT)
    with open(ACCESS_LOG, "a", encoding="utf-8", newline="\n") as f:
        f.write(f"{_dt.datetime.now().isoformat(timespec='seconds')}\tCONVERT\t"
                f"no statistics\t{' '.join(sys.argv)}\n")
    r = convert(OUT_ROOT)
    r["test_end_day"] = r["last_row_day"]
    r["test_end_rule"] = "LA2.1: day index of the last row of auth.txt.gz"
    out = {"resources_before": res_before, "output_root": OUT_ROOT, "convert": r}
    _write_json(FULL_JSON, out)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
