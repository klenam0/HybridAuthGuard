# backend/eval/lanl_inspect.py
"""
LANL phase L0, steps 0 and 1: file integrity and red-team format (no split).

redteam.txt.gz is read in full. From auth.txt.gz only the first line is
decoded: compressed bytes are fed to the decompressor in small pieces until
the first newline appears, and any decompressed bytes after it are discarded
unread. The rest of auth.txt.gz is only hashed byte-wise in compressed form.

Writes results/lanl_inspect.json and prints the same facts.

Run from backend/:  python -m eval.lanl_inspect
"""

import collections
import gzip
import hashlib
import json
import os
import sys
import zlib

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANL_DIR = os.environ.get("LANL_DIR", r"C:\Users\Dell\datasets\lanl")
AUTH_GZ = os.path.join(LANL_DIR, "auth.txt.gz")
REDTEAM_GZ = os.path.join(LANL_DIR, "redteam.txt.gz")
OUT = os.path.join(BACKEND, "results", "lanl_inspect.json")
DAY = 86400


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def auth_first_line(path, piece=64):
    """Decode only up to the first newline of a gzip file."""
    d = zlib.decompressobj(wbits=31)
    out = b""
    with open(path, "rb") as f:
        while b"\n" not in out:
            chunk = f.read(piece)
            if not chunk:
                break
            out += d.decompress(chunk)
    line, nl, _ = out.partition(b"\n")
    if not nl:
        raise ValueError("no newline found at the start of auth.txt.gz")
    return line.decode("utf-8").rstrip("\r")


def is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def main():
    files = {}
    for name, path in (("auth.txt.gz", AUTH_GZ), ("redteam.txt.gz", REDTEAM_GZ)):
        files[name] = {"bytes": os.path.getsize(path), "sha256": sha256_file(path)}

    # redteam: full read; gzip verifies CRC32 and length at EOF.
    with gzip.open(REDTEAM_GZ, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    lines = text.splitlines()
    trailing_newline = text.endswith("\n")
    nonempty = [ln for ln in lines if ln.strip()]
    field_counts = collections.Counter(len(ln.split(",")) for ln in nonempty)
    modal = field_counts.most_common(1)[0][0]
    int_fields = [i for i in range(modal)
                  if all(len(ln.split(",")) == modal and is_int(ln.split(",")[i])
                         for ln in nonempty)]
    malformed = [i for i, ln in enumerate(nonempty)
                 if len(ln.split(",")) != modal or not is_int(ln.split(",")[0])]

    times = [int(ln.split(",")[0]) for ln in nonempty
             if len(ln.split(",")) == modal and is_int(ln.split(",")[0])]
    sorted_ok = all(a <= b for a, b in zip(times, times[1:]))

    first = auth_first_line(AUTH_GZ)
    auth_fields = first.split(",")
    t0 = int(auth_fields[0])

    rt_min, rt_max = min(times), max(times)
    result = {
        "files": files,
        "redteam": {
            "gzip_full_read_ok": True,
            "decompressed_bytes": len(raw),
            "trailing_newline": trailing_newline,
            "empty_lines": len(lines) - len(nonempty),
            "rows": len(nonempty),
            "first_5_lines": nonempty[:5],
            "fields_per_line": {str(k): v for k, v in sorted(field_counts.items())},
            "integer_fields_0based": int_fields,
            "malformed_rows": len(malformed),
            "time_field_0based": 0,
            "time_min": rt_min,
            "time_max": rt_max,
            "times_sorted_nondecreasing": sorted_ok,
        },
        "auth_line1": {
            "decoded_utf8_ok": True,
            "first_field_is_int": is_int(auth_fields[0]),
            "t0": t0,
        },
        "day_convention": "day = floor((time - t0) / 86400)",
        "checks": {
            "all_redteam_times_ge_t0": rt_min >= t0,
            "redteam_min_day": (rt_min - t0) // DAY,
            "redteam_max_day": (rt_max - t0) // DAY,
        },
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps(result, indent=2))
    return 0 if result["checks"]["all_redteam_times_ge_t0"] else 1


if __name__ == "__main__":
    sys.exit(main())
