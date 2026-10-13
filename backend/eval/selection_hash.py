# backend/eval/selection_hash.py
"""
Canonical SHA-256 of a Phase 4 selection file (results/phase4_selection.json):
the JSON with its wall-clock fields removed ("timings_seconds", "latency"
and the "timings_file" pointer), serialised with sorted keys, compact
separators and ASCII escapes, UTF-8. Two select runs that chose the same
rows give the same hash, whatever their timings and line endings.

Files written before the timings moved to phase4_select_timings.json carry
those fields inline; they are removed the same way, so old and new files
compare directly.

Run from backend/:  python -m eval.selection_hash [path ...]
"""

import hashlib
import json
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(BACKEND, "results", "phase4_selection.json")
VOLATILE = ("timings_seconds", "latency", "timings_file")


def canonical_sha256(path=DEFAULT):
    with open(path, encoding="utf-8") as f:
        sel = json.load(f)
    for k in VOLATILE:
        sel.pop(k, None)
    blob = json.dumps(sel, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def main(argv):
    for path in argv or [DEFAULT]:
        print(f"{canonical_sha256(path)}  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
