# backend/eval/freeze.py
"""
The Phase 5c freeze (results/FREEZE.json) and its check for Phase 6.

  python -m eval.freeze            write results/FREEZE.json
  python -m eval.freeze --verify   exit 1 unless every frozen hash, the
                                   policy table and the detector settings
                                   equal FREEZE.json

Frozen: config.py, every .py file under agents/ and utils/, eval/harness.py
and the triage code (agents/triage.py, which is under agents/, and its
offline twin in eval/phase5.py, eval/phase5b.py, eval/phase5c.py). File
hashes are SHA-256 over the content with CRLF normalised to LF, so a fresh
git checkout (core.autocrlf) hashes the same. Also recorded, not frozen:
data/model_v4.pkl, data/model.pkl (legacy) and the locked test files' lock.
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
import subprocess
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import config  # noqa: E402

PATH = os.path.join(BACKEND, "results", "FREEZE.json")
TRIAGE_CODE = ("agents/triage.py", "eval/phase5.py", "eval/phase5b.py", "eval/phase5c.py")
RECORDED = ("data/model_v4.pkl", "data/model.pkl", "results/test_lock.txt")


def sha256_text(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()


def sha256_bytes(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def frozen_files():
    rel = ["config.py", "eval/harness.py"]
    for d in ("agents", "utils"):
        rel += sorted(os.path.relpath(p, BACKEND).replace(os.sep, "/")
                      for p in glob.glob(os.path.join(BACKEND, d, "**", "*.py"), recursive=True)
                      if "__pycache__" not in p)
    rel += [p for p in TRIAGE_CODE if p not in rel]
    return rel


def snapshot():
    return {
        "files_sha256_lf": {p: sha256_text(os.path.join(BACKEND, p)) for p in frozen_files()},
        "response_policy": {
            "rules_mode": config.RULES_MODE, "ml_mode": config.ML_MODE,
            "ml_v4_iforest": config.ML_V4_IFOREST,
            "triage_score": config.TRIAGE_SCORE,
            "tier_rates": dict(config.RESPONSE_TIER_RATES),
            "floor_detectors": list(config.RESPONSE_FLOOR_DETECTORS),
            "detector_precision_val_a": dict(config.TRIAGE_DETECTOR_PRECISION),
            "block_ttl_seconds": config.BLOCK_TTL_SECONDS,
            "step_up_ttl_seconds": config.STEP_UP_TTL_SECONDS,
            "email": {"tiers": list(config.EMAIL_TIERS), "max_per_hour": config.EMAIL_MAX_PER_HOUR,
                      "ip_cooldown_seconds": config.EMAIL_IP_COOLDOWN_SECONDS},
            "table": config.response_policy_table(),
        },
        "detector_settings": {**config.public_config()["v3"],
                              "suspicious_hour_start": config.SUSPICIOUS_HOUR_START,
                              "suspicious_hour_end": config.SUSPICIOUS_HOUR_END},
    }


def _git(*args):
    return subprocess.run(["git", *args], cwd=BACKEND, capture_output=True, text=True).stdout.strip()


def write():
    assert not _git("status", "--porcelain", "--", "."), "commit everything before freezing"
    out = {"frozen_commit": _git("rev-parse", "HEAD"),
           "date": datetime.date.today().isoformat(),
           "note": "Phase 6 must refuse to run unless `python -m eval.freeze --verify` passes.",
           "hash_method": "SHA-256 of file content with CRLF normalised to LF",
           **snapshot(),
           "recorded_not_frozen_sha256": {p: sha256_bytes(os.path.join(BACKEND, p))
                                          for p in RECORDED if os.path.exists(os.path.join(BACKEND, p))}}
    with open(PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(f"wrote {PATH}: {len(out['files_sha256_lf'])} files, commit {out['frozen_commit']}")


def verify():
    with open(PATH, encoding="utf-8") as f:
        frozen = json.load(f)
    now = snapshot()
    bad = []
    fz, nw = frozen["files_sha256_lf"], now["files_sha256_lf"]
    for p in sorted(set(fz) | set(nw)):
        if fz.get(p) != nw.get(p):
            bad.append(f"file {p}: frozen {fz.get(p)} now {nw.get(p)}")
    norm = lambda x: json.loads(json.dumps(x))   # noqa: E731  (tuples -> lists)
    for k in ("response_policy", "detector_settings"):
        if norm(frozen[k]) != norm(now[k]):
            bad.append(f"{k} differs from FREEZE.json")
    for line in bad:
        print("FREEZE MISMATCH:", line)
    print("freeze MATCHES" if not bad else f"freeze BROKEN ({len(bad)} differences)")
    return 0 if not bad else 1


def main(args=None):
    if args is None:
        ap = argparse.ArgumentParser()
        ap.add_argument("--verify", action="store_true")
        args = ap.parse_args()
    if getattr(args, "verify", False):
        return verify()
    write()
    return 0


if __name__ == "__main__":
    sys.exit(main())
