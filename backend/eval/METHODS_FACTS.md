# Methods facts (read-only fact check, 2026-10-15)

Branch `lanl-l3` at 9c0cced. No code was changed and nothing was read through
the evaluation loaders. Paths below are relative to `backend/` unless they
start with `../` or are absolute.

## 1. Detector triggers (frozen v3)

`agents/rules_v3.py` and `config.py` are identical to tag `v3.0.0-frozen`
(`git diff --stat v3.0.0-frozen -- config.py agents/rules_v3.py` prints
nothing). Thresholds and windows are read from `config.py` in
`V3DetectionAgent.__init__` (`agents/rules_v3.py:268-281`).

Common definitions:

- **Failure** = an event with status `FAILED` (upper-cased, `rules_v3.py:308,321`)
  whose account is *not* an unknown-account ID. **Unknown-account ID** =
  `config.UNKNOWN_ACCOUNT_IDS = ["-4324475583306591935"]` (`config.py:66`),
  matched after `strip().casefold()` (`rules_v3.py:78-79,282,320`).
- **Window semantics.** Every window is a sliding window over event time
  (seconds). For the per-IP and per-account windows the window ends at the
  *latest* event time in that key's window (`Window.last()`), and includes
  times `>= last - W` (`bisect_left`, `rules_v3.py:150-155`); late events are
  inserted in order (`rules_v3.py:110-123`). Success After Failures instead
  counts `[t - W, t]` around the success's own time (`rules_v3.py:157-158,374,377`).
- **Duplicates.** An event with the same `event_id` (or, without one, the same
  timestamp, IP, account, status, country and device type) within
  `V3_DUPLICATE_WINDOW_SECONDS = 300` (`config.py:103`) is ignored entirely
  (`rules_v3.py:316-318,425-435`).
- **Alert de-duplication.** A match always counts as a match
  (`Detection.matched`), but an alert is raised only if no alert with the same
  (detector, key) was raised within the cooldown: 3600 s by default, 600 s for
  Suspicious Login Time (`config.py:35,99`; `rules_v3.py:400-404`). The key is
  given per detector below.

| # | Detector | Counts | Keyed by | Window | Threshold | Source |
|---|---|---|---|---|---|---|
| 1 | Brute Force Attack | failures (real-account FAILED events) from the IP | IP | 60 s (`V3_BF_WINDOW_SECONDS`) | `>= 5` (`V3_BF_MIN_FAILURES`) | `config.py:68-69`; `rules_v3.py:335-346`; alert key IP |
| 2 | Slow Brute Force | failures from the IP, **only when Brute Force did not match on this event**; the span from the earliest to the latest failure in the window must be `>= 300 s` | IP | 7 d = 604,800 s (`V3_SLOW_BF_WINDOW_SECONDS`) | `>= 3` failures (`V3_SLOW_BF_MIN_FAILURES`) and spread `>= 300 s` (`V3_SLOW_BF_MIN_SPREAD_SECONDS`) | `config.py:71-73`; `rules_v3.py:347-352`; alert key IP |
| 3 | Credential Stuffing | **distinct real accounts** with at least one failure from the IP (successes and unknown-account attempts excluded) | IP | 7 d (`V3_CS_WINDOW_SECONDS`) | `>= 2` accounts (`V3_CS_MIN_ACCOUNTS`) | `config.py:75-76`; `rules_v3.py:341-342,353-355`; alert key IP |
| 4 | Invalid Account Spraying | attempts **on the unknown-account ID** (any status: FAILED or SUCCESS) from the IP | IP | 7 d (`V3_INVALID_WINDOW_SECONDS`) | `>= 3` attempts (`V3_INVALID_MIN_ATTEMPTS`) | `config.py:78-79`; `rules_v3.py:327-334`; alert key IP |
| 5 | Distributed Brute Force | **distinct source IPs** with at least one failure against the account | real account | 48 h = 172,800 s (`V3_DIST_WINDOW_SECONDS`) | `>= 3` IPs (`V3_DIST_MIN_IPS`) | `config.py:81-82`; `rules_v3.py:358-368`; alert key (account, IP) |
| 6 | Success After Failures | on a real-account SUCCESS: failures on that account (from any IP) **or** failures from that IP (on any real account) in `[t - 7 d, t]` | real account and IP | 7 d (`V3_SAF_WINDOW_SECONDS`) | `>= 3` on the account **or** `>= 3` from the IP (`V3_SAF_MIN_FAILURES`) | `config.py:84-85`; `rules_v3.py:370-379`; alert key (account, IP) |
| 7 | Multiple IP Login | on a real-account SUCCESS: the account's previous SUCCESS was from a different IP less than 120 s earlier (`abs(t - last_t) < 120`), unless exempt. Exemption in force: `known_ip` only = the new IP had a SUCCESS on this account within the last 30 d | real account | 120 s (`V3_MULTI_IP_WINDOW_SECONDS`); known-IP TTL 30 d (`V3_KNOWN_IP_TTL_SECONDS`) | one IP change within 120 s | `config.py:88-92`; `rules_v3.py:380,437-468`; alert key (account, IP) |
| 8 | Suspicious Login Time | any SUCCESS (including the unknown-account ID; not gated on `unknown`) whose hour, read as characters 11-12 of the timestamp string (no time-zone conversion), is in 00-05 | IP (for de-duplication only) | none (per event) | hour in `[0, 5]` (`SUSPICIOUS_HOUR_START`/`END`) | `config.py:33-35`; `rules_v3.py:383-387`; alert key IP, 600 s cooldown |

Answers to the two specific questions:

- **Invalid Account Spraying (7 d, >= 3).** Three **login attempts whose
  user ID is the unknown-account ID `-4324475583306591935`**, of any status,
  **from the same source IP**, within 7 days ending at that IP's latest such
  attempt. It is not three distinct usernames: the dataset has one
  unknown-account ID, so the detector counts attempts, not accounts
  (`rules_v3.py:327-334`, `config.py:66,78-79`). Unknown-account attempts never
  feed any other detector except Suspicious Login Time (for a SUCCESS) and ML.
- **Distributed Brute Force (48 h, >= 3 IPs).** Three **distinct source IPs,
  each with at least one FAILED login against the same real account**, within
  48 hours ending at that account's latest failure (`rules_v3.py:358-368`,
  `config.py:81-82`). Successes do not count, and the unknown-account ID is
  excluded. The alert key is (account, IP), so each new failing IP can raise
  its own alert once the account is over threshold.

The ML step ("ML Anomaly Detected", `rules_v3.py:389-398`) is not one of the
8 rule detectors (`RULE_DETECTORS`, `rules_v3.py:72`).

## 2. Versions

Commands: `python --version`, an `importlib` version print, `python -m pip show`,
`ollama --version`, `ollama list`, `ollama show phi3:mini`,
`curl http://localhost:11434/api/tags`.

| Component | Installed | Pinned in `requirements.txt` |
|---|---|---|
| Python | 3.12.0 (`C:\Python312\python.exe`) | not pinned |
| scikit-learn | 1.8.0 | 1.8.0 |
| numpy | 2.3.2 | 2.3.2 |
| pandas | 2.3.2 | 2.3.2 |
| pyarrow | 26.0.0 | 26.0.0 |
| polars | not installed; not imported anywhere (`grep -rn "import polars\|from polars" --include=*.py` finds nothing) | not listed |
| Flask | 3.1.3 | 3.1.3 |
| flask-cors | 6.0.2 | 6.0.2 |
| joblib | 1.5.3 | 1.5.3 |

Ollama (installed):

- `ollama --version`: `ollama version is 0.40.4` (API `/api/version` agrees: `0.40.4`).
- Model used: `config.OLLAMA_MODEL = "phi3:mini"` (`config.py:365`), base URL
  `http://localhost:11434` (`config.py:364`).
- `ollama list`: `phi3:mini  4f2222927938  2.2 GB  2 months ago`.
- Full digest (`/api/tags`):
  `sha256:4f222292793889a9a40a020799cfd28d53f3e01af25d48e06c5e708610fc47e9`
  (format gguf, family phi3, 3.8B parameters, Q4_0, context length 131072).
- `ollama show phi3:mini`: architecture phi3, 3.8B, context 131072, embedding
  3072, quantization Q4_0, stop tokens `<|end|>`, `<|user|>`, `<|assistant|>`.

## 3. Account-takeover scope

**Where "44" comes from.** The reports live outside the repository in
`C:\Users\Dell\audit_scratch\` (no `PHASE*_REPORT.md` or FINDINGS file is
tracked in git; `C:\Users\Dell\Downloads\BATCH4_FINDINGS.md` has no ATO
count). `grep -nE "\b44\b"` over them, filtered for ATO/takeover/account:

```
audit_scratch/PHASE2_DATA_REPORT.md:79:- ATO: 44 events, on 44 users and 37 IPs. All 44 are successful logins, and 25 are on attack IPs.
audit_scratch/PHASE2_REPORT.md:22: ... there are only 44 `Is Account Takeover` events. ...
```

**Scope.** Development months only, 2020-02-03 to 2020-04-30 (6,392,584 rows),
all rows, **no filter** (not restricted to the unknown-account ID, attack IPs
or successes). The report says so at `PHASE2_DATA_REPORT.md:3` ("Every label
statistic below comes from the development months only ... The locked test
month (May 2020) appears only as a row count"). Split breakdown at
`PHASE2_DATA_REPORT.md:31-32`: dev_train (Feb 3 – Mar 29) 31, dev_val
(Mar 30 – Apr 30) 13; 11 of the dev_val 13 are in dev_val_cold (line 33).
Composition at line 78: 19 ATO-only + 25 ATO-and-attack-IP = 44. It is
**not** a whole-dataset count and does not include May 2020.

**Raw-file count (descriptive, made after the test month was scored).** Read
directly from the raw CSV with pyarrow (not the evaluation loaders); details,
method and file hash in `eval/DATASET_DESCRIPTION.md`, raw numbers in
`results/rba_ato_counts.json`.

- Whole file: **141** rows with `Is Account Takeover = True` out of
  31,269,264 (140 with `Login Successful = True`, 77 with `Is Attack IP = True`).
- Per month: 2020-02 22, 2020-03 11, 2020-04 11, 2020-05 15, 2020-06 17,
  2020-07 10, 2020-08 17, 2020-09 16, 2020-10 14, 2020-11 8,
  2020-12 0, 2021-01 0, 2021-02 0.
- Feb–Apr 2020 sum to 44, which reproduces the Phase 2 figure.

## 4. Repository

- Remote (`git remote -v`): `origin https://github.com/klenam0/HybridAuthGuard.git` (fetch and push).
- `v3.0.0-frozen` is a **lightweight** tag (`git cat-file -t v3.0.0-frozen` → `commit`)
  on `fc69d1ddbc6835b7a5cba424792ea8d4abef5431` (2026-10-14 07:36:09 +0000,
  "chore(freeze): Phase 5c.6 results/FREEZE.json ...").
  `git ls-remote --tags origin "v3.0.0-frozen*"` prints nothing: **the tag is
  local only, not on GitHub.**
- `CITATION.cff` exists at the repository root (`../CITATION.cff`). It states
  `version: "2.0.0"` (line 8) and `date-released: "2026-10-09"` (line 7), last
  changed in 734a390. It is the same at `v3.0.0-frozen`. It does not state 3.0.0.
