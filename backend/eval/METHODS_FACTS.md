# Methods facts (read-only fact check, 2026-10-15)

Branch `lanl-l3` at 00c9905. No code was changed and nothing was read through
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
  on `bb40c168c55d6e2bd9f8af2c3906b8c0fda9185f` (2026-10-14 07:36:09 +0000,
  "chore(freeze): Phase 5c.6 results/FREEZE.json ...").
  `git ls-remote --tags origin "v3.0.0-frozen*"` prints nothing: **the tag is
  local only, not on GitHub.**
- `CITATION.cff` exists at the repository root (`../CITATION.cff`). It states
  `version: "2.0.0"` (line 8) and `date-released: "2026-10-09"` (line 7), last
  changed in 734a390. It is the same at `v3.0.0-frozen`. It does not state 3.0.0.

## 5. Triage baseline T0, tier bars, alert retention

Read-only, at 365e384. No code changed, no test output read, no metric
computed.

### T0 as implemented

**Score.** A 2-tuple, higher = more urgent, compared lexicographically:
(highest val_a alert precision among the incident's rule detectors, number
of distinct rule detectors in the incident).

- Live agent: `agents/triage.py:212-220`; the T0 branch is line 220,
  `return (top, n_det) if name == "T0" else (top, d.asn_max)`, with
  `top = max(p for j, p in enumerate(self.prec) if inc.mask >> j & 1)`
  (line 219) and `n_det = bin(inc.mask).count("1")` (line 213).
  `self.prec` comes from `config.TRIAGE_DETECTOR_PRECISION`
  (`agents/triage.py:126-127`).
- Detector precisions (val_a point estimates at the amendment 3 setting,
  `config.py:268-279`): Brute Force 0.296875, Credential Stuffing 0.27344,
  Slow Brute Force 0.26303, Distributed Brute Force 0.25163, Success After
  Failures 0.24569, Invalid Account Spraying 0.23123, Multiple IP Login
  0.14554, Suspicious Login Time 0.13086.
- Offline twin used for the evaluation: `eval/phase5.py:173-176`
  (`running("T0")` returns `[self.top, self.n_det]`), with `self.top` from
  the same config table (`eval/phase5.py:155-156`). Final score = running
  value at the incident's last alerted event (`eval/phase5.py:183-184`).

**Order and tie-break (end-of-day ranking, the only place T0 is used).**
`eval/phase5.py:212-222` (`day_rank`): `np.lexsort((tie, -n_det, -top,
day))`, i.e. within each calendar day, by `top` descending, then `n_det`
descending, then a uniform random draw `np.random.default_rng(TIE_SEED)
.random(n)` with `TIE_SEED = 42` (`eval/phase5.py:67`) ascending. The top B
per day are taken in `budget_metrics` (`eval/phase5.py:225-248`,
`take = rank < B`). Phase 6 P2 calls the same functions for T2 and T0
(`eval/phase6_primary.py:26,65`; the T2-vs-T0 test at lines 66-69).

T0 is not deployed: `config.TRIAGE_SCORE = "T2"` (`config.py:266`). In the
live tiers (any score), there is no random tie-break: the cutoff is the
k-th of the previous day's final scores sorted descending
(`agents/triage.py:236-241`) and an incident qualifies when
`score >= cutoff` (`agents/triage.py:224-226`), so ties at the cutoff all
qualify, subject to the per-day cap.

**Amendment 6 text declaring T0** (`eval/PROTOCOL.md`):

```
573	   **Triage candidates**, in tie order (simplest first). Scores are
574	   compared lexicographically, higher = more urgent:
575	   - T0: amendment 3's budget score: (highest val_a alert precision, point
576	     estimate at the chosen setting, among the incident's detectors;
577	     number of distinct detectors). Baseline.
...
591	   Remaining ties in an end-of-day ranking are broken uniformly at random,
592	   `default_rng(42)`, as in amendment 3.
```

and its role as the bar (lines 597-607):

```
597	   highest *mean daily attacking IPs caught* at B = 500 on val_a (per day:
598	   distinct attacking IPs with an attack incident among that day's top 500;
599	   mean over the 16 days), subject to: the day-clustered bootstrap lower
600	   bound of the *mean daily top-500 incident precision* >= T0's val_a point
601	   value of that same mean. Bootstrap: the 16 days resampled with
...
605	   T0 is subject to the same bar; its lower bound is below its own point
606	   value unless every day is equal, so it is expected to fail it. **If no
607	   candidate qualifies, T0 is kept.** Also reported: B = 100 and B = 2,000,
```

### Block-tier admission criterion (`eval/PROTOCOL.md`)

Amendment 6:

```
623	   - **Block, TTL 3600 s:** k_block = the largest k in K whose region on
624	     val_a has >= 30 incidents and an incident-precision lower bound >=
625	     0.80 (IP-clustered bootstrap of amendment 3: the IPs with an incident
626	     in the region, 1,000 resamples, `default_rng(42)` per call). **If no
627	     k qualifies there is no block tier**, and nothing is ever blocked.
```

Restated under capped admission, amendment 7:

```
712	   **Block.** Unchanged criterion: k_block = the largest k in amendment
713	   6's grid K whose capped block region on val_a has >= 30 incidents and
714	   an IP-clustered lower bound >= 0.80. None is expected; if none, there
715	   is no block tier.
```

So: incident minimum **30**, lower-bound bar **0.80**. Deployed:
`RESPONSE_TIER_RATES["block"] = 0` (no block tier; `config.py:262,267`).

### Step-up band bar (`eval/PROTOCOL.md`)

The bar is **0.2149** (a lower bound, on val_a). Amendment 6:

```
628	   - **Step-up challenge** (simulated MFA, recorded, not enforced, TTL
629	     3600 s): k_step = the largest k in K, k > k_block, whose band (rate-k
630	     region minus the rate-k_block region) has >= 30 incidents on val_a and
631	     a lower bound >= 0.2149. None qualifies: no step-up tier.
```

Amendment 7 (replaces "largest k" with a volume-capped choice, same bar):

```
731	   k_step = the k in K_step that maximises attacking IPs challenged,
732	   subject to (i) >= 30 band incidents on val_a (carried over from
733	   amendment 6), (ii) band lower bound >= 0.2149, and (iii) mean
734	   legitimate users challenged per day <= **U = 200**. Ties: the smaller
735	   k. **If no k qualifies there is no step-up tier.**
```

Amendment 9 (test plan) reports tiers against both 0.2149 and 2 x the May
base rate (lines 841-843, 868).

### 30-day alert retention: by save time (wall clock), not event time

- Setting: `config.ALERT_RETENTION_DAYS = int(os.environ.get(
  "ALERT_RETENTION_DAYS", "30"))` (`config.py:236`; comment lines 234-235:
  "saved more than this many days ago (wall clock)").
- `saved_at` is set at insert to the wall clock,
  `alert.setdefault("saved_at", datetime.now().strftime(...))`
  (`utils/alert_store_sqlite.py:125`).
- Prune: `cutoff = datetime.fromtimestamp(time.time()) - timedelta(days=
  retention_days)` (`utils/alert_store_sqlite.py:175-177`), then
  `DELETE FROM alerts WHERE saved_at < ?` (line 182), then incidents left
  with no alert are deleted (lines 184-187). `retention_days <= 0` disables
  it (line 173).
- When: on store open (`utils/alert_store_sqlite.py:105`) and then at most
  once per 86,400 s of the monotonic clock, checked on writes
  (`_maybe_prune`, lines 197-204; called from `save_alerts`, line 152).
- The module docstring states the reason (`utils/alert_store_sqlite.py:16-20`):
  "Wall clock, not event time, so replaying old data does not prune what it
  just wrote."
- Retention is store housekeeping only: no detector, triage or tier state
  reads the store.

## 6. Phase 6 figures: S1 TPR, val_b step-up cost, S5 timing

Read-only, at 82eab63. Only saved results JSON (and the saved stdout and
report in `C:\Users\Dell\audit_scratch\`) were read; nothing went through the
evaluation loaders, no metric was computed, no code changed.

### 6.1 S1: TPR at 1% FPR per variant and seed (May)

**File.** `results/phase6_secondary.json` does not exist. S1 is written by
`eval/phase6_secondary.py` (`stage_s1`, `save_json(_out_name("s1", ...))`,
lines 114-117) to **`results/phase6_s1.json`**. All values below come
from that file.

JSON path: `variants/<v>/seed_<s>/<stratum>/tpr_at_1pct_fpr`, stratum `all`
(2,158,083 May events) or `new_attackers` (1,974,163; `events/*`).

| Variant | Seed | May, all | May, new attackers |
|---|---|---|---|
| (a) original | 42 | 0.003002 | 0.000942 |
| (a) | 43 | 0.002717 | 0.001005 |
| (a) | 44 | 0.002622 | 0.000879 |
| (b) maps all rows, fit non-attack | 42 | **0.004373** | 0.000942 |
| (b) | 43 | 0.003823 | 0.000754 |
| (b) | 44 | **0.004343** | 0.001130 |
| (c) label-free | 42 | 0.003127 | 0.000754 |
| (c) | 43 | 0.002922 | 0.000691 |
| (c) | 44 | 0.003763 | 0.000942 |

Mean / min / max over seeds are under `variants/<v>/over_seeds/<stratum>/
tpr_at_1pct_fpr` (e.g. (b) all: mean 0.004180, max 0.004373; (a) all: max
0.003002; (c) all: max 0.003763; new attackers max over all variants
0.001130, (b) seed 44).

Metric code: `eval/phase4.py:415-423` (`event_metrics`),
`tpr_at_1pct_fpr = max(tpr[fpr <= 0.01])` on the ROC curve of the event
scores (`s[rows] = -P2.score_samples(model, Xs)`,
`eval/phase6_secondary.py:95-97`).

**"at most 0.004" (`PHASE6_REPORT.md:181`, "TPR at 1% FPR: at most 0.004
for every variant").** No JSON field holds 0.004; it is prose written from
the per-seed values (the S1 stdout, `phase6_s1_stdout.txt` lines 4-22, prints
them rounded to 4 places). **It is not exact:** variant (b), May all events,
is 0.0044 at seed 42 (0.004373) and 0.0043 at seed 44 (0.004343), and the
(b) mean is 0.0042. Correct statements: "at most 0.0044 (all events) and
at most 0.0011 (new attackers)" or "below 0.005". Every other cell is
<= 0.0038.

### 6.2 Legitimate users challenged by step-up on val_b

| Source | JSON path | Total | Per day (mean of 16) | Max day |
|---|---|---|---|---|
| Phase 6 causal replay | `results/phase6_primary.json`: `results/val_b/P3/response_cost/all/step_up/legitimate_users_affected`, `.../legitimate_users_per_day`, `.../legitimate_users_max_day` | **1,433** | **90.3125** | 210 |
| Phase 5b | `results/phase5b_response.json`: `response_cost/val_b/all/step_up/legitimate_users_affected`, `.../legitimate_users_per_day` | **1,443** | **90.9375** | 210 (max of `.../legitimate_users_daily`) |

(`phase6_primary_devonly.json` has the same values as `phase6_primary.json`.)

**They are different policies, not just different runs.**

- Phase 5b (`protocol: "eval/PROTOCOL.md amendment 7"`) is T2, step-up
  200/day capped, queue 500, **without** the amendment 8 score floor.
- Phase 6 (`protocol: "eval/PROTOCOL.md amendment 9"`) is the frozen system,
  which **includes the floor** (`config.RESPONSE_FLOOR_DETECTORS`; recorded
  in `results/phase6_replay_check.json` `defaults/RESPONSE_FLOOR_DETECTORS`).
  The stream also continues into May, but val_b ends before May and the
  run is causal, so that does not change val_b.
- Phase 5c (`results/phase5c_floor.json`) shows both versions:
  - `halves/val_b/without_floor/step_up_cost/all/legitimate_users_affected`
    = 1,443 (per day 90.9375), equal to Phase 5b;
  - `halves/val_b/with_floor/step_up_cost/all/legitimate_users_affected`
    = 1,433 (per day 90.3125), equal to Phase 6.
- Phase 6 checks this itself: `consistency_with_earlier_phases/
  P3_tiers_equal_phase5c = true` in `phase6_primary.json`.
- Day by day (`.../legitimate_users_daily`), the floor lowers 6 of the 16
  val_b days by 1 to 4 users and leaves the other 10 the same
  (5b: 42, 210, 57, 54, 208, 171, 43, 44, 45, 59, 51, 41, 49, 190, 144, 47;
  6: 41, 210, 57, 54, 208, 171, 41, 43, 44, 58, 47, 41, 49, 190, 144, 47).

The report's "val_b 90.3" (`PHASE6_REPORT.md:365`) is the with-floor (Phase
6 / 5c) value.

### 6.3 S5: 87.0 µs vs 81.5 µs per event

Both come from one replay, `stage_replay` in `eval/phase6.py:376-518`,
written to `results/phase6_replay_check.json`. They measure different
things over different event sets.

| | 87.0 µs | 81.5 µs |
|---|---|---|
| JSON path | `S5/total_us_per_event_mean` = 87.03 (also `S5/total_us_per_event_p50` 24.2, `S5/total_us_per_event_p99` 363.2) | `replay_us_per_event` = 81.5, from `replay_seconds` = 696.9 and `events` = 8,550,667 |
| Events averaged | **May only**, 2,158,083 (`per_event[S.n_dev:n]`) | **All**: dev (6,392,584) + May |
| What is timed | Only `mon._process_event(e)`, per event, with `time.perf_counter()` (`eval/phase6.py:416-418`) | The whole loop, wall clock `time.time()` (`eval/phase6.py:406-420`). That includes building each event dict (`events(S)` generator), the untimed `status_untimed(e)` call, array writes, `_process_event`, and the final `responder.flush()` |
| Formula | `1e6 * per_event[S.n_dev:n].mean()` (`eval/phase6.py:487`) | `1e6 * t_replay / n` (`eval/phase6.py:517`) |

So the 81.5 µs figure includes *more* work per event than the 87.0 µs
figure but is averaged over a different set of events. It is lower because
dev events (75% of the replay) cost less on average in `_process_event`
than May events. The per-event dev times are not saved (`per_event` is not
written to disk), so the size of that gap cannot be read back from the
results. The two numbers are not comparable, and neither is "wrong". The
per-May-event figure for the frozen pipeline is 87.0 µs.

The stage buckets (`S5/us_per_event`: rules 30.08, triage_response 29.4,
analysis 6.43, store_record 13.65; sum 79.56) are May-only deltas of
wrapped methods (`_Timer`, `eval/phase6.py:355-373,396-401,411-412,485`),
divided by the May event count. The other ~7.5 µs of the 87.03 is
`_process_event` work outside the wrapped methods. Every timer's own
overhead is inside the bucket it measures (`S5/note`).
