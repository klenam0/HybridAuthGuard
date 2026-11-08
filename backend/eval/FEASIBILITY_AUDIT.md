# Feasibility audit for the JCS article (read-only)

Written 2026-11-06. Read-only: no dataset row after 2020-05-31 was decoded,
and no frozen, declared or tagged file was changed. The only RBA quantities
this audit computed are row counts, taken from Parquet footer metadata
(`pyarrow.parquet.ParquetFile(path).metadata.num_rows`), which decodes no
row data. Every other number below is copied from a named file or computed
from those numbers by arithmetic.

## Freeze manifest

| When | Command (from `backend/`) | Output | Exit |
|---|---|---|---|
| Before the audit | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
| After the audit | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

`results/FREEZE.json`: `frozen_commit` 1b9ac866ee25e6e693e316521115d4ca761ab495,
date 2026-10-14. Tags: `v3.0.0-frozen` = bb40c168c55d6e2bd9f8af2c3906b8c0fda9185f,
`v3.0.0` = 97a37f926d81697fea0dcbc1d850dc3115a55ae9, HEAD = 07c1ae3f72a493c985b3bfbfcfd073ac8c36494b.
`git diff --stat v3.0.0-frozen HEAD -- agents config.py eval/phase5b.py eval/phase5c.py`
is empty, so the line numbers in Task 4 are the same at the tag and at HEAD.

---

## Task 1. Which months have never been read

### Rows per month (Parquet footers)

| Month | File | Rows |
|---|---|---:|
| 2020-02 | `data/rba_parquet/month=2020-02/part-0.parquet` | 2,004,450 |
| 2020-03 | `data/rba_parquet/month=2020-03/part-0.parquet` | 2,214,823 |
| 2020-04 | `data/rba_parquet/month=2020-04/part-0.parquet` | 2,173,311 |
| 2020-05 | `data/rba_locked/test_2020-05.parquet` (locked; not in the partitioned directory) | 2,158,083 |
| 2020-06 | `data/rba_parquet/month=2020-06/part-0.parquet` | 2,185,601 |
| 2020-07 | `data/rba_parquet/month=2020-07/part-0.parquet` | 2,221,046 |
| 2020-08 | `data/rba_parquet/month=2020-08/part-0.parquet` | 2,171,500 |
| 2020-09 | `data/rba_parquet/month=2020-09/part-0.parquet` | 2,162,510 |
| 2020-10 | `data/rba_parquet/month=2020-10/part-0.parquet` | 2,313,404 |
| 2020-11 | `data/rba_parquet/month=2020-11/part-0.parquet` | 3,090,246 |
| 2020-12 | `data/rba_parquet/month=2020-12/part-0.parquet` | 3,270,165 |
| 2021-01 | `data/rba_parquet/month=2021-01/part-0.parquet` | 3,100,885 |
| 2021-02 | `data/rba_parquet/month=2021-02/part-0.parquet` | 2,203,240 |
| **Total** | | **31,269,264** |

These equal `results/rba_conversion_stats.json` `rows_per_month` month by
month, and the total equals its `rows_total` and `PROTOCOL.md:10`. The
copy `results/phase6_cache/test_2020-05.parquet` (Phase 6 cache) also has
2,158,083 rows in its footer.

### The four splits

Date ranges are from `eval/PROTOCOL.md` (splits table, lines 24-30; val_a /
val_b in amendment 3) and `eval/datasets.py:39-43`.

| Split | Range (PROTOCOL.md) | Rows | Source of the row count |
|---|---|---:|---|
| `dev_train` | 2020-02-03 00:00 <= t < 2020-03-30 00:00 | 4,055,357 | **Not in PROTOCOL.md.** `results/phase2_data_audit.json` `splits/dev_train/rows`; also `results/amendment10_lookup.json` `dev_train_rows` |
| `val_a` | 2020-03-30 00:00 <= t < 2020-04-15 00:00 | 1,183,517 | **Not in PROTOCOL.md.** `results/amendment10_lookup.json` `lookup/val_a/events` |
| `val_b` | 2020-04-15 00:00 <= t < 2020-05-01 00:00 | 1,153,710 | **Not in PROTOCOL.md.** `results/amendment10_lookup.json` `lookup/val_b/events` |
| `test` (locked) | 2020-05-01 00:00 <= t < 2020-06-01 00:00 | 2,158,083 | `PROTOCOL.md:816` (amendment 9); `results/test_lock.txt` `rows` |

The only split row counts PROTOCOL.md itself states are `test` (2,158,083,
line 816) and `dev_val` = val_a + val_b (2,337,227, line 135). The val_a and
val_b counts add up to it: 1,183,517 + 1,153,710 = 2,337,227, which also
equals `results/phase2_data_audit.json` `splits/dev_val/rows`.

**Sum:** 4,055,357 + 1,183,517 + 1,153,710 + 2,158,083 = **8,550,667. Confirmed.**
It also equals the Feb + Mar + Apr + May footers (2,004,450 + 2,214,823 +
2,173,311 + 2,158,083), `results/phase6_replay_check.json` line 3 and
`results/phase6_twin_check.json` line 22.

### Months outside all four splits

- **Partly outside: none.** 1-2 February 2020 lies outside `dev_train`, but
  PROTOCOL.md:26 says those days have no rows. The stored data agree:
  `phase2_data_audit.json` `loaded_rows` is 6,392,584, which is the full
  Feb + Mar + Apr footer total, read through the `>= 2020-02-03` filter, and
  `splits/dev_train/time_range[0]` is `2020-02-03 12:43:30.772000`. So every
  February row is inside `dev_train`.
- **Wholly outside:** June 2020 to February 2021, nine months, 22,718,597 rows:

| Month | Rows |
|---|---:|
| 2020-06 | 2,185,601 |
| 2020-07 | 2,221,046 |
| 2020-08 | 2,171,500 |
| 2020-09 | 2,162,510 |
| 2020-10 | 2,313,404 |
| 2020-11 | 3,090,246 |
| 2020-12 | 3,270,165 |
| 2021-01 | 3,100,885 |
| 2021-02 | 2,203,240 |
| **Total** | **22,718,597** (= 31,269,264 - 8,550,667) |

PROTOCOL.md:30 reserves these months ("Not used. Reserved for an optional
drift study, to be decided later").

---

## Task 2. Are those months untouched?

### Code references to post-May-2020 months, date literals or date filters

Searched: every `*.py` under `backend/` (this includes `backend/eval/`,
`backend/ml/`, `backend/tests/` and the untracked `backend/demo/`). The
patterns were `2020-06` to `2020-12`, `2021-xx`, slash-dated forms,
`month=`, `month=*`, `rba_parquet` and `PARQUET_DIR`. Every read of the CSV
or of Parquet (`read_csv`, `pq.read_table`, `read_parquet`, `ParquetFile`,
`RBA_DATASET_PATH`) was also listed. Git history was searched with
`git log --all -G` over `*.py`.

**Date literals later than 2020-05-31: none.** The only post-May strings
are the exclusive upper bound of the test month:

| File:line | Text | Meaning |
|---|---|---|
| `eval/datasets.py:9` | `test 2020-05-01 00:00 <= t < 2020-06-01 00:00 (LOCKED)` | docstring, exclusive end of May |
| `eval/datasets.py:43` | `TEST_END = pd.Timestamp("2020-06-01 00:00:00")` | exclusive end of May, used only by `load("test")` on the locked file |
| `tests/test_datasets.py:34` | `"2020-06-01 00:00:00"` | synthetic boundary row in a unit test |

The one git-history hit (commit cd2da60, 2026-10-13) adds these same three
lines.

**Month partitions and readers:**

| File:line | What it does | Can it reach June 2020 or later? |
|---|---|---|
| `eval/datasets.py:44` `DEV_MONTHS = ("2020-02", "2020-03", "2020-04")`; `:59-60` `_month_file`; `:67` `pq.read_table` | the only loader for the partitioned copy; it opens only the three dev partitions, and `load("test")` opens only `data/rba_locked/` | No: no code path builds a partition path for any other month |
| `eval/convert_rba.py:7, 39, 74, 78` | the one-off CSV to Parquet conversion; **it wrote every month, June 2020 to February 2021 included** | Yes, once, at conversion. Its docstring (lines 11-13) says it "reads no label column: per batch it only parses rows, counts them per month, checks timestamp order and writes them out". Its stored output (`rba_conversion_stats.json`) holds only row counts, order checks and timing |
| `tests/test_features_v4.py:196`, `tests/test_phase5_policy.py:454` | open `month=2020-02` only | No |
| `eval/lock_test.py:34` | footer row count and file hash of the locked May file | No |
| `eval/phase6.py:81` | reads the Phase 6 May cache | No (May only) |
| `eval/lanl_*.py` | LANL dataset, not RBA | Not applicable |
| `ml/train_from_dataset.py:86`, `ml/train_from_dataset_v2.py:134` (and the batch scripts that call `stream_dataset()`: `ml/batch4_*`, `batch5_*`, `evaluate_hybrid_*`, `train_from_dataset_v3*.py`) | pre-protocol (Batches 1-5): stream the **raw CSV from the first row** in 100,000-row chunks and stop once 700,000 non-attack and 70,000 attack rows are collected (`ml/train_from_dataset_v2.py:100-102`, break at about line 167). They cache to `results/rba_sample_cache.pkl` (gitignored) | By construction the stop comes long before June (February alone has 2,004,450 rows). **The sample's actual time range is not in any stored output, and the cache was not opened (opening it would read data). Missing: no stored evidence either way.** |

### Access logs, full contents

`backend/results/test_access.log` (1 line, tab-separated):

```
2026-10-14T09:11:49	ALLOWED	pid=57564	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\phase6.py cache
```

`backend/results/lanl_test_access.log` (8 lines, tab-separated):

```
2026-10-14T16:01:09	CONVERT	no statistics	C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_convert.py
2026-10-15T03:43:45	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T03:55:49	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T04:50:59	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T04:53:15	ALLOWED	pid=7756	run_id=L3-20261015T034342-14240	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p2 --target test --tag test --scorer D1 --run-id L3-20261015T034342-14240
2026-10-15T06:45:20	ALLOWED	pid=22432	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p2 --target test --tag test --scorer D1 --run-id L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation
2026-10-15T06:45:42	ALLOWED	pid=17144	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p2 --target test --tag test --scorer D2 --run-id L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation
2026-10-15T06:45:58	ALLOWED	pid=20124	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_final.py --p2 --target test --tag test --scorer D3 --run-id L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation
```

No other `*access*.log` exists in the repository. These logs record only
`load("test")` calls (RBA May) and LANL test reads. **No mechanism logs
reads of the June 2020 to February 2021 partitions or of the raw CSV.**

### Has data after May 2020 ever been loaded? Plain answer: yes.

1. **Conversion (row level, no statistics).** `eval/convert_rba.py`
   decoded every CSV row, June 2020 to February 2021 included, to write the
   partitions. Its stored output has row counts per month only.
2. **Label counts on the reserved months exist and are published.**
   `results/rba_ato_counts.json`. Its own `description` says:
   "Rows with Is Account Takeover = True in the raw rba-dataset CSV, whole
   file and per calendar month ... counted on 2026-10-15, after the May 2020
   test month was already scored." Under `per_month`, every month from
   2020-06 to 2021-02 has the keys `ato_true`, `ato_true_login_successful`
   and `ato_true_attack_ip`, plus whole-file totals. The per-month values
   are tabulated in `eval/DATASET_DESCRIPTION.md` (lines 3-49, including a
   stated observation about which late months have no account-takeover
   label) and in `eval/METHODS_FACTS.md` (whole-file and per-month counts).
   It came in commit 365e384 (2026-10-15), which is contained in tag
   `v3.0.0`. No script in the repository writes this file
   (`grep rba_ato_counts` over `*.py` finds nothing), so it was an ad hoc
   computation over the raw CSV.
   - Consequence for a locked June 2020 to February 2021 test: the
     `Is Account Takeover` label has already been counted per month on
     every candidate month, and those counts are in a tagged, released
     document. Any account-takeover-based claim on those months is
     therefore not blind. No stored output gives `Is Attack IP` counts,
     attack base rates, detector metrics or per-address statistics for
     those months. The only attack-IP figure is `ato_true_attack_ip`, which
     counts the intersection with takeover rows.
   - Audit disclosure: the auditor checked which months the file covers by
     printing its structure with numbers masked. A later digit-masked grep
     of the Markdown files masked only numbers of three or more digits, so
     the small per-month account-takeover counts appeared on the auditor's
     console. They are not reproduced in this report or used anywhere in it.
3. **Pre-protocol CSV sampling.** Last row of the reader table above: it
   streams from the start of the file and stops early by construction, but
   no stored output records its time range. **Missing.**
4. **Every Phase 2 to 6 path** loads only the dev partitions or the locked
   May file (above), and no stored JSON or TXT under `results/` contains a
   full date (`YYYY-MM-DD`) after 2020-05-31. Only month keys (`2020-06` ...)
   appear, in `rba_conversion_stats.json` and `rba_ato_counts.json`.

---

## Task 3. Leakage statistic from stored output only

Inputs: `results/phase4b_diag.json` (val_a, val_b), `results/phase6_s1.json`
(May), `results/amendment10_lookup.json` (cross-check). Nothing refitted, no
dataset read. Values are Python `repr` of IEEE doubles, not rounded.

- above-chance ranking share of variant v = (AUC_v - 0.5) / (AUC_a - 0.5)
- label-attributable share of (a) relative to (c) = (AUC_a - AUC_c) / (AUC_a - 0.5)

(The second is 1 minus the first for v = c, by algebra.)

### Inputs

| Half | Variant | Seed | ROC-AUC | JSON path |
|---|---|---|---|---|
| val_a | a | single run (seed 42 per PROTOCOL.md amendment 5; the file does not record the seed) | 0.762999627767321 | `phase4b_diag.json` `variants/a/val_a/roc_auc` |
| val_a | b | single run | 0.5531101898878288 | `phase4b_diag.json` `variants/b/val_a/roc_auc` |
| val_a | c | single run | 0.5039329966694688 | `phase4b_diag.json` `variants/c/val_a/roc_auc` |
| val_b | a | single run | 0.750421331271785 | `phase4b_diag.json` `variants/a/val_b/roc_auc` |
| val_b | b | single run | 0.5552088718116418 | `phase4b_diag.json` `variants/b/val_b/roc_auc` |
| val_b | c | single run | **MISSING**: `phase4b_diag.json` has no `variants/c/val_b` | — |
| May, all | a | 42 / 43 / 44 | 0.7487062306072065 / 0.741738379898951 / 0.7477192716830735 | `phase6_s1.json` `variants/a/seed_4x/all/roc_auc` |
| May, all | b | 42 / 43 / 44 | 0.5700513078955789 / 0.5761743650777634 / 0.5687845737407811 | `phase6_s1.json` `variants/b/seed_4x/all/roc_auc` |
| May, all | c | 42 / 43 / 44 | 0.5206572901452777 / 0.5183114384719445 / 0.5197991675448458 | `phase6_s1.json` `variants/c/seed_4x/all/roc_auc` |
| May, all | a / b / c | mean | 0.7460546273964104 / 0.571670082238041 / 0.5195892987206894 | `phase6_s1.json` `variants/{a,b,c}/over_seeds/all/roc_auc/mean` |

Cross-check: `amendment10_lookup.json` `s1_construction_a/val_a/roc_auc`
(0.762999627767321) and `s1_construction_a/val_b/roc_auc`
(0.750421331271785) equal the `phase4b_diag.json` values for (a).

Missing input: (c) on val_b. PROTOCOL.md amendment 5 reports it only in the
`confirm` stage. A key `d1_c_val_b/roc_auc` exists in
`results/phase4b_confirm.json`, but that file is outside the three allowed
inputs, so its value was not read or used.

### Results: val_a and val_b (one run each, no seed mean)

| Half | Share (a) | Share (b) | Share (c) | Label-attributable, (a) vs (c) |
|---|---|---|---|---|
| val_a | 1.0 | 0.2019401713177177 | 0.014954381125392126 | 0.9850456188746078 |
| val_b | 1.0 | 0.22046393384804353 | **MISSING** (no AUC_c) | **MISSING** (no AUC_c) |

### Results: May test month, all events (per seed, paired by seed)

| Seed | Share (a) | Share (b) | Share (c) | Label-attributable, (a) vs (c) |
|---|---|---|---|---|
| 42 | 1.0 | 0.28166285872513674 | 0.08305899733530504 | 0.9169410026646949 |
| 43 | 1.0 | 0.3151107619303359 | 0.07574899144934644 | 0.9242510085506536 |
| 44 | 1.0 | 0.27767146767968265 | 0.0799258265629668 | 0.9200741734370332 |
| Mean of the per-seed shares | 1.0 | 0.2914816961117184 | 0.07957793844920609 | 0.920422061550794 |
| Share of the stored mean AUCs (`over_seeds/.../mean`) | 1.0 | 0.2912771159656989 | 0.07961361640693597 | 0.920386383593064 |

The two "mean" rows are different estimators: mean of ratios versus ratio
of means. The article should name the one it uses.

### Supplementary: May, new-attackers stratum (stored in the same file)

Not requested, and reported only because `phase6_s1.json` stores it. Inputs
are `variants/{a,b,c}/seed_4x/new_attackers/roc_auc` and
`.../over_seeds/new_attackers/roc_auc/mean`. Here AUC_a is close to 0.5
(0.5695 to 0.5745), so the denominator is small and the ratio is unstable.
Shares exceed 1 and the label-attributable share is negative, because (c)
ranks new attackers better than (a).

| Seed | Share (b) | Share (c) | Label-attributable, (a) vs (c) |
|---|---|---|---|
| 42 | 0.9322059511389607 | 1.0939409864681189 | -0.09394098646811898 |
| 43 | 1.0247720802235663 | 1.1607259386547344 | -0.16072593865473445 |
| 44 | 1.0778417657476016 | 1.0794230577857782 | -0.07942305778577823 |
| Mean of the per-seed shares | 1.0116065990367096 | 1.1113633276362105 | -0.11136332763621055 |
| From the stored mean AUCs | 1.0109138394734416 | 1.1104323227637876 | -0.1104323227637876 |

---

## Task 4. What a user-denominated response cap would require

Line numbers are at `v3.0.0-frozen` (identical at HEAD for these files; see
the freeze section). Files are under `backend/`.

### Where the daily step-up incident cap is enforced

- `config.py:267` `RESPONSE_TIER_RATES = {"block": 0, "step_up": 200, "queue": 500}`
  sets the cap, k = 200 incidents per day. The comment at `config.py:254-265`
  records that k was chosen subject to at most U = 200 legitimate users
  challenged per day on val_a.
- `agents/triage.py:124-125` load the rates; `:141` holds
  `self.admitted`, today's entries per tier.
- **Enforcement:** `agents/triage.py:189-196`. For each alerted event, the
  tiers are tried top down; an incident enters `tier` only if
  `k and self.admitted[tier] < k and self._qualifies(inc.score, tier)`
  (line 193), and then `self.admitted[tier] += 1` (line 195). The floor gate
  is at line 188.
- Day handling: `agents/triage.py:228-234` (`_roll`, day = `t // 86400`
  of event time) and `:236-245` (`_close_day`). The next day's cutoff is the
  k-th highest final score of the closed day (line 241), and `admitted` is
  reset (line 245).
- Offline twin (frozen, used by the gates): `eval/phase5b.py:65-102`
  `capped_entries`. Candidates are ordered by (day, first eligible event)
  at line 94, and the cap is `rnk < k` at lines 96-97.

### Where a challenge is applied to a source, and for how long

- `agents/response_agent.py:78` `self.challenge_list = BlockList(config.STEP_UP_TTL_SECONDS)`,
  with `config.py:295` `STEP_UP_TTL_SECONDS = 3600`.
- `agents/response_agent.py:112-113`: on **every** alerted event whose
  incident tier is `step_up`, `self.challenge_list.block(ip, t)`.
- `agents/response_agent.py:29-32` (`BlockList.block`): expiry = t + 3600,
  extended if later. A challenge therefore lasts from the admitting event
  until 3600 s of event time after the incident's last alerted event in the
  step-up tier. It can cross midnight, because `BlockList` is not reset by
  the triage day roll.
- `agents/response_agent.py:86-91` (`status`) and `:38-40` (`is_blocked`):
  the per-event check, made before the event. The challenge is the source
  IP's, not a user's.
- Offline twin: `eval/phase5.py:579-587` `before_ttl`.

### Is there a per-day count of distinct users challenged in the running path?

**No.** The running path has only:

- `agents/monitoring_agent.py:35` and `:99-101`:
  `challenged_source_events`, a cumulative count of **events** from a
  challenged IP. It is not per day and not per user. It is not written to
  `pipeline_stats.json` (no other reference at the tag).
- `agents/monitoring_agent.py:109`: each alert carries a
  `challenged_source` flag.
- `agents/triage.py:98-103` `_IPDay` keeps failed / success / placeholder /
  max ASN ratio per IP-day, but no user set.

The distinct-user count exists only after the fact, in evaluation code:

- `eval/phase5.py:590-624` `response_cost`:
  `legitimate_users_affected = len(np.unique(S.user[legit]))` (line 614),
  where `legit = benign_ev & ~S.unknown` and `benign_ev = ev & ~S.truth`
  (lines 610-612). **It uses the attack labels.**
- `eval/phase5b.py:125-161` `cost`: per-day distinct (day, user) pairs
  (lines 145-147) give `legitimate_users_per_day` / `_daily` (lines 154-155).
  `choose` (line 171-176) applies U to this offline value.
- `eval/phase6_primary.py:98, 101` (added after the tag, commit eb1aa5e)
  calls `P5B.cost` for May.

### What would have to change

1. **A label-free quantity.** The deployed system cannot see `S.truth`, so
   "legitimate users challenged" (amendment 7: benign events, non-placeholder
   users) cannot be the running cap. The running quantity would be distinct
   non-placeholder users with any event from a challenged IP that day. That
   is an upper bound on the evaluated quantity, so the article would need to
   report both.
2. **New running state.** A per-day set of user IDs, added where the
   challenge state is known before the event: `agents/monitoring_agent.py:99-101`,
   or in `ResponseAgent` from `status()`. It needs a day key matching
   `triage.py:229` and the placeholder exclusion of `config.UNKNOWN_ACCOUNT_IDS`.
3. **A new admission rule in `agents/triage.py:193`.** Today the cost of an
   admission is known when it happens (one slot). The user cost of a
   challenge is mostly realised *after* admission, while the 3600 s TTL
   runs and is renewed. A user cap must therefore either
   (a) stop admitting once today's running distinct-user count reaches U.
   That is reactive: incidents already admitted keep adding users, so U can
   be exceeded. Or (b) charge each incident an estimated user cost at
   admission, for example distinct users already seen from the IP today.
   That needs a user set in `_IPDay`, and it is still a forecast.
   `IncidentTriage` would also need the user count fed back from the
   response side, which it does not receive today.
4. **The cutoff.** `triage.py:241` defines the cutoff as the k-th highest
   previous-day score. Without k this needs a new definition (for example
   the score at which the previous day's cumulative challenged users reached
   U), or a kept k with U as a second constraint.
5. **Frozen files and protocol.** `agents/triage.py`,
   `agents/response_agent.py`, `agents/monitoring_agent.py`, `config.py`,
   `eval/phase5b.py` and `eval/phase5c.py` are all hashed in `FREEZE.json`.
   The change would break the freeze and the 0-mismatch twin gates. It would
   need a new dated amendment, a new freeze and new gates, and any result on
   May would be post hoc.

### Would it alter the admission order of incidents?

- **The order in which candidates are offered: no.** Candidates are still
  taken in stream order of their first eligible event within the day
  (`triage.py:189-196`; twin `phase5b.py:94`). T2 scores and the cutoffs do
  not depend on admissions: `_close_day` (line 237) ranks the final scores
  of all incidents, admitted or not, and challenge state does not feed back
  into detection or scores (`monitoring_agent.py:82-84`).
- **The admitted set: yes.** Under rule (a), the admitted step-up incidents
  remain a time-ordered prefix of the same candidate list, cut at a
  different point that is no longer 200. Under rule (b), a high-cost incident
  can be refused while later, cheaper ones are admitted, so the set is no
  longer a prefix of the order.
- **Knock-on effect on the queue tier: yes.** An incident refused at
  step-up falls through to the queue test on the same event
  (`triage.py:189-196` loop, and `higher` in `phase5b.py:101`). So the queue's
  500 daily slots, and which incidents get them, change too. Emails also
  change, because `EMAIL_TIERS = ("block", "step_up")` (`config.py:308`).

---

## Files

- Created: `backend/eval/FEASIBILITY_AUDIT.md` (this file).
- Changed: none. No tag moved, no commit made. The pre-existing working-tree
  state (`M frontend/src/pages/Incidents.jsx`, `?? backend/demo/`) was left
  as found.
