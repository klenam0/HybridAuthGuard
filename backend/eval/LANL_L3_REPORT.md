# LANL phase L3 report

## 0. Changes made before the test was opened (memory; no measure changed)

This is a note, not an amendment: no LA3/LA4 measure, k, bar or procedure
changed. Everything here was committed before the first ALLOWED line in
`results/lanl_test_access.log`.

### What changed and why

The test has about 812M auth rows (lock) and about 127M filtered rows
(assumed at the dev maximum filtered share). The L2 code builds full-length
arrays that would not fit the machine's commit limit (about 11 GB free when
checked). Approved changes:

- **`eval/lanl_data.py`.**
  - `load_lanl(..., by_day=True)` returns an iterator of (day, table), so test
    days are read one at a time through the guarded loader. The guard, the
    access-log line and the lock check all happen at the call.
  - `run_id=` is written into every access-log line.
- **`eval/lanl_d_metrics.py`** (memory only):
  - `evaluate()` no longer builds full-length rank arrays. `positive_ranks()`
    computes, for the positives only, the same ranks L2 used, overall and
    within each day: score descending, then stream position ascending. That
    is rows with a higher score plus earlier rows with an equal score. It
    asserts that position increases with the array index and that day is
    non-decreasing, both true by construction in `load_split`. Ties are
    handled exactly as in L2.
  - `np.unique(day)` is replaced by run-length counts on the sorted day array
    (`day_counts`).
  - `load_split()` preallocates instead of building lists and concatenating.
  - `main()` keeps a red-team user and event count only for positive rows,
    instead of full-length arrays, and passes views instead of copies when a
    scope drops no rows.
  - `main(splits=...)` replaces the hard-coded `("val_a", "val_b")`.
  - The sklearn cross-check (`check_strict_ranking_vs_sklearn`) needs
    full-length arrays. It is a self-check, not an LA3.6 measure. It still runs
    for populations of up to 20,000,000 rows, which covers both val splits, and
    above that records `"skipped"` with the reason. On the test it will be
    skipped.
- **`eval/lanl_final.py`** (new) drives the imported L2 A and D code over days
  0 to the last target day. After every day it writes a checkpoint of the whole
  pass-1 state (twin, D state, offsets, label facts, step-up counts) and
  records the process's private commit.
  - The resume rule: if the run fails for an infrastructure reason, resuming
    from the last completed day's checkpoint is the one allowed rerun, with a
    new run ID recorded.
  - The twin's and D state's string-normalising lambdas are replaced at
    construction by an equivalent module-level function (`_strip`) so the state
    can be pickled.

### Dev equality checks (saved output)

| check | file | result |
|---|---|---|
| Lean D metrics vs L2's saved `lanl_d_dev.json`, val_a and val_b, field by field: every metric block, bootstrap interval, top-k count, all-red-team line, stratum, definitions and the sklearn checks (only `seconds` and `peak_working_set_bytes` excluded) | `results/lanl_final_lean_check.json` | `first_difference: null`; `reproduces_L2_exactly: true` |
| Lean positive ranks equal L2's full `ranks()` at the positives, overall and per day, for D1-D3 on val_a and val_b | same file | all 6 `true` |
| Full Step 1 dry run on val_b with the new code (twin and D from day 0, D1 scored, A and D metrics) vs L2's saved val_b A and D blocks, sklearn checks, and the per-day twin, D and D1 arrays for days 12-13 | `results/lanl_final_dryrun_check.json` | all first differences `null`; all arrays equal; `reproduces_L2_exactly: true` |
| val_b run forcibly stopped after day 12 (exit 3), then resumed from the checkpoint, vs the uninterrupted dry run: every per-day file (arrays equal and file bytes equal), the A and D metric JSON, the label facts and the step-up counts | `results/lanl_final_resume_check.json` | `identical: true`; resumed `from_day: 13` |
| Lean D metrics memory on val_a, cross-check off | `results/lanl_final_lean_memory.json` | 128.6 bytes per filtered row (peak private minus private before; includes about 0.3 GB of fixed per-day transients, so it overstates the per-row cost) |

The access log held only the CONVERT line throughout these checks.

### Revised condition 4: memory bar (saved output; the test was not opened)

Machine state when this session began (after a restart): `C:\pagefile.sys`,
2,048 MB allocated, system-managed, 0 MB in use; free commit 21,309,595,648 B
of 36,282,888,192 B; free physical 19,989,999,616 B. Gates before: freeze,
test lock and LANL test lock all MATCHES; D1 model SHA-256
`48bf2436…cfb3` equals L2; `results/lanl_test_access.log` holds only the
CONVERT line.

`results/lanl_final_projection.json` is the earlier session's sum-rule
projection (free commit 11,480,932,352 B then; `within_limit: false`). It is
committed as found.

**Code change for 4a (before any test access).** `run()` in
`eval/lanl_final.py` now records the process's private commit at the start of
the run, right after pass 1's state is released (`del tw, S`, iterator reset,
`gc.collect()`), and right before the D metrics start (after the A metrics).
`--project-cond4` (`project_cond4()`) applies 4a and then 4b or the sum rule.
The val_b dry run was rerun with this code: `reproduces_L2_exactly: true`, all
first differences `null`, all arrays equal (`results/lanl_final_dryrun_check.json`;
only memory and timing fields differ from the previous version of that file).

**4a** (`results/lanl_final_projection_cond4.json`, block `4a`; dry run on val_b):

| figure | bytes |
|---|---|
| private commit at run start | 431,308,800 |
| private at end of pass 1 (after day 13) | 5,293,613,056 |
| peak private during pass 1 | 10,548,961,280 |
| private right after pass 1's state is released | 4,460,826,624 |
| private right before the D metrics start (after the A metrics) | 5,653,790,720 |

Measured against the end-of-pass level, pass 1's within-run rise is
4,862,304,256 B. Right after the release, the drop is 832,786,432 B (17.1% of
that rise). Right before the D metrics, private is 360,177,664 B *above* the
end-of-pass level (−7.4%), because the A metrics ran in between. Measured
against the peak, the rise is 10,117,652,480 B and the drop is 60.2% right
after the release, or 48.4% before the D metrics. Every reading is under 80%,
so **4a fails and the sum rule stands.**

**Sum rule** (same file):

| figure | bytes |
|---|---|
| projected pass 1 peak (end-of-day slope 109,989,717 B/day to day 57: 9,968,216,789; plus largest within-day rise 5,846,470,656) | 15,814,687,445 |
| projected D metrics peak: residual before D metrics 5,653,790,720 × 1.9436 (projected end-of-pass growth) = 10,988,856,740, plus 128.63 B/row × 127,416,854 assumed test filtered rows = 16,389,234,235 | 27,378,090,976 |
| sum | 43,192,778,420 |
| free commit at check | 20,773,273,600 |
| 80% of free commit | 16,618,618,880 |
| free physical at check / 80% | 20,751,912,960 / 16,601,530,368 |

43.19 GB > 16.62 GB: **the bar fails.** The test was not opened. For
reference only (4b does not apply), the 4b bar would also fail:
max(15.81 GB, 27.38 GB) > 16.62 GB, and even with the unscaled residual the
D metrics peak (5.65 + 16.39 = 22.04 GB) exceeds it. Pass 1 alone,
15.81 GB, is under 80% of free physical (16.60 GB).

Gates after: freeze, test lock and LANL test lock MATCHES;
`results/lanl_test_access.log` still holds only the CONVERT line.

### Approved process split: equality and per-process memory bar (the test was not opened)

Approved after the condition 4 failure: one evaluation run = process 1 (pass 1
+ A metrics; writes the D score arrays and per-day outputs) followed by
process 2 (D metrics only, fresh Python processes reading those arrays), same
run ID throughout; if process 2 still fails the bar, one fresh process per
scorer. Bar per process: projected peak <= 80% of free commit and <= 80% of
free physical RAM, rechecked just before each process starts.

At the start of this step: `C:\pagefile.sys` 2,048 MB allocated
(system-managed, 51 MB in use); free commit 20,592,295,936 B; free physical
20,611,391,488 B. Gates MATCHES; access log only the CONVERT line.

**Code (before any test access).**
- `eval/lanl_d_metrics.py`: `load_split(split, scorers=...)` and
  `main(splits, scorers=...)` load and evaluate only the given scorers.
  Defaults are unchanged. A scorer's blocks do not depend on the other
  scorers: the bootstrap weights come from a fresh `default_rng(42)` per call
  (`lanl_a_metrics.boot_weights`).
- `eval/lanl_final.py`:
  - `run()` is now process 1. It no longer calls the D metrics, and it records
    memory after the A metrics.
  - `d_process()` is process 2 for one scorer. On the test it reads the
    red-team frame through `load_lanl("test", "redteam")` with the run ID, and
    no auth day.
  - `orchestrate()` runs process 1 and then process 2 for D1, D2, D3 in
    sequence, each as a child process. On the test it checks the bar
    immediately before each one and stops with exit 4 if it fails. Process-1
    outputs stay on disk, and `--skip-p1 --run-id <ID>` continues the run
    under the same ID.
  - `merge_d()` merges the per-scorer JSON into the single-process layout and
    asserts that the scorer-independent fields agree.
  - `project_split()` writes the bar projection;
    `--measure-lean-scorers` runs the per-scorer val_a measurement.

**Process 2 as one process fails.** From `results/lanl_final_lean_memory.json`
(val_a, fresh process): 427,524,096 + 128.63 B/row × 127,416,854 =
16,816,758,331 B > 80% of free commit (16.47 GB at the time). So per-scorer
processes (item 2).

**Per-scorer bytes per row on val_a** (fresh process each, cross-check off;
`results/lanl_final_lean_memory_scorers.json`): D1 112.51, D2 112.54,
D3 112.49 B/row (private before about 427.4 MB; peak about 1,391.5 MB).

**Equality (item 3).** The split val_b dry run reproduces L2 exactly:
`results/lanl_final_dryrun_check.json`, A, D and sklearn-check first
differences `null`, arrays for days 12-13 equal, `reproduces_L2_exactly: true`
(822.1 s). The first attempt of this dry run ran all four processes but
stopped in `merge_d` on its own consistency assert (`('D2', 'all')`). This
was a bug in the merge: it compared each scorer's shared fields against a
dict that already held D1. The merge was fixed and the whole dry run rerun;
the result above is from the rerun.

**Projection** (`results/lanl_final_projection_split.json`). Process 1, from
the split dry run's process 1:

| figure | bytes |
|---|---|
| private at start | 430,534,656 |
| end-of-day private, days 0-13: slope per day | 108,601,137 |
| projected end-of-pass private at day 57 | 9,892,567,117 |
| largest within-day rise | 5,803,024,384 |
| projected pass 1 peak | 15,695,591,501 |
| private right after release / after A metrics | 4,459,659,264 / 5,668,687,872 |
| projected A metrics peak (release × 1.9344 + 6,136,180,736 rise through A metrics) | 14,762,787,793 |
| **process 1 projected peak** | **15,695,591,501** |

Process 2, per scorer:
- My first projection used the larger of val_a (cross-check off) and the
  val_b dry-run process (cross-check on, about 206.5 B/row): about 26.7 GB.
  The cross-check builds full-length arrays and is skipped on the test (127M
  rows > 20,000,000), so that figure measures a step the test does not run.
- Before anything was committed or opened, the method was changed to use the
  val_b dry-run process re-run with the cross-check off (memory only; outputs
  `p2_<s>_nocheck.json` in the work directory, not compared to anything).
  This is a choice made after seeing a failing figure, recorded here. It
  does not change the outcome.

| scorer | val_b private before | val_b peak | val_b B/row (check off) | val_a B/row (check off) | B/row used | projected peak (× 127,416,854 rows) |
|---|---|---|---|---|---|---|
| D1 | 429,236,224 | 1,369,133,056 | 147.24 | 112.51 | 147.24 | 19,190,094,003 |
| D2 | 428,392,448 | 1,369,407,488 | 147.42 | 112.54 | 147.42 | 19,211,570,274 |
| D3 | 428,302,336 | 1,368,838,144 | 147.34 | 112.49 | 147.34 | 19,201,914,428 |

At projection: free commit 20,296,404,992 B (80%: 16,237,123,994); free
physical 20,733,345,792 B (80%: 16,586,676,634).

| process | projected peak | <= 80% free commit | <= 80% free physical |
|---|---|---|---|
| p1 | 15,695,591,501 | yes | yes |
| p2_D1 | 19,190,094,003 | no | no |
| p2_D2 | 19,211,570,274 | no | no |
| p2_D3 | 19,201,914,428 | no | no |

**The bar fails for every process 2. The evaluation was not started; the
test was not opened.**

Note on the per-row figures: the dev peak rise above the starting private
barely changes with population size (val_a 964,100,096 B at 8,569,072 rows;
val_b 939,896,832 B at 6,383,434 rows). Most of the dev peak is therefore not
proportional to rows, and the linear per-row projection probably overstates
the test peak. This was not used to change the bar: a two-point fit gives
11 B/row, below the 25 B/row the stored arrays alone need (pos, day, score
and y), so two dev sizes cannot pin down the per-row cost.

Gates after: freeze, test lock and LANL test lock MATCHES;
`results/lanl_test_access.log` holds only the CONVERT line.

### Process 2 re-measured on all dev days; bar re-checked (the test was not opened)

Machine state at the start of this session (after a restart with a fixed
pagefile): `C:\pagefile.sys` 32,768 MB allocated (initial = maximum = 32,768
MB; not system-managed), 0 MB in use, peak 0 MB; free commit 54,937,903,104 B
of 68,495,142,912 B; free physical 21,955,854,336 B. Gates before: freeze,
test lock and LANL test lock MATCHES; D1 model SHA-256 `48bf2436…cfb3`
equals L2; `results/lanl_test_access.log` holds only the CONVERT line. With
the larger pagefile, free physical RAM, not free commit, is now the binding
limit.

**Approved method (option 1).** Process 2 is measured on all dev days 0-13 as
one population, one fresh process per scorer, sklearn cross-check off as on
the test. A least-squares line, peak private = fixed + per_row × rows, is fit
through three measured points per scorer (val_b, val_a, dev_all) and
evaluated at 127,416,854 test rows. The projected peak is the larger of that
fit and (dev_all peak / dev_all rows) × test rows. Process 1's projection is
unchanged (`lanl_final_projection_split.json`).

**Code (before any test access; measurement only, no reported dev result
changes).** `eval/lanl_final.py`:
- adds the dev target `dev_all` (days 0 to c3 = 14). Its red-team frame is
  the dev frame with `split` relabelled `dev_all` for days before c3.
- `prep_dev_all()` builds `final_devall/d` in the work directory. It holds
  hard links to L2's unchanged per-day D files for days 0-13 and L2's D1
  scores for days 8-13, plus D1 scores for days 0-7 computed exactly as
  `run()` computes them (L2 scored only val days).
- `measure_dev_all()` runs the existing `d_process` per scorer with
  `--no-crosscheck` and writes `results/lanl_final_memory_devall.json`. The
  dev_all metric outputs stay in the work directory. They are not a reported
  result and were not looked at.
- `project_devall()` writes `results/lanl_final_projection_devall.json`.
  `PROJ_FILE` (the file `bar_check` reads before each process) now points to
  it.

**Measured points** (peak private, fresh process, cross-check off):

| scorer | val_b (6,383,434 rows) | val_a (8,569,072 rows) | dev_all (33,578,516 rows) |
|---|---|---|---|
| D1 | 1,369,133,056 | 1,391,513,600 | 2,843,766,784 |
| D2 | 1,369,407,488 | 1,391,706,112 | 2,876,403,712 |
| D3 | 1,368,838,144 | 1,391,431,680 | 2,842,398,720 |

Private before the D metrics in the dev_all processes: 428.5-428.8 MB.

**Fit and projections** (to 127,416,854 rows):

| scorer | fixed (B) | per row (B) | fit projection | dev_all peak / row | ratio projection | **used (max)** |
|---|---|---|---|---|---|---|
| D1 | 965,039,322 | 55.83 | 8,078,219,542 | 84.69 | 10,790,941,956 | **10,790,941,956** |
| D2 | 956,099,965 | 57.06 | 8,226,603,590 | 85.66 | 10,914,785,865 | **10,914,785,865** |
| D3 | 965,176,712 | 55.78 | 8,072,693,615 | 84.65 | 10,785,750,708 | **10,785,750,708** |

Fit residuals are under 54 MB at every point. The ratio projection is the
larger for every scorer, so it is the one used.

**History of the process 2 projection method:**
1. A single process for all scorers, using val_a's 128.63 B/row: 16.82 GB.
   It failed and led to per-scorer processes.
2. Per scorer, the larger of val_a and the val_b dry run with the cross-check
   on (about 206.5 B/row): about 26.7 GB. The cross-check does not run on the
   test.
3. After seeing figure 2 fail, and before anything was committed or opened,
   the method switched to val_b with the cross-check off (147.2-147.4 B/row):
   19.19-19.21 GB. This failed (commit c32e0d2).
4. Approved after that failure: this section's three-point fit and dev_all
   ratio, 10.79-10.91 GB. Each change came after the previous figure was seen
   to fail. All were made before any test access.

**Bar at projection** (free commit 55,606,562,816 B, 80% = 44,485,250,253;
free physical 22,405,267,456 B, 80% = 17,924,213,965):

| process | projected peak | <= 80% free commit | <= 80% free physical |
|---|---|---|---|
| p1 | 15,695,591,501 | yes | yes |
| p2_D1 | 10,790,941,956 | yes | yes |
| p2_D2 | 10,914,785,865 | yes | yes |
| p2_D3 | 10,785,750,708 | yes | yes |

**Every process passes at projection; option 3 was not needed.** The bar is
rechecked immediately before each process starts (`bar_check`, logged to
`results/lanl_final_bar_checks.json`). Process 1 has the least margin:
15.70 GB against 17.92 GB.

Disk: the work volume had 46 GB free. Scaled from val_b, the test's per-day
outputs need about 11 GB.

Gates after the measurement: freeze, test lock and LANL test lock MATCHES;
`results/lanl_test_access.log` still holds only
the CONVERT line.

## 1. The evaluation run: stopped in process 2 (D1) on a code assertion

Run ID `L3-20261015T034342-14240`, started 2026-10-15T03:43:42 from commit
6a59742 (`FINAL_EVAL=1 python -m eval.lanl_final`). Access-log lines (all with
this run ID):

```
2026-10-15T03:43:45	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=...lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T03:55:49	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=...lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T04:50:59	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	argv=...lanl_final.py --p1 --target test --tag test --run-id L3-20261015T034342-14240
2026-10-15T04:53:15	ALLOWED	pid=7756	run_id=L3-20261015T034342-14240	argv=...lanl_final.py --p2 --target test --tag test --scorer D1 --run-id L3-20261015T034342-14240
```

The process 1 lines are the red-team read, the test-day iterator (days 14-57)
and its reopening for the A metrics (`test_iterator_opens` = 2 in `p1.json`).
The process 2 line is the red-team read.

- **Bar checks** (`results/lanl_final_bar_checks.json`):
  - p1 passed at 03:43:42: 15,695,591,501 against 80% of free physical,
    17,756,251,750.
  - p2_D1 passed at 04:53:14: 10,790,941,956 against 17,981,217,178.
- **Process 1 completed.** It ran days 0-57 with no resume, in 4,171.1 s;
  peak private was 13,166,358,528 B (projected 15,695,591,501). It wrote
  `results/lanl_final_a.json` and the per-day D outputs.
- **Process 2 for D1 failed** with exit 1, in
  `eval/lanl_d_metrics.py:80` (`load_split`):
  `AssertionError: a positive row is outside the filter`. At least one
  LA3.1-positive test auth row is not in the LA3.3 filtered population. LA3.3
  covers this case: such red-team events count as missed in the all-red-team
  line. But the L2 loader asserts it never happens, which held on every dev
  split. D2 and D3 were not started, and `lanl_final_d.json`, the merge and
  the LA3.8 verdict were not produced.
- **Why the run was not resumed.** This is a deterministic code assertion,
  not an infrastructure failure, so resuming would fail the same way. The one
  recovery was not used. Handling the case needs a code change after the
  first ALLOWED line, which under the phase rules ends the phase. No code was
  changed, nothing was rerun, and no test output was opened. That includes
  `lanl_final_a.json` (on disk, not committed) and the label facts in
  `p1.json`.

Gates after: freeze, test lock and LANL test lock MATCHES.

## 2. Deviation: code fix after the first ALLOWED line

Approved as the only deviation, after section 1. It is not the
infrastructure recovery.

- **Assertion:** `eval/lanl_d_metrics.py:80` (before the fix), in
  `load_split`: `assert (pr >= 0).all(), "a positive row is outside the filter"`.
- **Cause class:** at least one LA3.1-positive test auth row is outside the
  LA3.3 filter. Process 1 saves `y` only for filtered rows, but it saves the
  label pairs (`pairs_row`, `pairs_event`) for every matched row. The L2
  loader asserted every pair row was in the filter, which held on every dev
  split.
- **No test output was read before the fix.** Before any change, the SHA-256
  of every process 1 output was recorded and committed:
  `results/lanl_final_p1_hashes.txt`, 135 files (`lanl_final_a.json`,
  44 A day files, 44 D day files, 44 D1 score arrays, the checkpoint and
  `p1.json`), commit 2707f9a. All 135 were re-verified unchanged after the
  dev checks.

**Fix (exactly LA3.3).** In `load_split`, pairs whose row is outside the
filter are dropped (`eval/lanl_d_metrics.py:79-85`). The row was already
outside D's population, since `y` covers filtered rows only. An event with no
matched row inside the filter therefore cannot be caught, but it stays in the
split's event and user denominators, so it counts as missed in the
all-red-team lines. No other behaviour changes.

**Review of the D path** (assertions or assumptions that held on dev but that
LA3 might permit to fail on the test):

| # | where | condition | status |
|---|---|---|---|
| 1 | `eval/lanl_d_metrics.py:80` (old) | positive row outside the filter | LA3.3 specifies it; fixed as above |
| 2 | `eval/lanl_d_metrics.py:274` | a pair row is not a positive | holds by construction: `y` and the pairs come from the same `label_day` merge (`eval/lanl_la3.py:125-130`, `eval/lanl_final.py` `run()`); not data-dependent |
| 3 | `eval/lanl_d_metrics.py:277` | a positive row has no red-team event | holds by construction, as #2 |
| 4 | `eval/lanl_d_metrics.py:131-132` | pos strictly increasing; day non-decreasing | holds by construction in `load_split` |
| 5 | `eval/lanl_d_metrics.py:133` | NaN scores | not a test condition LA3 permits. D1 features are finite (failure-rate denominator >= 1, `eval/lanl_d.py:141`); D2 and D3 are counts. No change |
| 6 | `eval/lanl_d_metrics.py:179`, `eval/lanl_la3.py:119` | days with no positives or no red-team events | handled: zero counts. LA3.6 daily top-k selects rows on such days with none caught. No change |
| 7 | `eval/lanl_d_metrics.py:262-277` | unmatched test events | handled as LA3.1 specifies: in the split's events and users, with no pair, so missed. No change |
| 8 | after the fix | users whose events are all outside the filter | handled as LA3.3 and LA3.6 specify: counted in the all-red-team user denominator, never caught; not in the in-population `users`. Covered by the fix |
| 9 | `eval/lanl_final.py:172-174` | LA3.8 bounds need intervals | the test has 51 distinct red-team users (L0), so the all-users block uses bootstrap mode. No change |
| 10 | `eval/lanl_d_metrics.py:176-177, 197, 204, 222, 248` | **a scope (all users, new users, returning users) with zero positives in D's filtered population** (possible on the test: all of a stratum's events unmatched or outside the filter, or a stratum with no users) | **not specified by LA3/LA4.** The code does not crash (dev check below): ROC-AUC and PR-AUC become `None`; lift = 0/0 = NaN (written as `NaN`); with >= 20 users in the scope the bootstrap is skipped and the mode is "exact counts", although LA2.6/LA3.7 call for a bootstrap interval with >= 20 users. **Stopped here.** |

Zero positives cannot differ by scorer: within a scope, every scorer has the
same positives.

**Dev checks** (FINAL_EVAL unset):
- (a) The full split val_b dry run with the fix reproduces L2 exactly:
  `results/lanl_final_dryrun_check.json`, A, D and sklearn first differences
  `null`, arrays for days 12-13 equal, `reproduces_L2_exactly: true` (741.5 s).
- (b) Synthetic check (`--check-outside-filter`,
  `results/lanl_final_outside_filter_check.json`). On a copy of val_b, one
  positive row is moved outside the filter: day 12, day row 5,386,281,
  event 338, the first positive whose event matches only that row. It is
  removed from that day's filtered arrays and its pair is kept, as process 1
  writes such a row on the test.
  - The fixed D metrics equal, field by field, a reference copy where the
    pair is also removed (the event unmatched for D): first difference
    `null`.
  - Against L2's val_b: filtered rows and positives are 1 lower; red-team
    event and user counts, and every all-red-team denominator, are unchanged.
  - Event 338 was caught at k = 10,000 by D1 and D2 in L2. In the copy it
    counts as missed: D1 89 → 88, D2 108 → 107; D3 unchanged at 52.
  - A population with zero positives evaluates without error: AUC `None`,
    top-1000 lift `nan`, mode "exact counts" (row 10).

**Row 10 resolved by LA5 (no code change).** Row 10's handling was not
specified, so the work stopped before process 2 and reported. The approved
resolution was a reporting rule, not code:
- **LA5** (`eval/PROTOCOL_LANL.md`), committed alone as **1623ecd**. It was
  written before any D test output existed: the work directory then held
  only process 1's files.
- **The rule:** a zero-positive scope is reported as "undefined (0 positives
  in the filtered population)", with exact counts and no interval. If the
  all-users scope has zero positives, every LA3.8 verdict is "not
  evaluable". The saved JSON stays as produced.
- **On the test it does not apply.** Every scope has positives: all users
  103, new users 30, returning users 73.

**Continuation run.**
- **Hashes:** all 135 process 1 output hashes were re-verified unchanged
  immediately before the continuation.
- **Run:** process 2 ran for D1, D2 and D3, one fresh process each, with the
  bar re-checked before each, under the new run ID `L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation`. It was recorded
  as a continuation of `L3-20261015T034342-14240`.
- **Command:** `FINAL_EVAL=1 python -m eval.lanl_final --skip-p1 --resume
  --run-id <ID>`. With `--skip-p1`, process 1 is not run, so `--resume` has
  exactly one effect: it skips the assert in `orchestrate` that the run ID
  equals process 1's. That assert would otherwise block any new run ID
  without a code change.
- **Recorded as:** deviation, code fix after first ALLOWED line. It is not
  the infrastructure recovery, which remains unused.
- **What process 1 contributed:** process 2 read only process 1's saved D
  arrays, plus the red-team file through the guarded loader. No test output
  was read before the fix.

## 3. Run IDs and access-log lines

| run ID | role |
|---|---|
| `L3-20261015T034342-14240` | the evaluation run: process 1 (pass 1 days 0-57 + A metrics) completed; process 2 D1 stopped on the assertion (section 1) |
| `L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation` | continuation after the deviation (section 2): process 2 D1, D2, D3 |

`results/lanl_test_access.log` after the run (8 lines; the CONVERT line, then
7 ALLOWED lines, every one carrying one of the two run IDs above):

```
2026-10-14T16:01:09	CONVERT	no statistics	...lanl_convert.py
2026-10-15T03:43:45	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	--p1 (red-team read)
2026-10-15T03:55:49	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	--p1 (test days 14-57)
2026-10-15T04:50:59	ALLOWED	pid=15816	run_id=L3-20261015T034342-14240	--p1 (test days, reopened for the A metrics)
2026-10-15T04:53:15	ALLOWED	pid=7756	run_id=L3-20261015T034342-14240	--p2 D1 (red-team read; failed on the assertion)
2026-10-15T06:45:20	ALLOWED	pid=22432	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	--p2 D1
2026-10-15T06:45:42	ALLOWED	pid=17144	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	--p2 D2
2026-10-15T06:45:58	ALLOWED	pid=20124	run_id=L3C-20261015T064518-cont-of-L3-20261015T034342-14240-deviation	--p2 D3
```

(Full argv in the log file.)

Bar checks (`results/lanl_final_bar_checks.json`): every check passed. Each
check's limit is 80% of free physical RAM, which was below 80% of free commit
every time.

| process | run ID | projected peak | 80% free physical at check | measured peak private |
|---|---|---|---|---|
| p1 | first | 15,695,591,501 | 17,756,251,750 | 13,166,358,528 |
| p2_D1 (failed) | first | 10,790,941,956 | 17,981,217,178 | n/a |
| p2_D1 | continuation | 10,790,941,956 | 18,046,763,008 | 7,360,348,160 |
| p2_D2 | continuation | 10,914,785,865 | 18,061,806,797 | 7,470,915,584 |
| p2_D3 | continuation | 10,785,750,708 | 18,087,647,642 | 7,441,154,048 |

Process 1 took 4,171.1 s: A twin 3,126.0, D features 418.2, D1 scoring 246.0,
A metrics 134.8, checkpoints 97.3 and reads 52.7. Process 2 took 21.7 s,
15.5 s and 17.0 s. LA4.7 applies: these runtimes are not for the paper.

## 4. Gates after the run

| check | after |
|---|---|
| `python -m eval.freeze --verify` | freeze MATCHES |
| `python -m eval.lock_test --verify` | test lock MATCHES |
| `python -m eval.lanl_lock --verify` | LANL test lock MATCHES |
| D1 model SHA-256 (`lanl_final_run.json`) | `48bf2436…cfb3`, equals L2 |
| process 1 outputs vs `results/lanl_final_p1_hashes.txt` | 135 / 135 unchanged before the continuation |

## 5. Test label facts (`lanl_final_run.json` `labels`; `lanl_final_d.json`)

| fact | value |
|---|---|
| red-team events (test) | 121 |
| distinct red-team users | 51 |
| matched events (LA3.1) | 121 |
| unmatched events | 0 |
| positive auth rows (all rows) | 104 |
| positive rows in D's filtered population | 103 |
| **positive rows outside the LA3.3 filter** | **1** |
| events passing LA3.3 (at least one matched row in the filter) | 121 |
| **red-team events outside the filter** | **0** |
| users passing LA3.3 | 51 |
| D filtered population (rows) | 110,018,263 |
| step-up incidents (source computer, day) over 44 test days | 6,506 (at the 200/day cap on 30 days, 0 on 9 days) |

Positive rows are fewer than events (LA4.4): a duplicated red-team line
matches the same auth row. The one positive row outside the filter belongs to
an event that also matches a row inside the filter. So the deviation's fix
dropped one positive row and changed no event's status: no event counts as
missed because of the filter.

## 6. A on test (LA3.4, LA3.6, LA3.7; `results/lanl_final_a.json`)

51 users, so bootstrap intervals (95%, 1,000 resamples over red-team users,
seed 42). Events and users caught are out of all 121 test red-team events and
51 users. Precision counts alerted auth rows (LA4.4).

A detectors (test; all 121 events / 51 users):

| detector | alerts | positive alerts | precision | events caught | users caught |
|---|---|---|---|---|---|
| Brute Force Attack | 64535 | 0 | 0.0 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| Slow Brute Force | 401458 | 1 | 2.49e-06 [0.0, 7.47e-06] | 4 / 121 [0.0, 0.113] | 1 / 51 [0.0, 0.059] |
| Credential Stuffing | 238749 | 1 | 4.19e-06 [0.0, 1.26e-05] | 4 / 121 [0.0, 0.113] | 1 / 51 [0.0, 0.059] |
| Invalid Account Spraying | 0 | 0 | n/a | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| Distributed Brute Force | 482824 | 0 | 0.0 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| Success After Failures | 56728702 | 58 | 1.02e-06 [9.17e-07, 1.15e-06] | 76 / 121 [0.504, 0.771] | 50 / 51 [0.941, 1.000] |
| Multiple IP Login | 126358 | 5 | 3.96e-05 [7.91e-06, 7.12e-05] | 5 / 121 [0.010, 0.083] | 5 / 51 [0.020, 0.176] |
| Suspicious Login Time | 9757684 | 0 | 0.0 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| any rule alert | 66620795 | 59 | 8.86e-07 [7.81e-07, 9.91e-07] | 76 / 121 [0.504, 0.771] | 50 / 51 [0.941, 1.000] |

A tiers:

| tier | alerted events at tier | positive alerts at tier | precision | red-team events caught | users caught | incidents (final tier) | incidents with a positive |
|---|---|---|---|---|---|---|---|
| block | 0 | 0 | n/a | 0 / 121 | 0 / 51 | 0 | 0 |
| step_up | 21445396 | 0 | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 | 6506 | 0 |
| queue | 12921468 | 0 | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 | 15646 | 0 |
| log | 32253931 | 59 | 1.83e-06 [1.61e-06, 2.05e-06] | 76 / 121 | 50 / 51 | 409960 | 9 |

Red-team events from a challenged source: 0 / 121 (users 0 / 51). Legitimate users challenged per day (mean over 44 test days): 16475.55; daily: 20656, 20677, 11664, 0, 12551, 12510, 21996, 21486, 21161, 12043, 0, 12716, 21930, 12811, 0, 20332, 19064, 13557, 13666, 22871, 13204, 0, 20973, 19070, 12886, 12885, 23474, 23294, 23367, 23336, 18419, 13529, 13357, 13708, 23233, 23117, 23063, 18937, 10513, 12025, 22540, 22901, 22789, 22613.

A LA1.5 user strata (events caught / users caught):

| stratum | users / events | mode | any rule | Success After Failures | Multiple IP Login | Slow Brute Force | Credential Stuffing | step_up | queue | challenged |
|---|---|---|---|---|---|---|---|---|---|---|
| new_users | 18 / 32 | exact counts | 21 / 18 | 21 / 18 | 5 / 5 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| returning_users | 33 / 89 | bootstrap | 55 / 32 | 55 / 32 | 0 / 0 | 4 / 1 | 4 / 1 | 0 / 0 | 0 / 0 | 0 / 0 |

The strata use LA1.5: a user is "returning" if the user appears in a
red-team event before the test starts. The new-user stratum has 18 users, so
its counts are exact (LA2.6).

## 7. D on test (LA3.5-LA3.7; `results/lanl_final_d.json`)

- **Intervals:** 95% bootstrap over red-team users (1,000 resamples, seed
  42) where a scope has 20 or more users; exact counts and point AUCs
  otherwise (LA2.6, LA4.5).
- **Daily top-k:** ranked within each of the 44 test days. Precision is
  caught rows / selected rows over the test days; lift is precision / the
  scope's filtered base rate.
- **"In population" columns:** only positives inside D's filtered
  population. The all-red-team columns count every test red-team event and
  user, with unmatched and filter-excluded events as missed (here there are
  none of either).
- **LA5:** every scope has positives, so LA5 does not apply and no value
  needed translating.

D population (test): 110018263 filtered rows, 103 positive rows; 121 red-team events, 51 users.


D, scope all (51 users, 121 events; mode bootstrap):

| scorer | positives / population | base rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|
| D1 | 103 / 110018263 | 9.36e-07 | 0.9232 [0.8227, 0.9836] | 1.8e-05 [1.17e-05, 3.4e-05] |
| D2 | 103 / 110018263 | 9.36e-07 | 0.8695 [0.8275, 0.9144] | 0.00042 [0.000127, 0.00112] |
| D3 | 103 / 110018263 | 9.36e-07 | 0.8630 [0.8270, 0.8912] | 5.45e-06 [3.42e-06, 8.23e-06] |

| scorer | k | rows caught / positives | precision | lift | events caught (in population) | users caught (in population) | all-red-team events | all-red-team users |
|---|---|---|---|---|---|---|---|---|
| D1 | 100 | 0 / 103 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| D1 | 1,000 | 1 / 103 | 2.27e-05 [0.0, 6.82e-05] | 24.3 [0.0, 75.1] | 1 / 121 | 1 / 51 [0.0, 0.059] | 1 / 121 [0.0, 0.026] | 1 / 51 [0.0, 0.059] |
| D1 | 10,000 | 10 / 103 | 2.27e-05 [0.0, 6.14e-05] | 24.3 [0.0, 64.7] | 10 / 121 | 3 / 51 [0.0, 0.137] | 10 / 121 [0.0, 0.230] | 3 / 51 [0.0, 0.137] |
| D2 | 100 | 0 / 103 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| D2 | 1,000 | 2 / 103 | 4.55e-05 [0.0, 0.000114] | 48.6 [0.0, 135.9] | 12 / 121 | 2 / 51 [0.0, 0.098] | 12 / 121 [0.0, 0.254] | 2 / 51 [0.0, 0.098] |
| D2 | 10,000 | 24 / 103 | 5.45e-05 [3.18e-05, 8.18e-05] | 58.3 [34.9, 89.1] | 38 / 121 | 18 / 51 [0.235, 0.490] | 38 / 121 [0.172, 0.466] | 18 / 51 [0.235, 0.490] |
| D3 | 100 | 0 / 103 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| D3 | 1,000 | 0 / 103 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 121 | 0 / 51 [0.0, 0.0] | 0 / 121 [0.0, 0.0] | 0 / 51 [0.0, 0.0] |
| D3 | 10,000 | 1 / 103 | 2.27e-06 [0.0, 6.82e-06] | 2.4 [0.0, 6.8] | 1 / 121 | 1 / 51 [0.0, 0.059] | 1 / 121 [0.0, 0.024] | 1 / 51 [0.0, 0.059] |

D, scope new_users (18 users, 32 events; mode exact counts):

| scorer | positives / population | base rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|
| D1 | 30 / 110018190 | 2.73e-07 | 0.9771 | 5.58e-06 |
| D2 | 30 / 110018190 | 2.73e-07 | 0.9909 | 0.000982 |
| D3 | 30 / 110018190 | 2.73e-07 | 0.9472 | 3.08e-06 |

| scorer | k | rows caught / positives | precision | lift | events caught (in population) | users caught (in population) | all-red-team events | all-red-team users |
|---|---|---|---|---|---|---|---|---|
| D1 | 100 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D1 | 1,000 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D1 | 10,000 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D2 | 100 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D2 | 1,000 | 1 / 30 | 2.27e-05 | 83.3 | 3 / 32 | 1 / 18 | 3 / 32 | 1 / 18 |
| D2 | 10,000 | 18 / 30 | 4.09e-05 | 150.0 | 20 / 32 | 12 / 18 | 20 / 32 | 12 / 18 |
| D3 | 100 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D3 | 1,000 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |
| D3 | 10,000 | 0 / 30 | 0.0 | 0.0 | 0 / 32 | 0 / 18 | 0 / 32 | 0 / 18 |

D, scope returning_users (33 users, 89 events; mode bootstrap):

| scorer | positives / population | base rate | ROC-AUC | PR-AUC |
|---|---|---|---|---|
| D1 | 73 / 110018233 | 6.64e-07 | 0.9011 [0.7751, 0.9857] | 1.33e-05 [6.98e-06, 3.23e-05] |
| D2 | 73 / 110018233 | 6.64e-07 | 0.8196 [0.7768, 0.8726] | 4.59e-05 [4.44e-06, 0.000276] |
| D3 | 73 / 110018233 | 6.64e-07 | 0.8284 [0.7743, 0.8656] | 2.96e-06 [1.32e-06, 5.48e-06] |

| scorer | k | rows caught / positives | precision | lift | events caught (in population) | users caught (in population) | all-red-team events | all-red-team users |
|---|---|---|---|---|---|---|---|---|
| D1 | 100 | 0 / 73 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 89 | 0 / 33 [0.0, 0.0] | 0 / 89 [0.0, 0.0] | 0 / 33 [0.0, 0.0] |
| D1 | 1,000 | 1 / 73 | 2.27e-05 [0.0, 6.82e-05] | 34.3 [0.0, 98.7] | 1 / 89 | 1 / 33 [0.0, 0.091] | 1 / 89 [0.0, 0.034] | 1 / 33 [0.0, 0.091] |
| D1 | 10,000 | 10 / 73 | 2.27e-05 [0.0, 6.14e-05] | 34.3 [0.0, 89.3] | 10 / 89 | 3 / 33 [0.0, 0.212] | 10 / 89 [0.0, 0.300] | 3 / 33 [0.0, 0.212] |
| D2 | 100 | 0 / 73 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 89 | 0 / 33 [0.0, 0.0] | 0 / 89 [0.0, 0.0] | 0 / 33 [0.0, 0.0] |
| D2 | 1,000 | 1 / 73 | 2.27e-05 [0.0, 6.82e-05] | 34.3 [0.0, 134.0] | 9 / 89 | 1 / 33 [0.0, 0.091] | 9 / 89 [0.0, 0.300] | 1 / 33 [0.0, 0.091] |
| D2 | 10,000 | 6 / 73 | 1.36e-05 [4.55e-06, 2.5e-05] | 20.6 [8.9, 32.4] | 18 / 89 | 6 / 33 [0.061, 0.333] | 18 / 89 [0.042, 0.386] | 6 / 33 [0.061, 0.333] |
| D3 | 100 | 0 / 73 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 89 | 0 / 33 [0.0, 0.0] | 0 / 89 [0.0, 0.0] | 0 / 33 [0.0, 0.0] |
| D3 | 1,000 | 0 / 73 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0 / 89 | 0 / 33 [0.0, 0.0] | 0 / 89 [0.0, 0.0] | 0 / 33 [0.0, 0.0] |
| D3 | 10,000 | 1 / 73 | 2.27e-06 [0.0, 6.82e-06] | 3.4 [0.0, 8.8] | 1 / 89 | 1 / 33 [0.0, 0.091] | 1 / 89 [0.0, 0.031] | 1 / 33 [0.0, 0.091] |

**sklearn cross-check.** The cross-check
(`check_strict_ranking_vs_sklearn`) was skipped on the test for all three
scorers. The population of 110,018,263 rows is above the 20,000,000-row
limit, and the check needs full-length arrays. The dev equality checks stand
in for it:
- lean D metrics vs L2 on val_a and val_b, field by field, sklearn checks
  included (`lanl_final_lean_check.json`);
- lean positive ranks equal to full ranks (same file);
- the split val_b dry run, rerun after the fix (`lanl_final_dryrun_check.json`);
- the synthetic outside-filter check (`lanl_final_outside_filter_check.json`).

## 8. LA3.8 verdict (test; all-users scope)

A scorer works if all three hold: (1) the ROC-AUC 95% lower bound is above
0.50; (2) at k = 1,000, the lift lower bound is at least 10; (3) at
k = 1,000, it catches at least 20% of the test's 51 red-team users.

| scorer | (1) ROC-AUC lower bound | (2) k = 1,000 lift lower bound | (3) k = 1,000 users caught | verdict |
|---|---|---|---|---|
| D1 | 0.8227 > 0.50: met | 0.0 < 10: not met | 1 / 51 = 1.96% < 20%: not met | **does not work** |
| D2 | 0.8275 > 0.50: met | 0.0 < 10: not met | 2 / 51 = 3.92% < 20%: not met | **does not work** |
| D3 | 0.8270 > 0.50: met | 0.0 < 10: not met | 0 / 51 = 0.0% < 20%: not met | **does not work** |

**D1 does not work. D2 does not work. D3 does not work.** All three are
reported; none is selected over another.

## 9. Anything unexpected

- **Process 2 failed on its assertion** (section 1). One positive test row
  lies outside the LA3.3 filter, a case that never occurred on dev and that
  the L2 loader asserted against. It was fixed as LA3.3 specifies, under the
  one approved deviation (section 2). It changed no event's status: 0 events
  outside the filter.
- **The review found an unspecified case.** A zero-positive scope had no
  specified handling; LA5 now specifies it. It did not occur on the test.
- **Continuation flag.** The continuation needed `--resume` alongside
  `--skip-p1` to use a new run ID without a code change (section 2).
- **Memory came in under projection.** Process 2's measured peaks
  (7.36-7.47 GB) were about 31-32% under the ratio projection (10.79-10.91
  GB), and process 1's peak (13.17 GB) was 16% under its projection
  (15.70 GB).
- **Step-up cap.** The cap of 200 incidents per day was reached on 30 of the
  44 test days, and legitimate users challenged averaged 16,475.5 per day
  (LA4.9).
