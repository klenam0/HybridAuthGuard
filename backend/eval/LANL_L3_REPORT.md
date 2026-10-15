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
