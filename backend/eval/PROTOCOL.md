# Evaluation protocol (Phase 2)

Pre-declared on 2026-10-13, before any model was trained or any replay was
scored under it. Do not change it after looking at results. If a change
becomes necessary, add a dated entry under "Amendments" that says what
changed, why, and what had already been seen.

## Data

- Source: the RBA CSV at `RBA_DATASET_PATH` (31,269,264 rows, 2020-02-03 to
  2021-02-28), converted once by `eval/convert_rba.py` into month-partitioned
  Parquet with all 16 columns. The CSV is time-ordered; row order is kept.
- Label: an event is an attack if `Is Attack IP` OR `Is Account Takeover`
  (same definition as Batches 1 to 5). The two flags are also reported
  separately where it matters.
- Event fields for the agents: `ip` = IP Address, `user` = str(User ID),
  `timestamp` = Login Timestamp truncated to whole seconds
  (`%Y-%m-%d %H:%M:%S`, as before), `status` = SUCCESS/FAILED from
  Login Successful, `country` = Country (missing -> "XX"), `device_type` =
  Device Type (missing -> "Unknown"). Ties keep CSV order.

## Splits (fixed in `eval/datasets.py`)

| Split | Rows | Use |
|---|---|---|
| `dev_train` | 2020-02-03 00:00 <= t < 2020-03-30 00:00 (8 weeks; Feb 1-2 have no rows) | Model fitting, frequency maps |
| `dev_val` | 2020-03-30 00:00 <= t < 2020-05-01 00:00 (4 weeks 4 days) | Contamination choice, all Phase 2-5 comparisons |
| `dev_val_cold` | `dev_val` rows whose User ID has no row of any kind in `dev_train` | Cold-start check |
| `test` | 2020-05-01 00:00 <= t < 2020-06-01 00:00, all rows | Locked; final evaluation only |
| later months | June 2020 onward | Not used. Reserved for an optional drift study, to be decided later |

- `dev_train` and `dev_val` keep the natural attack prevalence. `dev_val` and
  `test` are never resampled, filtered by label, or rebalanced.
- `dev_val_cold` is a subset of `dev_val` rows, not a separate replay: its
  metrics are computed on those rows from the same full replay (below), so
  IP-level rule state is unaffected by the subsetting.

## Test lock

- The test month is written to its own file,
  `data/rba_locked/test_2020-05.parquet`, outside the month-partitioned
  directory. Its row count and SHA-256 are in `results/test_lock.txt`.
- `eval.datasets.load("test")` raises `TestSetLocked` unless the environment
  variable `FINAL_EVAL` is exactly `1`, and appends every call, refused or
  allowed, to `results/test_access.log` (`tests/test_datasets.py`).
- Until the final evaluation, nothing may compute label statistics, model
  scores or any metric on test rows. The only allowed operations are
  writing them to the separate file, counting rows and hashing the file.
- The final evaluation runs once, with every choice (features, rules,
  thresholds, policy, contamination) frozen on `dev_val` beforehand.

## Model fitting

- The Isolation Forest is fitted on the non-attack events of `dev_train`
  only. Labels are used for nothing else during fitting. The frequency maps
  and known-IP/country sets come from the same rows.
- If `dev_train` is too large for memory, users (not events) are subsampled
  for fitting only, and the fraction is reported. Replays always use
  complete streams.
- The Phase 2 baseline keeps the current design: the same 10 features
  (`ml/train_from_dataset.py: extract_features_freq`), 200 trees,
  `max_samples=100000`, `max_features=1.0`, StandardScaler.
- Contamination (amended, see Amendment 1): the eleven-point grid of
  Batch 3.7 (0.02, 0.05, 0.10, ..., 0.50), choosing the value with the
  highest Isolation Forest event-level F1 (`predict == -1`) on `dev_val`,
  which is the rule that selected the deployed 0.4
  (`ml/train_from_dataset_v3.py`, `_v3_extend.py`). Contamination moves only
  the threshold, not the trees, so for each grid value the threshold is the
  `100*c` percentile of the training `score_samples` (what scikit-learn sets
  as `offset_` for `contamination=c`), evaluated vectorised at seed 42. The
  chosen value is then used for seeds 42, 43 and 44, and the hybrid is
  replayed only at that value. Because contamination is chosen on `dev_val` and the
  baseline is reported on `dev_val`, the baseline is slightly optimistic;
  later phases are compared with it on the same footing.

## Replay

- Per-entity state (rule counters, blocks, the runtime `failed_rate`
  counters) is built causally, without labels, from every event before the
  scored event. To score `dev_val` the harness replays the whole development
  stream (`dev_train` then `dev_val`) through the real agents
  (`eval/harness.py`, PrecomputedScorer for the ML step), and metrics are
  computed on `dev_val` events only. The test replay will likewise run over
  the development months and then May.
- Configurations reported: rules only, Isolation Forest only, hybrid.
  "Isolation Forest only" scores every `dev_val` event with the model, with
  `failed_rate` counted per IP over every prior development event; it flags
  `decision < ML_ALERT_MARGIN`. Its simulated response block is the first
  event with "High" confidence (the analysis agent maps that to HIGH).

## Metrics (on `dev_val`, and on `dev_val_cold` rows)

- Isolation Forest scores: ROC-AUC, PR-AUC (average precision), TPR at 1%
  and 5% FPR (largest TPR whose FPR does not exceed the budget).
- Rules only and hybrid are binary: TPR at a budget is the detector's TPR if
  its FPR is within the budget, and "not reached" otherwise.
- Campaign coverage: share of attacking IPs (IPs with an attack event in the
  split) with at least one alert on an attack event. Benign IPs flagged: IPs
  with only non-attack events in the split that got at least one alert.
- Event recall and FPR; per alert type (type, severity, confidence) the
  alert counts and precision.
- Response cost (`harness.summarize`): simulated blocks on HIGH alerts, benign
  IPs blocked, benign events and successes after a block, legitimate users
  affected. Blocks made during `dev_train` still apply in `dev_val` (that is
  the current, causal behaviour, audit F02); costs are counted on `dev_val`
  events only.
- Seeds 42, 43, 44 for every ML configuration: mean and per-seed values.

- Reporting addition (not a protocol change): every `dev_val` metric is
  also reported without the events of user ID `-4324475583306591935`, the
  apparent placeholder for unknown usernames (37% of development rows; see
  the Phase 2 data report). The replay itself always includes it. For that
  ID the baseline also reports its `dev_val` event count, attack share and
  alerts by type, and how many Credential Stuffing alerts involve it.

## Amendments

1. 2026-10-13, before the baseline run. The contamination rule changed from
   "highest hybrid event F1 (11 hybrid replays)" to "highest Isolation
   Forest event-level F1, vectorised", at the project owner's instruction,
   to match the rule that originally chose the deployed value. Seen before
   the change: the dev-only data audit and timing probes of the replay. No
   model score or metric on any split had been computed under this
   protocol (a smoke test on the first 300,000 February rows, with a
   stand-in split, checked only that the code runs).
