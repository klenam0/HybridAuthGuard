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

2. 2026-10-13, Phase 3, before any v3 metric. Selection of the v3 rule
   engine's parameters (`agents/rules_v3.py`, `RULES_MODE = "v3"`). Seen
   before this amendment: the Phase 2 baseline, the unit tests of the
   engine (synthetic events only) and the legacy-mode gate. No v3 detector
   had been run on any RBA row.

   **Criterion.** For each detector, choose the parameter setting on
   `dev_val` that maximises *attacking IPs flagged* subject to *alert
   precision* >= 2 x the `dev_val` base rate (2 x 237,620 / 2,337,227 =
   0.2033, i.e. >= 20.3%). If no setting meets it, the detector is
   **advisory only** (it alerts, it never blocks); its reported setting is
   the one with the highest precision, and that precision is reported.
   Settings with fewer than 30 `dev_val` alerts are not eligible (either
   way). Ties: more attacking IPs flagged, then higher precision, then
   fewer alerts, then the earlier setting in grid order.

   **Definitions.** An *alert* is what the engine emits after
   de-duplication: one per (detector, key) per cooldown, where the key is
   the IP, or (account, IP) for Distributed Brute Force, Success After
   Failures and Multiple IP Login. *Alert precision* = share of a
   detector's alerts on `dev_val` events that are on attack events.
   *Attacking IPs flagged* = `dev_val` attacking IPs with at least one alert
   of that detector on one of their `dev_val` attack events. Both are on all
   of `dev_val`, placeholder included. State is built causally over the
   whole development stream (dev_train then dev_val), as in the Phase 2
   replay; replay events carry the CSV `index` as `event_id`, so no RBA row
   is treated as a duplicate delivery.

   **Grids** (seconds unless stated):

   | Detector | Parameter | Values |
   |---|---|---|
   | Brute Force | window | 60, 300, 600, 1800, 3600 |
   | | min failures | 3, 5, 10, 20, 50 |
   | Slow Brute Force (with the chosen Brute Force setting) | window | 3600, 10800, 21600, 43200, 86400 |
   | | min failures | 3, 4, 6, 10, 20 |
   | | min spread | 300, 900, 1800 |
   | Credential Stuffing | window | 300, 1800, 3600, 21600, 86400 |
   | | min failing accounts | 2, 3, 5, 10, 20 |
   | Invalid Account Spraying | window | 300, 1800, 3600, 21600, 86400 |
   | | min attempts | 2, 3, 5, 10, 20 |
   | Distributed Brute Force | window | 300, 1800, 3600, 21600, 86400 |
   | | min distinct IPs | 2, 3, 5, 10, 20 |
   | Success After Failures | window | 300, 1800, 3600, 21600, 86400 |
   | | min failures (account or IP) | 1, 2, 3, 5, 10 |
   | Multiple IP Login (window fixed at 120) | exemption | none, known IP, same /24 or /64, same ASN, all three |

   Brute Force is chosen first, because Slow Brute Force only fires below
   the Brute Force count. Suspicious Login Time is not tuned (per-user hour
   profiles are Phase 4); it is only reported.

   **Fixed, not tuned:** alert cooldown 3600 s (Suspicious Login Time keeps
   600 s per IP), duplicate-delivery window 300 s, known-IP memory 30 days,
   ML `failed_rate` window 30 days (day buckets, every event), block TTL
   3600 s, `UNKNOWN_ACCOUNT_IDS = ["-4324475583306591935"]`.

   **Method.** One pass records per-event window statistics for every grid
   window; thresholds and de-duplication are then applied offline. The real
   v3 agent is replayed once at the chosen settings over the development
   stream, and its matches and alerts per detector must equal the offline
   computation exactly, or the selection is void.

   **Comparisons** (reported, not used for selection): rules-only legacy
   (Phase 2 figures) vs rules-only v3; hybrid v3 (chosen rules + the Phase 2
   Isolation Forest design refitted on dev_train at seed 42, contamination
   0.3, scored on every event with the v3 `failed_rate`) vs the Phase 2
   hybrid at seed 42; on all `dev_val`, without the placeholder, and on
   `dev_val_cold`. Interim response policy: block, TTL 3600 s, only on
   alerts of detectors that met the criterion (the ML step is checked
   against the same criterion); everything else alerts only.

3. 2026-10-13, Phase 3b, before any metric on the halves below. Corrects
   the Phase 3 selection protocol, which chose and reported on the same
   rows. Seen before this amendment: every Phase 3 result (amendment 2
   selection and comparisons), all computed on the whole of `dev_val`, so
   on both halves defined here. The val_b confirmation below is therefore
   independent of the parameter *choice* but not of the decisions that
   shaped this amendment (the grid extensions follow from where Phase 3's
   whole-`dev_val` choices landed). No metric had been computed on either
   half on its own.

   **Split of `dev_val` in time.** `val_a` = 2020-03-30 00:00 <= t <
   2020-04-15 00:00 (tuning); `val_b` = 2020-04-15 00:00 <= t < 2020-05-01
   00:00 (confirmation); 16 calendar days each. State is always built
   causally from the start of the development stream (2020-02-03), through
   `dev_train`, `val_a` and `val_b`; the halves only select which events are
   scored. Parameters are chosen on `val_a` only. `val_b` is evaluated once
   per configuration, after the choice is written to disk, and is never
   used for choosing or re-tuning. Phase 4 uses the same split.
   `dev_val_cold` keeps its definition (User ID with no row in `dev_train`),
   restricted to each half.

   **Alert-tier criterion** (replaces amendment 2's criterion; units,
   de-duplication, keys and "attacking IPs flagged" are as in amendment 2,
   measured on `val_a`). For each detector, choose the setting that
   maximises attacking IPs flagged on `val_a`, subject to (i) >= 30 alerts
   on `val_a` and (ii) the *lower bound* of a 95% bootstrap interval of
   alert precision on `val_a` >= 2 x the `val_a` base rate. Ties: higher
   lower bound, then fewer alerts, then the earlier setting in grid order.
   If no setting qualifies, the detector *fails the criterion* and is
   reported at its eligible (>= 30 alerts) setting with the highest lower
   bound.

   **Bootstrap.** Clustered by source IP: the units are the IPs with at
   least one of the detector's alerts on the half's events; each resample
   draws that many IPs with replacement and computes precision as (attack
   alerts) / (alerts) summed over the drawn IPs. 1,000 resamples; 95%
   percentile interval (2.5th and 97.5th percentiles). Random numbers:
   `numpy.random.default_rng(42)`, re-created for every (detector, setting,
   half), resamples drawn in a fixed order.

   **Confirmation on `val_b`.** For the chosen setting (and the ML step)
   the same alert precision, interval, attacking and benign IPs flagged are
   computed on `val_b`. The detector *holds on val_b* if it has >= 30
   alerts there and its lower bound is >= 2 x the `val_b` base rate.
   Failing on `val_b` is reported; it does not trigger re-tuning.

   **No blocking in this phase.** Every detector, the ML step included,
   is alert-only; the response and blocking policy is deferred to Phase 5.
   The amendment 2 interim block policy is removed from the evaluation
   (`V3_BLOCK_DETECTORS` is empty; the TTL block-list code path stays).
   The criterion decides each detector's parameters and whether it is in
   the alert tier; it no longer decides blocking.

   **Grids.** Extended only where Phase 3 chose an edge of that dimension:
   windows add 172800 and 604800 where 86400 was chosen; counts add 1 where
   the chosen count was the grid minimum 2. Brute Force chose the lower
   edges (60 s, 3); the extension rule does not cover a lower edge, so its
   grid is unchanged. Final grids (seconds):

   | Detector | Parameter | Values |
   |---|---|---|
   | Brute Force | window | 60, 300, 600, 1800, 3600 |
   | | min failures | 3, 5, 10, 20, 50 |
   | Slow Brute Force (with the chosen Brute Force setting) | window | 3600, 10800, 21600, 43200, 86400, 172800, 604800 |
   | | min failures | 3, 4, 6, 10, 20 |
   | | min spread | 300, 900, 1800 |
   | Credential Stuffing | window | 300, 1800, 3600, 21600, 86400, 172800, 604800 |
   | | min failing accounts | 1, 2, 3, 5, 10, 20 |
   | Invalid Account Spraying | window | 300, 1800, 3600, 21600, 86400, 172800, 604800 |
   | | min attempts | 2, 3, 5, 10, 20 |
   | Distributed Brute Force | window | 300, 1800, 3600, 21600, 86400, 172800, 604800 |
   | | min distinct IPs | 1, 2, 3, 5, 10, 20 |
   | Success After Failures | window | 300, 1800, 3600, 21600, 86400, 172800, 604800 |
   | | min failures (account or IP) | 1, 2, 3, 5, 10 |
   | Multiple IP Login (window fixed at 120) | exemption | none, known IP, same /24 or /64, same ASN, all three |

   289 settings. Suspicious Login Time is still not tuned, only reported.
   Fixed, as in amendment 2: cooldown 3600 s (600 s per IP for Suspicious
   Login Time), duplicate window 300 s, known-IP memory 30 days, ML
   `failed_rate` window 30 days. The ML step is the unchanged Phase 2
   Isolation Forest design at seed 42, contamination 0.3, its alerts
   de-duplicated per IP with a 3600 s cooldown as in Phase 3; it is not
   tuned, only checked against the criterion.

   **Incidents.** Alerts are grouped into incidents per (source IP,
   calendar day, UTC as in the data). An incident is *attack* if any event
   carrying one of its alerts is an attack event. Incident precision = attack
   incidents / incidents. For a subset (all events, without the
   placeholder, cold users), only alerts on events in the subset form
   incidents.

   **Workload on `val_b`** (reported, never used for choosing). Two
   configurations: v3 rules alone (every rule detector at its reported
   setting, including those failing the criterion), and v3 rules + the ML
   step. Reported: alerts/day, incidents/day, incident precision, on all
   `val_b` events, without the placeholder's events, and on cold users.

   **Budget curves.** Each incident gets a score = the highest `val_a`
   alert precision (point estimate, chosen setting) among the detectors
   with an alert in it; ties go to the incident with more distinct
   detectors, remaining ties are broken uniformly at random
   (`numpy.random.default_rng(42)`). Each calendar day the top B incidents
   are taken, for B = 100, 500 and 2,000 incidents/day. Reported per
   budget: incidents taken, incident precision, and attacking IPs caught
   (`val_b` attacking IPs with at least one attack incident taken), also as
   a share of the subset's `val_b` attacking IPs.

   **Gates.** The real v3 agents replayed at the chosen settings must
   reproduce the offline matches and alerts per detector with 0 mismatches
   on `val_a` and on `val_b`, or the selection is void.
