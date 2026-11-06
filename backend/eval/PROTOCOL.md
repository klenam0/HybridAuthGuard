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

4. 2026-10-13, Phase 4, before any Phase 4 metric. ML redesign. Seen
   before this amendment: every Phase 2, 3 and 3b result (including the
   Phase 2 Isolation Forest's val_a and val_b alert precision in amendment
   3's confirmation) and data counts of the development stream (1,509,483
   users, 1,309,101 IPs, 153,387 user-agent strings, RTT missing on 96% of
   rows). No Phase 4 feature, model score or metric had been computed. The
   rule engine is frozen at the amendment 3 settings in `config.py`; no rule
   parameter, grid or severity changes in this phase.

   **Splits.** Fit on `dev_train` (2020-02-03 to 2020-03-29). Choose on
   `val_a` only. `val_b` is computed by a separate `confirm` stage of
   `eval/phase4.py` that reads the choice from disk, once; nothing is
   re-tuned after `val_b`. Feature state (`ml/features_v4.py`) is built
   causally from 2020-02-03 through `dev_train`, `val_a` and `val_b` in time
   order; the halves only select which events are scored.

   **Labels.** No label column (`Is Attack IP`, `Is Account Takeover`) feeds
   any feature or any unsupervised model. Labels are used only for metrics
   and for the supervised reference. Exception, inherited and unchanged:
   the Phase 2 Isolation Forest (candidate 1) was fitted on the non-attack
   rows of `dev_train` under the Phase 2 protocol; it is kept as the
   baseline as it is, and this is stated wherever it is reported.

   **Candidates eligible for deployment** (unsupervised, label-free), in
   this order (the order breaks the last tie):
   1. The Phase 2 Isolation Forest, unchanged: seed 42, contamination 0.3,
      v3 `failed_rate`, cached decisions `phase3_cache/ml_decision_v3.npy`.
      Not refitted. Score = -decision.
   2. Isolation Forest on the Phase 4 features, for each feature set of the
      ablation table: all groups A-E; A-E without one group (5 sets); each
      group alone (5 sets); 11 sets, in that order. Hyperparameters
      `n_estimators` in (100, 300) x `max_samples` in (256, 4096), in that
      order, `max_features` 1.0, no scaling (the forest is invariant to
      monotone per-feature scaling). Fitted on a uniform sample of 1,000,000
      `dev_train` events drawn with `default_rng(seed)`, attacks included
      (label-free). Every event is scored once; score =
      -`decision_function`.
   3. Freeman et al. (2016) per-user risk, label-free variant
      (`ml/features_v4.py`; its docstring lists the simplifications): log
      risk = sum over hierarchy levels of log p(value | population) - log
      p(value | user), IP chain country -> ASN -> /24 (/64) -> IP and UA
      chain browser family -> browser + OS -> UA string, nested.
      p(. | population) is the distribution over all prior events with
      add-one smoothing and one reserved unseen slot per node; p(. | user)
      is the user's causal history smoothed towards p(. | population) with
      strength beta, level by level. A user with no history gets the
      population prior (log risk 0). beta in (0.5, 2, 8), computed in the
      same pass, in that order.
   4. New IP for the user (binary; score = 1 if the user has no prior event
      from this IP).

   **Reference only, never deployable:** `HistGradientBoostingClassifier` on
   groups A-E and on A-C + E (without D), `class_weight="balanced"`, label =
   `Is Attack IP` or `Is Account Takeover`, `random_state` 42. Fitted on the
   first 90% of `dev_train` rows in time order with early stopping on the
   last 10% (`n_iter_no_change` 20, loss, `max_iter` 500). Grid
   `learning_rate` in (0.05, 0.1) x `max_leaf_nodes` in (15, 63); the
   setting with the highest `val_a` event PR-AUC is reported. The labels
   are a per-IP blocklist, so this shows a ceiling, not a deployable
   detector.

   **Thresholds.** For each scored model the alert thresholds are fixed
   before `val_a`, from that model's scores on all `dev_train` events: for q
   in (0.1, 0.5, 1, 2, 5, 10, 20, 30)%, the threshold is the `(1 - q)`
   quantile (`numpy.quantile`, method `inverted_cdf`), and an event alerts
   if its score >= the threshold. For discrete scores (new IP; Freeman for
   users without history) ties at the threshold all alert, so the realised
   share can exceed q; rows with identical alert sets are kept. ML alerts
   are de-duplicated per IP with a 3600 s cooldown, as the ML step in
   amendment 3 (one alert per IP per hour).

   **Primary criterion (incremental value over the frozen rules).** The
   frozen rules are the eight v3 rule detectors at their amendment 3
   settings, including the two that fail its criterion (the "rules"
   workload configuration). Incidents are per (source IP, calendar day), as
   in amendment 3. An *incremental incident* is an incident with at least
   one ML alert and no frozen-rule alert; it is an attack incident if any
   event carrying one of its ML alerts is an attack event. *Attacking IPs in
   incremental incidents* = `val_a` attacking IPs with at least one attack
   incremental incident. Choose the (model, feature set, threshold) that
   maximises attacking IPs in incremental incidents on `val_a`, subject to
   (i) >= 30 incremental incidents on `val_a` and (ii) the lower bound of
   the IP-clustered bootstrap of incremental-incident precision >= 0.2149
   (2 x the `val_a` event base rate, fixed). The bootstrap is amendment 3's
   with the incremental incident as the unit counted: the clusters are the
   IPs with an incremental incident, 1,000 resamples, 95% percentile
   interval, `default_rng(42)` re-created per row. Ties: higher lower bound,
   then fewer ML alerts, then candidate order above (then feature-set,
   hyperparameter and threshold order as listed).

   **Holds on val_b** = >= 30 incremental incidents on `val_b` and lower
   bound >= 0.1915 (2 x the `val_b` base rate); also reported against
   0.2149.

   **Pre-declared fallback.** If no candidate meets the criterion on
   `val_a`, no ML configuration is enabled for alerting in v4: `ML_MODE =
   "v4"` then runs the model but raises no ML alert. The candidate with the
   highest lower bound (among rows with >= 30 incremental incidents; ties as
   above) is reported, confirmed on `val_b` like a chosen one, and passed to
   Phase 5 only as a possible ranking signal.

   **Group D.** Aggregate reputation (prior failure ratio and prior event
   count per ASN and per IP) is closest to how the blocklist label was
   produced. Every headline result is reported with and without D, and the
   chosen configuration is stated as "with D" or "without D".

   **Secondary (reported, not used for choosing):** ML-alone alert precision
   with its interval and the amendment 3 criterion; event ROC-AUC, PR-AUC
   (average precision), TPR at 1% FPR; attacking IPs flagged; benign IPs
   flagged and legitimate users alerted (non-placeholder users with an ML
   alert on a non-attack event); ML-alone incident precision; and on
   `val_b` the budget curves at B = 100, 500, 2,000 with amendment 3's
   budget score, the ML detector being the chosen (or fallback) candidate
   with its `val_a` ML-alone alert precision as its score.

   **Strata** (only events in the stratum form alerts and incidents): all
   events; excluding the placeholder ID; cold users (no `dev_train` row);
   cold IPs (IP absent from `dev_train`); successful logins only;
   user-history length 0, 1-4, 5-19, 20+ prior events of the user in the
   stream.

   **Seeds.** The stochastic models (the new Isolation Forests) use seeds
   42, 43, 44. Choose on seed 42; seeds 43 and 44 are run for the chosen
   configuration and reported as mean and range. The Phase 2 forest exists
   only at seed 42 (cached, not refitted).

   **Gates.** `ML_MODE = "v4"` (default `"legacy"`, unchanged) loads
   `data/model_v4.pkl` and the chosen threshold. The real detection,
   analysis and response agents replayed in v3 + v4 mode over `dev_train`,
   `val_a` and `val_b` must reproduce the offline scores and ML alerts with
   0 mismatches and place 0 blocks, or the integration is void.

5. 2026-10-13, Phase 4b, before any Phase 4b metric. Open ML questions
   from Phase 4. Seen before this amendment: every Phase 2, 3, 3b and 4
   result, including all Phase 4 val_a rows and the val_b rows that Phase 4's
   `confirm` computed (fallback, best with and without D, Phase 2 forest's
   best row, the two HGB references). Rules, thresholds' definition, bars
   and the test-set lock are unchanged.

   **Why this phase exists.** Phase 4 raised three questions on `val_a`:
   (1) the Phase 2 forest's frequency maps and known-IP set were built from
   `dev_train`'s non-attack rows, and the forest was fitted on those rows,
   so its 0.763 `val_a` ROC-AUC may come partly from label information
   rather than from label-free anomaly signal; (2) the Freeman model scored
   the placeholder ID (`config.UNKNOWN_ACCOUNT_IDS`) as a user, and at
   q = 1% every one of its alerts was on that ID; (3) the supervised
   reference clears the bar, so it matters whether it generalises to IPs it
   never saw. **The new candidates below were proposed after seeing Phase
   4's `val_a` results.** `val_b` has not been computed for any of them.
   This is a second look at the same `val_a`, so a qualifying candidate here
   carries more selection risk than one chosen in Phase 4, and `val_b` is
   the only half that can confirm it.

   **Diagnostic D1 (measurement, not selection).** The Phase 2 forest is
   rebuilt with its exact code and hyperparameters
   (`eval/phase2_baseline.Prepared`, `ml/train_from_dataset.fit_frequency_maps`
   and `extract_features_freq`, `StandardScaler`, `IsolationForest` with 200
   trees, `max_samples` 100000, contamination 0.4, seed 42; events scored
   with the vectorised v3 features of `eval/phase3_rules.raw_features`,
   30-day `failed_rate`), in three variants:
   - (a) original: maps, known sets, scaler and fit from the non-attack
     `dev_train` rows. Its scores are the cached
     `phase3_cache/ml_decision_v3.npy` (not refitted).
   - (b) maps and known sets from **all** `dev_train` rows; scaler and fit
     on the non-attack rows (features of those rows computed with the
     all-rows maps).
   - (c) maps, known sets, scaler and fit from **all** `dev_train` rows:
     fully label-free.
   Score = -`score_samples` (a constant shift of -decision, so the quantile
   thresholds select the same events). Reported for each on `val_a` and
   `val_b`: event ROC-AUC, PR-AUC and TPR at 1% FPR. (b) - (a) isolates the
   leakage through the maps and known sets; (c) - (b) the leakage through
   the fit rows (including the training rows' cumulative `failed_rate`).
   D1 chooses nothing; its `val_b` numbers are measurements of an
   ineligible diagnostic for (a) and (b), and for (c) they are reported only
   in the `confirm` stage below, after the choice is on disk.

   **New eligible candidates (label-free)**, in this order (the order breaks
   the last tie):
   - C1: variant (c) of D1, seed 42.
   - C2: Freeman, same beta grid (0.5, 2, 8), with every event whose user is
     in `UNKNOWN_ACCOUNT_IDS` given the minimum risk score, so it never
     alerts (the same treatment group C already gives that ID). The minimum
     is the smallest value of that beta's column over all development
     events (a constant, label-free). Other events keep their cached
     Phase 4 risk.
   - C3: reputation scores with the direction fixed a priori (a higher
     prior failure ratio is riskier): `d_asn_fail_ratio` alone,
     `d_ip_fail_ratio` alone, and their elementwise maximum, taken from the
     cached Phase 4 feature matrix exactly as computed (group D, so all
     three are "with D"; C1 and C2 are "without D").

   **Thresholds, criterion and confirmation:** identical to amendment 4.
   Each new score gets the dev_train `(1 - q)` quantile thresholds for q in
   (0.1, 0.5, 1, 2, 5, 10, 20, 30)% (`inverted_cdf`, score >= threshold
   alerts, ties all alert, identical alert sets kept), ML alerts
   de-duplicated per IP with a 3600 s cooldown, the same
   incremental-incident criterion against the same frozen rule incidents,
   the same bars (>= 30 incremental incidents and lower bound >= 0.2149 on
   `val_a`; holds on `val_b` = >= 30 and lower bound >= 0.1915, also
   reported against 0.2149) and the same ties (higher lower bound, fewer ML
   alerts, the candidate order above, then beta / score and threshold
   order). The choice is made on `val_a` among C1 to C3 only; the Phase 4
   rows are not re-entered. The `select` stage computes no `val_b` metric.
   `confirm` reads the choice from disk and computes `val_b` once for the
   chosen row (or, if none qualifies, the best-by-lower-bound row, as in
   amendment 4's fallback rule), plus the best row of each of C1, C2 and C3
   by the same rule within that family.

   **If a candidate qualifies,** it replaces the Phase 4 fallback in
   `data/model_v4.pkl` with `alerting = True`, the `workload` stage is
   rerun with it, and (for C2 or C3) the real-agent replay in v3 + v4 mode
   with alerting on must reproduce it over `dev_train`, `val_a` and `val_b`
   with 0 mismatches, or the integration is void. **If none qualifies,** the
   Phase 4 fallback stays in `model_v4.pkl` unchanged (`alerting = False`).

   **Supervised generalisation (measurement, not selection).** The existing
   HGB reference fits are scored from their cached Phase 4 scores (no
   refit): all eight fits (two feature sets x four settings), the two
   Phase 4 reference settings marked. Each fit uses the dev_train threshold
   at its feature set's reference-row quantile (20% for A-E, 10% for
   without D). On `val_a` and on `val_b`, within each subset below, reported:
   event ROC-AUC, PR-AUC, TPR at 1% FPR, ML alert precision with its
   IP-clustered CI, and incremental-incident precision with its CI (rule
   coverage over all of the half's events, as for amendment 4's strata;
   only alerts on events in the subset form incidents). Subsets:
   - cold IPs: events whose IP has no `dev_train` event;
   - new attackers: events whose IP has no attack-labelled `dev_train`
     event (so the attacking IPs left are ones the blocklist label had not
     shown the model; benign events stay as negatives);
   - excluding the placeholder ID's events.
   This answers whether a model trained on a historical blocklist flags
   new attacking IPs.

6. 2026-10-14, Phase 5, before any Phase 5 metric. Incident triage,
   graded response policy and operational fixes. Seen before this
   amendment: every Phase 2, 3, 3b, 4 and 4b result, including the val_b
   rule workload of amendment 3 (alerts, incidents, incident precision and
   the amendment 3 budget curves on val_b, which are the T0 budget curves
   below), the Phase 3b diagnostic of incident precision by top detector on
   val_b, the Phase 4 and 4b val_b confirmations, and the Phase 4b finding
   that the ASN prior failure ratio is the best label-free ranking signal
   (val_a and val_b ROC-AUC 0.726 / 0.736). **The triage scores T1, T2 and
   T3 below have never been computed on any half, and never on val_b; the
   response tiers have never been computed at all.** The rules (amendment 3
   settings), `data/model_v4.pkl` (Phase 4 fallback, `alerting = False`)
   and the test lock are unchanged. Because v4 raises no ML alert, every
   incident below is formed by the eight frozen rule detectors only.

   **Unit.** The incident (source IP, calendar day, UTC), as in amendment 3.
   An incident is *attack* if any event carrying one of its alerts is an
   attack event.

   **Incident features** (computed causally; the *running* value at an
   alerted event uses that event and everything before it, the *final*
   value is the running value at the incident's last alerted event):
   one indicator per frozen rule detector (it has an alert in the
   incident); the number of distinct detectors; log1p(alert count); the
   IP's FAILED and SUCCESS event counts that calendar day (all its events,
   alerted or not; log1p in T3); whether any of the IP's events that day
   targeted a `UNKNOWN_ACCOUNT_IDS` account; the maximum, over the IP's
   events that day, of the event's ASN prior failure ratio (group D
   `d_asn_fail_ratio`, all prior history, label-free; Phase 4 cache).

   **Triage candidates**, in tie order (simplest first). Scores are
   compared lexicographically, higher = more urgent:
   - T0: amendment 3's budget score: (highest val_a alert precision, point
     estimate at the chosen setting, among the incident's detectors;
     number of distinct detectors). Baseline.
   - T1: label-free additive: (number of distinct detectors; maximum ASN
     failure ratio).
   - T2: label-free: (T0's first component, the detector tier; maximum ASN
     failure ratio).
   - T3: logistic regression on the incident features above (StandardScaler,
     L2, C = 1.0, lbfgs, `max_iter` 1000, no class weights), fitted on the
     final features of the **dev_train incidents with their labels**; score
     = the linear predictor (monotone in the probability). **This is the one
     use of labels in a deployable component in this project**, declared
     here as the exception to amendment 4's rule: it uses labels the way an
     analyst-feedback loop would. It has no IP identity or IP-history
     feature (the ASN ratio is ASN-level). If chosen, its new-attacker
     stratum is reported next to every overall result.
   Remaining ties in an end-of-day ranking are broken uniformly at random,
   `default_rng(42)`, as in amendment 3.

   **Triage criterion (choose on val_a).** Each calendar day the incidents
   are ranked by their final score and the top B are taken (end-of-day
   ranking, as amendment 3's budget curves). Choose the candidate with the
   highest *mean daily attacking IPs caught* at B = 500 on val_a (per day:
   distinct attacking IPs with an attack incident among that day's top 500;
   mean over the 16 days), subject to: the day-clustered bootstrap lower
   bound of the *mean daily top-500 incident precision* >= T0's val_a point
   value of that same mean. Bootstrap: the 16 days resampled with
   replacement, statistic = mean of the drawn days' precision, 1,000
   resamples, 95% percentile interval, `default_rng(42)` per call. Ties
   (equal mean daily attacking IPs caught) go to the earlier candidate.
   T0 is subject to the same bar; its lower bound is below its own point
   value unless every day is equal, so it is expected to fail it. **If no
   candidate qualifies, T0 is kept.** Also reported: B = 100 and B = 2,000,
   attacking IPs caught over the whole half (amendment 3's measure), and
   every candidate's budget curves. `select` writes the choice to disk and
   computes no val_b metric; `confirm` reads it and computes val_b once for
   all four candidates; the chosen one *holds* if its val_b lower bound is
   >= T0's val_b point value. Nothing is re-chosen after val_b.

   **Response tiers.** A live system cannot rank a day before it ends, so
   the tiers use a causal, rate-based cutoff. For a daily rate k, the
   cutoff on day d is the k-th highest *final* score (chosen candidate,
   lexicographic) among the incidents of the most recent earlier calendar
   day that had incidents; if that day had fewer than k incidents, every
   incident qualifies; before the first completed day, none does. An
   incident enters the rate-k region at its first alerted event whose
   running score is >= that cutoff, and stays there. Rate grid K = (5, 10,
   20, 50, 100, 200, 300, 500, 1000, 2000, 5000) incidents/day.
   - **Block, TTL 3600 s:** k_block = the largest k in K whose region on
     val_a has >= 30 incidents and an incident-precision lower bound >=
     0.80 (IP-clustered bootstrap of amendment 3: the IPs with an incident
     in the region, 1,000 resamples, `default_rng(42)` per call). **If no
     k qualifies there is no block tier**, and nothing is ever blocked.
   - **Step-up challenge** (simulated MFA, recorded, not enforced, TTL
     3600 s): k_step = the largest k in K, k > k_block, whose band (rate-k
     region minus the rate-k_block region) has >= 30 incidents on val_a and
     a lower bound >= 0.2149. None qualifies: no step-up tier.
   - **Alert queue:** the rate-500 region minus the tiers above (empty if
     k_step >= 500).
   - **Log only:** every other incident.
   Each alerted event of an incident in the block (step-up) tier places or
   extends a block (challenge) on its IP for 3600 s of event time; detection
   never consults either list. The tier precision on val_a is reported with
   its interval for every k in K; on val_b the chosen k's are evaluated once
   (against 0.80, 0.2149 and 0.1915; no re-tuning).

   **Response cost on val_b** (from the one causal run over the whole
   stream; blocks and challenges placed at the end of val_a carry over):
   legitimate (non-placeholder) users with a benign event from an IP while
   it is blocked, and while it is challenged; benign IPs (only non-attack
   events in val_b) blocked or challenged; attacking IPs blocked or
   challenged; attack events arriving while blocked or challenged.

   **Strata, every result:** all events; excluding the placeholder ID's
   events; cold users (no dev_train row); **new attackers** (events whose
   IP has no attack-labelled dev_train event; benign IPs stay in) and
   **returning attackers** (the complement: events whose IP has an
   attack-labelled dev_train event). Budget curves per stratum follow
   amendment 3 (only the stratum's alerts form incidents, ranked within
   the stratum; the per-IP daily counts and ASN maximum come from the full
   stream at the incident's last alerted event). Response costs per
   stratum restrict the single deployed run's outcomes to the stratum's
   events, users and IPs.

   **Email (operational, not a metric).** One email per incident, sent when
   it first enters the block or step-up tier; none for queue or log. Per-IP
   cooldown (`EMAIL_IP_COOLDOWN_SECONDS`), a global limit per event-time
   clock hour (`EMAIL_MAX_PER_HOUR`, default 20); incidents over the limit
   go into that hour's digest, sent once when the hour closes. Severity is
   derived from the tier (block and step-up HIGH, queue MEDIUM, log LOW).

   **Gates.** The real agents with the new defaults (v3 rules, v4 ML, this
   policy), replayed over dev_train, val_a and val_b, must reproduce the
   offline running scores, tiers, blocks, challenges and emails with 0
   mismatches, or the policy is void. The legacy gate (legacy set
   explicitly) stays byte-identical.

7. 2026-10-14, Phase 5b, before any Phase 5b metric. Response volume.
   Seen before this amendment: every result up to and including Phase 5,
   in particular the amendment 6 tiers **on val_b** (step-up band
   precision, the val_b response cost per stratum, the email volume) and
   the val_a region rows of every rate in amendment 6's grid. **The tiers
   of Phase 5 were evaluated on val_b, so val_b is no longer an unseen
   check for the tier rate chosen here.** The val_b numbers below are
   reported as previously seen; they confirm nothing. From here on the
   locked May test month is the only clean check. The rules (amendment 3
   settings), the T2 triage score (amendment 6, chosen on val_a), the
   block criterion, the test lock and `data/model_v4.pkl` are unchanged.

   **Why.** Amendment 6's step-up rule bounded precision but not volume:
   every rate met the bar, so "the largest qualifying k" landed on the grid
   edge (5,000/day; 43,622 legitimate users challenged on val_b). Its
   cutoffs, the previous day's k-th highest final score, also overshoot
   the nominal rate for T2 (rates 300 to 2,000 all gave about 2,100
   incidents/day on val_a), because T2 has few distinct detector tiers and
   ASN ratios drift upward from day to day.

   **Admission (causal, capped).** For a rated tier with daily rate k, an
   incident of day d enters the tier at the first of its alerted events at
   which both hold:
   - its running score is >= the cutoff of amendment 6 (the k-th highest
     final score of the most recent earlier day with incidents; every
     incident qualifies if that day had fewer than k; none before the
     first day closes);
   - fewer than k incidents have entered that tier so far on day d (in
     stream order).
   An incident that qualifies on score after the day's k slots are taken
   does not enter; it stays in a lower tier (queue or log). Once in, an
   incident stays. So each tier admits at most k incidents a day by
   construction. Tiers are admitted from the top (block, step-up, queue);
   a tier never admits an incident that is already in a higher tier, and
   such an incident uses none of its slots. A slot, once used, is not
   returned (a queue incident that later enters step-up keeps its queue
   slot used). The queue uses this mechanism at B = 500/day. Admission is
   first-come within the day, not best-first: a live system cannot know
   the day's later incidents; this is a known cost of the cap.

   **Block.** Unchanged criterion: k_block = the largest k in amendment
   6's grid K whose capped block region on val_a has >= 30 incidents and
   an IP-clustered lower bound >= 0.80. None is expected; if none, there
   is no block tier.

   **Step-up rate.** Grid K_step = (10, 25, 50, 100, 200, 500, 1000)
   incidents/day. For each k, the deployed causal run over the whole
   stream (capped step-up at rate k, the block tier above, the queue at
   500) gives on val_a:
   - the step-up band: the incidents of val_a days in the step-up tier;
     its incident precision with amendment 3's IP-clustered bootstrap
     (1,000 resamples, 95% percentile interval, `default_rng(42)`);
   - *attacking IPs challenged*: IPs with an attack event in val_a and a
     step-up challenge placed during val_a (Phase 5's "IPs challenged:
     attacking");
   - *legitimate users challenged per day*: for each val_a day, the
     distinct non-placeholder users with a benign event, that day, from an
     IP while it is challenged (and not blocked); the mean over the 16
     days. U is a ceiling on that mean.
   k_step = the k in K_step that maximises attacking IPs challenged,
   subject to (i) >= 30 band incidents on val_a (carried over from
   amendment 6), (ii) band lower bound >= 0.2149, and (iii) mean
   legitimate users challenged per day <= **U = 200**. Ties: the smaller
   k. **If no k qualifies there is no step-up tier.**
   U is an operational assumption stated here a priori (roughly the number
   of unexpected MFA prompts a day a small help desk could absorb); it is
   not tuned. A sensitivity table shows what U in {50, 200, 1,000} would
   have chosen; only U = 200 is deployed.
   Also reported per k on val_a: benign IPs challenged per day and in
   total, attacking IPs challenged per day, step-up incidents per day.

   **Reported on val_b, marked as previously seen** (no choice, no
   re-tuning): the chosen k's step-up band precision with its interval,
   and its response cost (legitimate users, benign IPs and attacking IPs
   challenged, in total and per day; benign and attack events challenged),
   overall and per stratum (all events, excluding the placeholder, cold
   users, new attackers, returning attackers), with amendment 6's
   definitions.

   **Label audit (descriptive only).** A description, on dev_train, val_a
   and val_b only, of the attacking and benign IPs that the rules do and
   do not alert on, to ask whether the near-zero new-attacker precision of
   every detector reflects the detectors or the coverage of the per-IP
   blocklist label. It re-scores no detector and makes no choice.

   **Gates.** The real agents with the new defaults, replayed over
   dev_train, val_a and val_b, must reproduce the offline running scores,
   tiers (including the capped admission), blocks, challenges and the
   email log with 0 mismatches, or the policy is void. The legacy gate
   stays byte-identical.

8. 2026-10-14, Phase 5c, before any Phase 5c metric. Score floor for the
   rated tiers. Seen before this amendment: every result up to and
   including Phase 5b (amendment 7's step-up grid on val_a, its tiers and
   response cost on val_a and val_b, the label audit), and the Phase 5b
   live demo, where the previous day had fewer than k incidents, so every
   incident qualified on score and ordinary simulated logins (e.g. an
   off-hours success caught only by Suspicious Login Time) were
   challenged. No metric of the floor below had been computed on any
   split. The rules (amendment 3 settings), T2, the rates (step-up 200/day,
   queue 500/day, no block tier), the capped admission of amendment 7,
   `data/model_v4.pkl` and the test lock are unchanged.

   **Floor.** An incident may enter a rated tier (block, step-up, queue)
   at an alerted event only if, at that event, it carries an alert of at
   least one of the five rule detectors that survived Phase 3b: those that
   met amendment 3's criterion on val_a **and** held on val_b
   (`results/phase3b_confirm.json`): Slow Brute Force, Credential
   Stuffing, Invalid Account Spraying, Distributed Brute Force, Success
   After Failures. An incident whose alerts so far come only from Brute
   Force (met on val_a, failed on val_b), Multiple IP Login or Suspicious
   Login Time (failed on val_a) stays at log; it can still enter a tier
   later that day if one of the five alerts in it. The set is read from
   numbers already on disk; no parameter is introduced or tuned.

   **On top of amendment 7, unchanged.** The cutoff of a tier on day d is
   still the k-th highest final T2 score among all incidents of the most
   recent earlier day with incidents (incidents below the floor included;
   every incident qualifies on score if that day had fewer than k), and at
   most k incidents enter a tier per day. An incident below the floor uses
   no slot. T2's score itself is unchanged.

   **Reported on val_a and val_b, both marked as previously seen** (val_a
   chose k_step, val_b was reported in Phases 5 and 5b; nothing is
   chosen or re-tuned): per tier, incidents (total and per day),
   incident precision with amendment 3's IP-clustered interval and
   attacking IPs, with and without the floor; step-up attacking IPs
   challenged, benign IPs challenged and legitimate users challenged
   (total and per day; amendment 7's definitions). Also: how often the
   floor binds over the whole stream (dev_train, val_a, val_b): incidents
   below the floor at their final event, and incidents that would have
   entered step-up or the queue without the floor but did not with it,
   in total and on how many days.

   **Gates.** The real agents with the new defaults, replayed over
   dev_train, val_a and val_b, must reproduce the offline running scores,
   tiers (capped admission with the floor), blocks, challenges and the
   email log with 0 mismatches, or the floor is void. The legacy gate
   stays byte-identical. The locked May test month stays the only clean
   check.

9. 2026-10-14, Phase 6, before the test month is read. The final test
   plan. Seen before this amendment: every development result up to and
   including Phase 5c (amendments 1 to 8), `results/FREEZE.json` (tag
   `v3.0.0-frozen`), and of the test month only its row count (2,158,083)
   and file hash from `results/test_lock.txt`. No May row has been decoded
   (`results/test_access.log` does not exist). This amendment lists every
   number Phase 6 computes; anything else computed on May is labelled
   **post hoc** wherever it is reported.

   **Frozen system.** The code and settings hashed in `FREEZE.json`.
   `python -m eval.freeze --verify` must pass before the test is read and
   again after scoring; nothing in it changes in Phase 6.

   **Test access.** `FINAL_EVAL=1` is set only for the one command that
   reads the test month: `load("test")` with all columns, written to a
   cache under `results/phase6_cache/` (gitignored). Every later
   computation reads that cache, never `load("test")`. The access log is
   reproduced in the report.

   **Stream and state.** One causal stream: dev (2020-02-03 to 2020-04-30)
   then May (2020-05-01 to 2020-05-31), in time order. All causal state
   (rule windows, de-duplication, triage counters, ASN prior failure
   ratios, previous-day cutoffs, email cooldowns) runs through dev without
   being reset; only May events are scored. The 1 May cutoff comes from
   30 April. The val_a and val_b figures are recomputed by the same code on
   the same stream and must equal Phase 5c's (val_b is marked previously
   seen); they are the comparison columns.

   **Base rate and bars.** May base rate = attack events / May events
   (label as in "Data"). Each detector and tier is reported against
   2 x the May base rate and against the val_a bar 0.2149.

   **Strata on May** (only events in the stratum form alerts and
   incidents, as in amendments 3 and 6): all events; excluding the
   placeholder ID; cold users (User ID with no event before 1 May); new
   attackers (events whose IP has no attack-labelled event before 1 May;
   benign IPs stay in); returning attackers (the complement). The val_a /
   val_b comparison columns keep their original definitions (dev_train).

   **Primary results** (frozen system, default mode; definitions,
   intervals and seeds as in amendments 3, 6, 7 and 8; IP-clustered
   bootstrap = amendment 3's, day-clustered = amendment 6's over the 31 May
   days):
   - P1. Per rule detector (the eight), on May, per stratum: alerts,
     alert precision with its IP-clustered 95% interval, attacking and
     benign IPs flagged; whether it meets (>= 30 alerts and lower bound
     >= bar) 2 x the May base rate, and 0.2149.
   - P2. End-of-day triage of May incidents (amendment 3's incidents and
     budgets), T2 (deployed) and T0, at B = 100, 500 and 2,000, per
     stratum: mean daily incident precision with its day-clustered
     interval, mean daily attacking IPs caught, attacking IPs caught over
     the month and their share; and whether T2's lower bound at B = 500 is
     >= T0's point value (amendment 6's test).
   - P3. Response tiers as deployed (the one causal run): per tier on May
     incidents: incidents (total, per day), precision with its interval,
     attacking IPs; step-up against 0.2149 and 2 x the May base rate;
     legitimate users challenged per day (mean and maximum; amendment 7's
     definition) and in total; benign and attacking IPs challenged (total
     and per day); benign and attack events challenged; the same response
     cost per stratum; the log tier's share of May attacking IPs (attacking
     IPs whose highest tier over May is log, among those with an attack
     incident); blocks placed (expected 0); emails and digests per day
     (mean, maximum) and outcomes; maximum admissions per day per tier; how
     often the amendment 8 floor binds in May.
   - P4. Rule incidents per day and incident precision with its interval
     on May, per stratum; rule alerts per day.

   **Secondary results:**
   - S1. Leakage replication. The Phase 2 forest variants (a) original,
     (b) maps and known sets from all dev_train rows, (c) label-free,
     built exactly as amendment 5's D1 (dev_train rows only; 30-day
     windowed `failed_rate` computed causally over the whole stream), at
     seeds 42, 43 and 44 (variant (a) at seed 42 must reproduce the cached
     Phase 3 decisions on dev events); on May events, overall and new
     attackers: event ROC-AUC, PR-AUC and TPR at 1% FPR, per seed and as
     mean and range.
   - S2. Supervised reference. The eight cached Phase 4 HGB fits (not
     refitted; the two Phase 4 reference settings marked), on Phase 4
     features (`ml/features_v4`) computed in one causal pass over the whole
     stream; on May events, overall and new attackers: ROC-AUC, PR-AUC and
     TPR at 1% FPR.
   - S3. Legacy system. `RULES_MODE` and `ML_MODE` "legacy",
     `data/model.pkl` (SHA-256 b47e9533...870be), through `eval/harness`
     (real agents, exact batch scorer), on May at natural prevalence. Its
     state is cumulative and never expires (audit F02), so it starts empty
     at 2020-05-01 00:00 rather than carrying three months of permanent
     blocks. Per legacy alert type (ML by confidence): alerts, precision
     with its IP-clustered interval, attacking and benign IPs flagged;
     overall alert precision, event recall, campaign recall and FPR; HIGH-
     alert simulated blocks: benign and attacking IPs blocked, benign
     events and successes after a block, and benign users affected
     (distinct users with a benign event from an IP after its first HIGH
     alert).
   - S4. Label audit on May (descriptive; amendment 7's groups and
     statistics, with "returning" = attack-labelled event before 1 May;
     strict misuse over the IP's whole history to 31 May; the ASN cue
     against attacking IPs seen before 1 May).
   - S5. Operations. From the real-agent replay: wall time per May event
     in microseconds for rules (detection), triage and response, analysis,
     and in total; store insert time per alert into SQLite for one May day
     (2020-05-15); peak memory. Timers are wrapped around the agents'
     methods by the replay script; no frozen file changes.
   - S6. Functional test. The Phase 5c live demo (a copy of the frozen
     backend, an empty data directory, one seeded previous day, the live
     simulator for 150 s): incidents form, simulated attacks reach step-up,
     pipeline stats are written while running. No RBA data, no metrics.

   **Gates.** Freeze verified before and after; test lock verified. The
   real agents (frozen defaults) replayed over dev and May must reproduce
   the offline twin (rule alerts per detector, running scores, tiers,
   blocked and challenged state before every event, the email log and
   outcomes) with 0 mismatches on dev_train, val_a, val_b and May; the
   primary results are the agents' outputs. The legacy gate stays
   byte-identical.

   **Bug policy.** A defect in evaluation code found after the test is
   read may be fixed only if the fix uses no test result to choose
   anything; it is logged with before and after values, and only the
   affected metric is rerun. A defect in the frozen system is reported,
   not fixed.

10. 2026-10-17. Amendment 10 (post hoc, written after the test was scored;
    dev data only; descriptive). A blocklist-lookup baseline: score = 1 if
    the event's IP appears in any attack-labelled dev_train row, else 0.
    Reported on val_a and val_b, all events: ROC-AUC (binary score, ties
    averaged), PR-AUC, precision and recall of score = 1, and the share of
    attack events whose IP was attack-labelled in dev_train. Compared with
    S1 construction (a) on the same halves. No May data is read.

LANL (second dataset): see eval/PROTOCOL_LANL.md (amendment LA1).

## Amendment 11. Entity-label leakage diagnostic

**Status: post hoc, disclosed.** Written on 6 November 2026, after every
result in the manuscript existed. It introduces no selection, changes no
reported number, and is not used to choose any detector, setting, score or
tier rate. It requires no new read of any locked period: it operates on
stored outputs and on development rows only.

**Purpose.** To state, as a procedure others can apply, the method by which
the leakage reported in the manuscript was located and measured.

**Scope condition.** The procedure applies where the evaluation label
attaches to a persistent entity rather than to an individual event. Leakage
through label-filtered fitting of pre-model artefacts is expected to be
severe when all three of the following hold: the label attaches to a
persistent entity; that entity recurs across the fitting and scoring
boundary; and the labelled entity's rows are almost entirely labelled.

### 11.1 Procedure

**Step 1. Entity-lookup reference.** For the entity the label marks, score
an entity 1 if it appears in any positively-labelled row of the warm-up
period and 0 otherwise. Report ROC-AUC and PR-AUC on each scored period,
with the precision and recall of the score-1 set. This reference reads
warm-up labels. It is neither a deployable detector nor a comparison
baseline, and it is reported as a measurement of what the label rewards.
Already computed for the first dataset under amendment 10.

**Step 2. Fitted-artefact audit.** Enumerate every artefact fitted before
the model: frequency and count maps, known-value sets, vocabularies,
encoders, scalers and thresholds. For each, record the row set it was fitted
on and whether that row set was selected using the label. Report the number
of code sites affected. Checking that no label column is passed as a feature
does not discharge this step, and in the case reported here it did not.

**Step 3. Three-construction rebuild.** Rebuild the detector in three
constructions, all fitted on warm-up rows only and scored on each later
period, over at least three model seeds where the model is stochastic:

- (a) the original construction, as deployed;
- (b) pre-model artefacts fitted on all rows, model fitted on
  label-selected rows;
- (c) fully label-free, artefacts and model both fitted on all rows.

Report for each construction which features are constant on every fitted
row, since a feature constant at fit time cannot carry the leakage however
much it appears to.

**Step 4. Label-attributable share.** Defined in 11.2.

### 11.2 The statistic

For a construction v, the above-chance ranking share is

    share_v = (AUC_v - 0.5) / (AUC_a - 0.5)

and the label-attributable share of the original construction is

    L = (AUC_a - AUC_c) / (AUC_a - 0.5)

which equals 1 - share_c by algebra.

**Estimator.** L is computed per model seed and reported as the mean of the
per-seed values. The ratio of the seed-mean AUCs is reported alongside it as
a secondary figure, and the two are not interchangeable.

**Domain of validity.** L is reported only where the lower bound of the
interval on AUC_a exceeds 0.55. Below that the denominator is small and the
statistic is unstable. The new-attacker stratum of the first dataset's
locked test month is the worked example of that failure and is reported as
such: there AUC_a lies between 0.5695 and 0.5745, the shares exceed 1 and L
is negative, because construction (c) ranks that stratum better than
construction (a). Where the condition fails, the three AUCs are reported
without the ratio.

**Interval.** 95% percentile bootstrap over 1,000 resamples clustered by the
labelled entity, using a numpy Generator(PCG64) seeded at 42, recomputing
both AUCs on each resample from stored per-event scores. If per-event scores
are not available for all three constructions, the interval is reported as
missing and the point values are given with the per-seed range; this is
recorded as a limitation rather than omitted.

### 11.3 Reporting rule

Report the previously-unlabelled stratum separately from the aggregate
whenever the label marks an entity, because the aggregate is dominated by
entities the label already carried and every detector scores 1.000 on
returning entities by construction.

### 11.4 Validation control: random persistent entity label

**Purpose.** To test whether the construction in step 3(a) manufactures
ranking from a persistent entity label that carries no attack signal at all.

**Scope.** RBA development data only: `dev_train`, `val_a` and `val_b`. The
induced label is applied to those three splits and to no other period. The
locked May test month and every month from June 2020 onward are not read
under this amendment.

**The induced label.**

- Entity: source address.
- From `dev_train`, let A be the set of distinct addresses carrying at least
  one attack-labelled row and N the set carrying none. Report the size of
  each and the share A/(A+N).
- Draw uniformly at random without replacement a subset S of N with the same
  cardinality as A. Three independent draws, using a numpy Generator(PCG64)
  seeded at 1, 2 and 3.
- Set the induced label to 1 on every row of every address in S, across
  `dev_train`, `val_a` and `val_b`, and 0 on every other row. Confirm and
  report that the intersection of S and A is empty.
- Because S is drawn from addresses carrying no attack-labelled row, the
  induced label carries no attack signal by construction.

**Constructions.** (a') and (c') exactly as step 3, with the induced label
substituted for the attack label, fitted on `dev_train` only, with the same
model settings as the existing S1 construction and model seeds 42, 43 and 44.

**Quantities.** Per draw and per model seed, on `val_a` and `val_b`
separately, scored against the induced label: ROC-AUC and PR-AUC for (a')
and (c'), the induced-label event base rate, and L.

**L for this control.** L = (AUC_a' - AUC_c') / (AUC_a' - 0.5), computed per
draw and model seed, averaged over the three model seeds within each draw,
and reported per draw. The mean over the three draws is a secondary figure.

**Intervals for this control.** 95% percentile bootstrap, 1,000 resamples,
clustered by source address, numpy Generator(PCG64) seeded at 42, computed
for AUC_a' and AUC_c' at model seed 42 for each draw. Three intervals per
split rather than nine, declared here to bound compute.

**Entity-lookup reference.** Step 1 applied to the induced label: score an
address 1 if it appears in any induced-label row of `dev_train`. Report
ROC-AUC, PR-AUC, and the precision and recall of the score-1 set.

**Fit-time absence count.** Report the size of the known-address set built
from all `dev_train` rows minus the size of the set built from rows whose
induced label is 0. The real-label value of that same quantity is 22,089,
recorded in `PHASE4B_REPORT.md` as 947,226 minus 925,137; that derivation is
to be verified in that file and reported alongside. It is a different
quantity from `dev_train_attack_ips` = 22,095 in
`results/amendment10_lookup.json`, which counts addresses with any
attack-labelled row. The induced-label figure must be computed by the same
code path as the real-label figure.

**Declared predictions.** Evaluated on `val_a` and `val_b` separately, and
holding only if they hold for all three draws on both splits:

1. the lower bound of the interval on AUC_a' exceeds 0.60;
2. the interval on AUC_c' contains 0.50;
3. L, averaged over the three model seeds within a draw, exceeds 0.85.

Any prediction that fails is reported as a failure, and the scope condition
in 11.1 is revised or withdrawn rather than restated.

### 11.5 Prior exposure and authorised inputs

Recorded because this amendment is post hoc.

- Before it was written, the real-label ranking shares of 11.2 had been
  computed from stored outputs in `backend/eval/FEASIBILITY_AUDIT.md` on
  6 November 2026, including L = 0.9850456188746078 on `val_a` and the
  per-seed and seed-mean values on the May test month. The `val_b` value for
  construction (c) had not been read.
- Nothing had been computed on any induced or random label.
- `results/phase4b_confirm.json` is authorised as an input for the `val_b`
  construction (c) ROC-AUC, which lay outside the three inputs used by the
  feasibility audit.
- No new read of the locked May test month, or of any month from June 2020
  onward, is permitted under this amendment.

### 11.6 Validation control: distribution-matched random label

**Status: post hoc, disclosed.** Written on 6 November 2026, after the 11.4
control was run and two of its three declared predictions failed. Those
results are recorded under prior exposure below.

**Purpose.** To determine whether the weakness of the 11.4 control is
explained by the row mass of the labelled entities rather than by the
mechanism itself failing. Under 11.4 the induced label matched the real
attack label on address count, 22,095, but not on the share of rows those
addresses carry, and most non-attacking addresses carry very few rows.
Removing a small number of rows perturbs the frequency maps only slightly,
which is the artefact the control was meant to exercise.

**Scope.** RBA development data only: `dev_train`, `val_a` and `val_b`. The
induced label is applied to those three splits and to no other period. The
locked May test month and every month from June 2020 onward are not read
under this amendment.

**The induced label.**

- Entity: source address.
- Bin every `dev_train` address by its row count in `dev_train`, using the
  declared bins 1, 2, 3 to 5, 6 to 10, 11 to 20, 21 to 50, 51 to 100, 101 to
  500, and 501 or more.
- For the real attack-labelled address set, report the number of addresses in
  each bin, and the share of `dev_train` rows that set carries. Call that
  share p.
- Draw, from the non-attack addresses in each bin, the same number of
  addresses as the real set holds in that bin, uniformly at random without
  replacement. Three independent draws, using a numpy Generator(PCG64) seeded
  at 11, 12 and 13.
- **Declared fallback.** If a bin holds fewer non-attack addresses than
  required, take all available and make the shortfall up from the next lower
  bin, repeating downward as needed. Report every shortfall, the bin it
  occurred in and the number of addresses moved.
- Set the induced label to 1 on every row of every drawn address, across
  `dev_train`, `val_a` and `val_b`, and 0 on every other row. Confirm and
  report that the intersection with the real attack-labelled set is empty.
- Report the achieved induced-label share of `dev_train` rows against p, the
  achieved address count against 22,095, and the rows-per-address
  distribution of both sets.

**Constructions, quantities, L and intervals.** Exactly as 11.4, with model
seeds 42, 43 and 44 and the bootstrap specification of 11.4 unchanged.

**Declared predictions.** Evaluated on `val_a` and `val_b` separately, and
holding only if they hold for all three draws on both splits:

1. the lower bound of the interval on AUC_a' exceeds 0.70;
2. L, averaged over the three model seeds within a draw, exceeds 0.85.

**No prediction is declared for AUC_c'.** The 11.4 control showed that its
position relative to 0.50 depends on how typical the drawn addresses are
relative to the average development row, and a distribution-matched draw
changes that in a direction this amendment has no basis to predict in
advance. AUC_c' is reported with its interval and no pass or fail attached.

**Stop condition.** If the lower bound of the interval on AUC_c' exceeds
0.60, stop and report. A label-free construction ranking a random label well
above chance would indicate that the draw is selecting on a property the
model observes, which is a fault in the control rather than a finding.
Failures of predictions 1 or 2 are substantive: report them and continue.

**Consequences, declared in advance.** If prediction 1 holds, the scope
condition in 11.1 gains a fourth clause, that the labelled entities must
carry a substantial share of rows, and the condition ceases to be
provisional. If prediction 1 fails while prediction 2 holds, then part of the
original construction's ranking came from genuine differences in the
behaviour of attacking addresses rather than from the filter, the paper must
report that, and L is presented as a decomposition of the apparent ranking
rather than as a measure of leakage alone.

**Limitation of the entity-lookup reference under induced labels.** Under
both 11.4 and 11.6 the induced label is defined over `dev_train` addresses,
so every induced-positive address appears in `dev_train` and the reference of
11.1 step 1 scores 1.0 on every measure by construction. It therefore carries
no information for an induced label, has no new-entity analogue, and is
reported only for the real label.

**Prior exposure.** Recorded because this amendment is post hoc. The 11.4
control was run on 6 November 2026 and reported: prediction 1 failed on all
six draw-and-split cases, with AUC_a' lower bounds of 0.541 to 0.575;
prediction 2 failed on draws 1 and 3 on both splits, with AUC_c' intervals of
about 0.454 to 0.493, and held on draw 2; prediction 3 held on all six, with
L between 0.912 and 1.445. The rebuilt constructions were bit-identical to
the cached originals, the induced-label fit-time absence count was 22,095 per
draw against the real-label 22,089, and the entity-lookup reference on the
induced label was 1.0 throughout. The construction (c) ROC-AUC for `val_b`,
0.506056815350325, was observed in `results/phase4b_confirm.json` while
reading code before the stop, and is authorised as an input under 11.5.

### 11.7 Second domain clause for L, and a declared contrast test

**Status: post hoc, disclosed.** Written on 6 November 2026, after the 11.4
and 11.6 controls and after LA6. Its contents were decided by their results.

#### 11.7.1 Second domain clause

Amendment 11.2 bounds L only from below, through the condition that the
lower bound on AUC_a exceeds 0.55. It does not bound it from above. Where
AUC_c falls below 0.5 the ratio exceeds 1, and a quantity presented as a
share of above-chance ranking cannot coherently exceed 1.

This arose in practice. In the 11.6 control, draws 12 and 13 returned L above
1 for that reason, and the real-label intervals are [0.9360, 1.0324] on
`val_a` and [0.9256, 1.0272] on `val_b`, both of which cross 1.

**Rule.** L is reported unclamped. Wherever AUC_c falls below 0.5, or an
interval bound on L exceeds 1, the figure carries an explicit flag and is
read as: all of the above-chance ranking is attributable to the label filter,
and in addition the label-free construction ranks below chance. L is never
silently clamped to 1, and an interval crossing 1 is reported as it stands
rather than truncated.

#### 11.7.2 Declared contrast test

The prediction in 11.6 compared the lower bound of AUC_a' against an absolute
value of 0.70, chosen by the authors. The question actually at issue is
whether a distribution-matched random label reaches the same ranking as the
real label on the same split, which is a contrast and not a threshold. That
test was never declared and is therefore not reported as a result of the
earlier controls.

**Test.** On `val_a` and `val_b` separately, compare AUC_a for the real
attack label against AUC_a' for each distribution-matched random draw of
11.6, using a 95% percentile bootstrap on the difference, 1,000 resamples,
clustered by source address, numpy Generator(PCG64) seeded at 42, computed at
model seed 42, with both constructions scored on the same resampled rows.

**Reported quantity.** The difference AUC_a minus AUC_a' with its interval,
per draw and split. That difference is the estimate of how much of the
original construction's ranking is not reproducible by a label with no attack
content.

**No prediction is declared.** The 11.6 result makes the direction known and
the magnitude small, so a prediction now would be a restatement of seen data
rather than a declaration. The quantity is reported with its interval and no
pass or fail attached, and the paper states that this test was declared after
the controls were seen.

#### 11.7.3 What this does not do

It does not revisit the failure of prediction 1 in 11.6. That failure stands
as reported, and the consequence declared in 11.6 applies.

### 11.8 Withdrawal of the scope condition, and the LA6.2 reading

**Status: post hoc, disclosed.** Written on 6 November 2026 after LA6 ran.

#### 11.8.1 Withdrawal of the scope condition in 11.1

The scope condition in 11.1 stated three clauses, and 11.6 proposed a fourth,
provisional clause on the row mass of the labelled entities. LA6.1 falsified
the condition: a persistent entity label induced on 86 LANL red-team source
users, removing 532,232 fitting rows or 2.86% of the fitting population,
produced L between -0.190 and 0.077 across all six split-and-seed cases, with
every interval containing 0, against a predicted value above 0.85.

**The scope condition is withdrawn, not revised.** This work claims no
general rule for when label-filtered fitting of pre-model artefacts produces
leakage.

**What replaces it is an observation, not a law.** On the authentication
dataset the labelled entity is itself a key of the frequency maps, so
filtering by the label removed 22,089 keys outright and those addresses
scored as unseen when they returned. On the enterprise dataset, removing the
rows of 86 labelled users changed 33 map entries and dropped one destination
computer, because the map keys are computers shared across many users and
remain populated from other users' traffic. This is reported with its
measured perturbation counts as an observation about two datasets, and
explicitly not as a condition that predicts occurrence.

**Consequence for the paper.** The diagnostic is presented as a check that
has to be run, because occurrence cannot be predicted from the shape of the
label. The failure of LA6.1 is reported in full wherever the diagnostic is
described, and is not omitted on the grounds that a later variant succeeded.

#### 11.8.2 The LA6.2 reading

LA6 contained two inconsistent definitions of failure: the prediction, which
required the interval on L to contain 0 and its upper bound to fall below
0.30, and the consequence clause in LA6.4, which defines failure as L being
substantially above 0.

The result: the upper bound was below 0.30 in all six cases, the largest
being 0.0073; the interval contained 0 in five of six cases; and seed 43 on
days 8 to 11 returned [0.0017, 0.0073].

**Reading applied.** The prediction as worded failed in one of six cases and
is reported as a failure. The consequence clause's trigger is not met, so the
diagnostic is not withdrawn. **This reading was chosen after the result was
seen and is disclosed as post hoc.** The inconsistency was in the amendment
as written, not in the result.

**Rule for future declarations.** A prediction of negligibility states a
magnitude bound. It does not require an interval to cover zero, because a
genuinely small perturbation produces a small non-zero effect that a precise
estimator will correctly detect.

#### 11.8.3 Deviations recorded from the LA6 run

- The bootstrap user ordering was corrected after the first metrics run
  failed to reproduce the stored D1 intervals. Point values were unchanged
  and both verdicts were identical in both runs; every reported figure comes
  from the corrected run.
- The LA6 declaration commit was amended to restore a final line dropped by
  the first append. This occurred before any code existed and before anything
  was pushed. It is recorded because it touches the declaration-order claim.
- Construction interpretation: known-value sets for source user and
  destination computer were reported as perturbation counts rather than as
  model inputs, which left construction (c) bit-identical to the stored D1
  detector, as the identity checks confirm.

### 11.9 Corrections to 11.8, withdrawal of LA7, and an artefact-absence measurement

**Status: post hoc, disclosed.** Written on 6 November 2026 after Tasks H, I
and J of the preceding run.

#### 11.9.1 Correction to 11.8.1

Amendment 11.8.1 states that on the enterprise dataset, removing the rows of
86 labelled users changed 33 map entries and dropped one destination
computer. **Those figures are wrong.** They are LA6.2's, from the true-label
negative control in which 50 matched rows were removed. They are not LA6.1's.

The correct LA6.1 figures, from `results/lanl_la6_controls.json`: the
source-user frequency map, which is keyed on users and is a model input,
lacked all 76 labelled users present in the fitting rows
(`artefacts/F/user/keys_only_in_c` equal to 76). The source-computer and
destination-computer maps, which are keyed on computers rather than on the
labelled entity, lost 298 and 280 keys respectively, those being the
computers appearing only in labelled users' rows; computers shared with
unlabelled users remained.

The explanation 11.8.1 attached to its figures is therefore **withdrawn**.
The labelled entity was removed from the artefact keyed on it, and no leakage
followed.

11.8.1's withdrawal of the scope condition in 11.1 **stands**. Only its
explanatory sentences are corrected here.

#### 11.9.2 Withdrawal of LA7, unrun

LA7 declared a single change to LA6.1: add a frequency map keyed on source
user as a model input, so that the labelled entity would itself be a key of a
relied-upon artefact. That map was already a model input in the D1 scorer and
in LA6.1, as the feature `user_freq`, and the construction (a) map already
lacked all 76 labelled users present in the fitting rows. LA7 as written was
therefore identical to LA6.1, and its declared expectation that construction
(c) would cease to be bit-identical to the stored D1 detector was false.

**LA7 is withdrawn without being run.** It remains in `PROTOCOL_LANL.md` at
commit `eb6937b` and is not removed or reverted, because a declaration made
and then withdrawn is itself part of the evidence this protocol exists to
preserve. The amendment register records it as declared and withdrawn unrun.

LA7's hypothesis was that the mechanism **requires** the labelled entity to
be a key of a relied-upon fitted artefact. LA6.1 shows that this condition
being met was **not sufficient** for leakage. It does not show the condition
unnecessary, and no claim either way is made.

#### 11.9.3 The cause of the non-reproduction is not established

No explanation is claimed for why the mechanism did not reproduce on the
enterprise dataset. The result is reported, and its cause is reported as
unknown.

#### 11.9.4 Artefact-absence measurement, descriptive

**Purpose.** To establish whether the information the mechanism would need is
present in the fitted artefacts, on both datasets.

**No prediction is declared, and the reason is recorded.** Revision 1 of this
amendment declared that the indicator's area would exceed 0.90 on the
authentication source-address artefact and fall below 0.70 on the enterprise
source-user artefact. That prediction is **withdrawn before commit**, on two
grounds. First, stored output already indicates the enterprise value: all 86
labelled users are absent from the construction (a) source-user map, 76
having been removed and 10 never appearing in the fitting rows, so the
indicator is 1 on every induced-positive row and its recall against the
induced label is 1 by construction, while the stored LA6.1 entity-lookup
reference reached 0.99991 and 0.99997. A prediction made with that in hand
would restate seen data. Second, revision 1 described the authentication side
as a consistency check against the amendment 10 lookup, which it is not: the
lookup flags addresses present in attack-labelled warm-up rows, whereas the
absence indicator flags addresses absent from the construction (a) artefact,
which includes every address never seen in the warm-up period at all, benign
or otherwise. The two are different indicators and the authentication value
may be well below 0.9646 because of benign address churn.

**Definition.** For each fitted artefact keyed on an entity, define on each
scored row an absence indicator equal to 1 if that row's key for the artefact
is absent from the construction (a) artefact, and 0 otherwise. Report, per
artefact and per scored split: the ROC-AUC and PR-AUC of that single
indicator against the label; the share of scored rows with the indicator set;
and the precision and recall of the indicator-set rows.

**Artefacts measured.** Authentication: the source-address frequency map, the
known-address set, and the country and device-type frequency maps where they
exist as fitted artefacts of construction (a). Enterprise: the
source-computer, source-user and destination-computer frequency maps. Where
two artefacts share the same key their indicators are identical; that is
reported once, with both artefacts named, rather than as two results.

**Labels.** On the enterprise dataset the indicator is reported against both
the true event-level red-team label and the LA6.1 induced label, with the
induced label primary, since it is the label whose mechanism is under
examination. On the authentication dataset the real attack label is used.

**No model is fitted.** Only frequency maps and known-value sets are
rebuilt. No scaler is fitted and no forest is trained. The enterprise maps
were not saved under LA6.1 and are rebuilt deterministically from the per-day
codes; before any indicator is computed, the rebuilt maps are checked against
the stored key counts of 298, 76 and 280, and a mismatch stops the task.

**Scope.** Both datasets, development splits only. No new read of either
locked period.

**What the paper will say.** If the indicator is strongly predictive on both
datasets while L is high on only one, the paper reports that the availability
of this information in the artefacts does not predict whether the mechanism
occurs, which strengthens the case that the full check has to be run. If the
ordering is the reverse of L's, the paper reports that. In neither case is an
explanation for the enterprise non-reproduction claimed, and 11.9.3 stands.

#### 11.9.5 Reporting rules arising from the consolidated table

- The May value of L is derived by arithmetic from the stored areas in
  `results/phase6_s1.json`. It is not stored in any file, carries no
  interval, and the domain condition of 11.2 cannot be checked for it. Every
  appearance of it is labelled as derived and interval-free.
- The flag of 11.7.1 applies to 38 of the 95 rows of the consolidated table.
  It is therefore a common condition and is explained in the main text
  wherever L is introduced, not relegated to a caption or footnote.
- One row fails the domain condition of 11.2: the 11.4 count-matched
  control, draw 1, `val_b`, model seed 42, with a lower bound on AUC_a' of
  0.5411. L for that row is not reported as a valid share.
- Intervals in the controls exist at model seed 42 only, so the domain
  condition cannot be checked for seeds 43 and 44, and those rows are
  reported with that limitation stated.
