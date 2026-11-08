# Amendment 11.7 contrast test, LA7 status, and every L to date

Written 2026-11-06. Governed by `eval/PROTOCOL.md` amendments 11.1 to 11.8
and `eval/PROTOCOL_LANL.md` LA6 and LA7.

Script: `eval/amendment11_7_la7.py`, with stages `contrast` (Task H), `label`
(Task I1) and `table` (Task J). Values: `results/amendment11_7_la7.json`.
JSON paths below are relative to that file unless another file is named.

**Development data only.**
- **RBA:** `datasets.load("dev")` through `eval.phase3b.stream()`. Task H fits
  nothing: it reads stored per-event scores for val_a and val_b. The locked
  May month, the Phase 6 May cache, and every month from June 2020 onward
  were not read. The May rows of Task J come from the stored result file
  `results/phase6_s1.json`, not from the month.
- **LANL:** Task I1 read the per-day codes and the D feature files for days
  0 to 13, through `eval.lanl_la6`, and the dev red-team rows through
  `eval.lanl_la3.redteam_dev`. No day from 14 onward was read.
  `results/lanl_test_access.log` had 8 lines before and 8 after.

## Summary

| Task | Result |
|---|---|
| H, the 11.7.2 contrast | AUC_a − AUC_a′ lies between 0.0337 and 0.0399 on val_a and between 0.0472 and 0.0506 on val_b. No interval contains 0: the lowest lower bound is 0.0253 and the highest upper bound 0.0603. No pass or fail is attached (11.7.2). |
| I, LA7 | **NOT RUN, apart from I1.** LA7's one declared change is already part of LA6.1, so LA7 as written cannot be carried out (below). I1 reproduces the LA6.1 label: 86 users, 75 present in both periods. The author decided to report Task I as not run, pending a correction amendment. No LA7 code was written or run. |
| J, every L | 95 rows. One row (row 17) fails the 11.2 domain condition: 11.4 draw 1, val_b, seed 42. Thirty-eight rows carry the 11.7.1 flag. The LA7 rows are MISSING. |

## Freeze manifest and tags

| When | Command (from `backend/`) | Output | Exit |
|---|---|---|---|
| Before any work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
| After all work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

No tag was moved: `v3.0.0` = 97a37f9 and `v3.0.0-frozen` = bb40c16. No
frozen file was modified. The only new code is `eval/amendment11_7_la7.py`.

## Step 0

Each amendment was appended verbatim from the drafting document and
committed on its own. After each append, the tail of the file was compared
byte for byte (`cmp`) with the text as drafted, and each
matched exactly.

| Commit | File | Text |
|---|---|---|
| `a596788` | `PROTOCOL.md` | 11.7 (Part 1), 53 lines |
| `d9f57d3` | `PROTOCOL.md` | 11.8 (Part 2), 67 lines |
| `eb6937b` | `PROTOCOL_LANL.md` | LA7 (Part 3), 52 lines |

LA7 was committed before the blocker in Task I was found.

---

## Task H. The contrast test (11.7.2)

**Scorers, both at model seed 42.**
- **(a):** the real construction, scored against the real attack label
  (`Stream.truth`). Scores: −`results/phase3_cache/ml_decision_v3.npy`, as in
  `amendment11_controls.stage_real`.
- **(a′):** the 11.6 construction for draw *d*, scored against draw *d*'s
  induced label. Scores:
  `results/amendment11_cache/matched_a_prime_draw{d}_seed42_val.npy`.

**Induced labels.** Rebuilt with the 11.6 code
(`amendment11_controls.matched_draw`). For all three draws, the induced row
counts on dev_train, val_a and val_b equal `amendment11_6_controls.json`
`C2/draw_d/induced_rows` (`H/label_rebuild_checks`).

**Bootstrap.**
- 1,000 resamples of source addresses with replacement, numpy
  `Generator(PCG64(42))`.
- Every resample weights the same rows for (a) and for every (a′), and each
  scorer is scored against its own label.
- AUC ties are averaged.
- The difference is recomputed on each resample, and the interval is the
  2.5 and 97.5 percentiles.
- All 1,000 resamples were valid in every case.

**Checks** (`H/splits/<split>/...`):
- Every point AUC recomputed from the per-event scores equals the stored
  value exactly.
- The marginal intervals equal the stored ones exactly: AUC_a against
  `amendment11_6_controls.json real/halves/<split>/interval/roc_auc_a`, and
  AUC_a′ against `draws/draw_d/<split>/interval_seed_42/a_prime_roc_auc`.
  So the paired resamples are the same ones that produced the 11.2 and 11.6
  intervals.

Clusters: 348,248 addresses on val_a (1,183,517 events) and 345,496 on
val_b (1,153,710 events).

| Split | Draw | AUC_a (real label) | AUC_a′ (matched random label) | AUC_a − AUC_a′ | 95% interval |
|---|---|---|---|---|---|
| val_a | 11 | 0.762999627767321 | 0.7292500101682221 | 0.03374961759909889 | [0.025319638453121285, 0.04243628443608322] |
| val_a | 12 | 0.762999627767321 | 0.7248520477590753 | 0.038147580008245696 | [0.02936357430007542, 0.0466984387075994] |
| val_a | 13 | 0.762999627767321 | 0.7231221273804145 | 0.03987750038690652 | [0.03305694475589224, 0.04608344661930493] |
| val_b | 11 | 0.750421331271785 | 0.7032710813798777 | 0.0471502498919073 | [0.03607211498568382, 0.05761727468620961] |
| val_b | 12 | 0.750421331271785 | 0.6998297292742648 | 0.05059160199752022 | [0.041008198209100497, 0.060335721582056974] |
| val_b | 13 | 0.750421331271785 | 0.700777514569204 | 0.049643816702581 | [0.040018808232813716, 0.059618799832901345] |

**Value sources.**
- AUC_a: `amendment11_6_controls.json real/halves/<split>/roc_auc_stored/a`
  (= `phase4b_diag.json variants/a/<split>/roc_auc`).
- AUC_a′:
  `amendment11_6_controls.json draws/draw_d/<split>/per_model_seed/seed_42/a_prime/roc_auc`.
- Difference and interval:
  `H/splits/<split>/draw_d/difference_a_minus_a_prime` and `.../difference_interval`.

As 11.7.2 requires, no prediction is attached
(`H/splits/<split>/draw_d/prediction` = null). This test was declared after
the 11.4 and 11.6 controls had been seen.

Bootstrap runtime: 160.6 s on val_a and 150.1 s on val_b
(`H/timings_seconds`).

---

## Task I. Mechanism localisation (LA7): not run

### I1. The LA6.1 induced label, rebuilt (`I/I1`)

| Quantity | Rebuilt | LA6.1 stored (`lanl_la6_controls.json F1`) |
|---|---:|---:|
| red-team source users, days 0–13 (labelled users) | 86 | 86 |
| labelled users present in the fitting rows (days 0–7) | 76 | 76 |
| labelled users present in the scoring rows (days 8–13) | 85 | 85 |
| labelled users present in both periods | **75** | 75 |
| labelled fitting rows | 532,232 | 532,232 |

All four comparisons in `I/I1/reproduces_LA6_1` are true.

### The blocker (`I/blocker`)

LA7 declares one change from LA6.1: "a frequency map keyed on source user
is added as a model input feature". **That map is already a model input in
LA6.1.**

- The D1 and LA6.1 model inputs (`eval/lanl_d.py FEATURES`, recorded at
  `I/I1/la6_1_model_inputs`) are `hour_sin`, `hour_cos`, `src_freq`,
  **`user_freq`**, `dst_freq`, `fail_rate_30d` and `is_new_src`.
- `user_freq` is the source-user frequency map, in column 3
  (`eval/lanl_la6.py FIELDS`, `I/I1/la6_1_frequency_maps`).
- In LA6.1 the construction (a) source-user map already lacked every
  labelled user present in the fitting rows:
  `lanl_la6_controls.json artefacts/F/user/keys_only_in_c` = **76**, equal to
  the 76 labelled users in the fitting rows.
- LA6.1's perturbation counts, construction (a) against (c)
  (`lanl_la6_controls.json artefacts/F`): 532,232 fitting rows removed,
  **298** source-computer keys dropped, **76** source-user keys dropped and
  **280** destination-computer keys dropped.
- With those keys absent, LA6.1's L lay between −0.190 and 0.077.
- The only other source-user artefact is a known-user set, which would give
  an `is_new_user` feature. That feature would be constant on every fitting
  row, as `is_new_src` is in every LA6 fit
  (`lanl_la6_controls.json fit/*/constant_features_on_fit_rows`), so a forest
  could not split on it.

**Consequences.**
- LA7 as written is the LA6.1 construction unchanged.
- Construction (c) would stay bit-identical to D1, contrary to LA7's
  declared consequence.
- Prediction 3 would hold trivially (76 = 76), and predictions 1 and 2
  would repeat LA6.1.
- Running it would be the retry of LA6.1 that LA7 itself forbids.

**Related finding on 11.8.1.** 11.8.1 says that on the enterprise dataset,
"removing the rows of 86 labelled users changed 33 map entries and dropped
one destination computer". Those figures belong to **LA6.2** (the true
red-team label), not LA6.1:
- LA6.2 removed 50 rows (`lanl_la6_controls.json artefacts/G/rows_removed`).
- Shared keys whose count changed: 3 source computers, 7 source users and 23
  destination computers, 33 in total (`artefacts/G/<field>/shared_keys_count_differs`).
- One destination-computer key was dropped (`artefacts/G/dst/keys_only_in_c`).

LA6.1's own counts are those given above. Per the author, 11.8 is left as
committed, and a correction amendment follows.

**Decision (author, 2026-11-06).** Task I is reported as not run. No LA7
code was written or run. The following are **MISSING**:
- I2: artefacts, constant features, perturbation counts, keys absent from
  the (a) map, and (c) against D1.
- I3: ROC-AUC, PR-AUC, L, intervals and the 11.7.1 flag.
- I4: the verdicts on the LA7 predictions.
- I5: runtimes and the contingency.

Wherever LA7 is mentioned, LA6.1's failure stands as reported in
`eval/LANL_LA6_REPORT.md`.

---

## Task J. Every L computed to date

Built by `python -m eval.amendment11_7_la7 table` from stored JSONs, with no
refit and no rescoring (`J/rows`, 95 rows). L = (AUC_a − AUC_c) / (AUC_a − 0.5).

**Columns.**
- **11.7.1 flag:** set where AUC_c < 0.5, L > 1, or an interval bound on L
  exceeds 1.
- **11.2 domain condition:** the lower bound of the 95% interval on AUC_a,
  or on AUC_a′ for the random-label controls, must exceed 0.55. It can be
  evaluated only where an interval on that AUC is stored.
  - In 11.4 and 11.6 the interval was computed at model seed 42 only, so
    seeds 43 and 44 and every aggregate are "not evaluable".
  - The May month has no stored per-event scores, so no interval exists and
    its rows are not evaluable.
- **"(derived)":** no JSON stores L for the May month. Those values apply the
  formula to stored AUCs in `phase6_s1.json`. They are arithmetic on stored
  values, not a recomputation, and they agree with the untracked
  `eval/FEASIBILITY_AUDIT.md` Task 3.

**J2. Domain condition not satisfied.**
- **Row 17: 11.4 count-matched control, draw 1, val_b, model seed 42.** The
  AUC_a′ interval is [0.5411034175924692, 0.5848314568150381]
  (`amendment11_controls.json control/draws/draw_1/val_b/interval_seed_42/a_prime_roc_auc`).
  Its lower bound is below 0.55, so **L = 1.458019649386749 is not reported as
  a valid share.** The seed 43 and 44 rows and the seed mean for that draw
  and split (rows 18 to 20) rest on the same construction and cannot be
  shown to satisfy the condition.
- **Rows marked "not evaluable"** are not shown to satisfy the condition, so
  they are not valid shares under 11.2 either. Their `valid_share` field in
  the JSON is false.
- Only rows marked "satisfied" are valid shares.

**11.7.1.** Thirty-eight rows are flagged (2 real-label, 18 from 11.4, 18 from 11.6).
- Real label on val_a and val_b: the interval on L crosses 1.
- Every 11.4 draw 1 and draw 3 row, and every 11.6 draw 12 and draw 13 row:
  AUC_c′ < 0.5 and L > 1.
- The over-draws means of both controls: L > 1.

Each flagged figure reads, under 11.7.1, as follows: all of the above-chance
ranking is attributable to the label filter, and in addition the label-free
construction ranks below chance. No value is clamped.

**May, new-attackers stratum** (rows 8 to 12). AUC_a lies between 0.5695
and 0.5745, so the denominator of L is small, and L is negative because (c)
ranks new attackers better than (a). These rows are included because
FEASIBILITY_AUDIT computed them. The domain condition cannot be evaluated
for them.

### J1. The table

| # | Label | Data | Split | Seed / aggregation | L | Interval on L | 11.7.1 flag | 11.2 domain condition | Source: file, JSON path |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | real attack label | RBA | val_a | 42 | 0.9850456188746078 | [0.9359823493364369, 1.032443692081726] | **FLAG**: interval upper bound > 1 | satisfied | `amendment11_6_controls.json` `real/halves/val_a/L (interval: real/halves/val_a/interval/L; domain: real/halves/val_a/interval/domain_condition_ci_low_a_gt_0.55)` |
| 2 | real attack label | RBA | val_b | 42 | 0.975813500712719 | [0.9256319143826766, 1.0272112243266462] | **FLAG**: interval upper bound > 1 | satisfied | `amendment11_6_controls.json` `real/halves/val_b/L (interval: real/halves/val_b/interval/L; domain: real/halves/val_b/interval/domain_condition_ci_low_a_gt_0.55)` |
| 3 | real attack label | RBA | May (all) | 42 | 0.9169410026646949 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_42/all/roc_auc and variants/c/seed_42/all/roc_auc` |
| 4 | real attack label | RBA | May (all) | 43 | 0.9242510085506536 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_43/all/roc_auc and variants/c/seed_43/all/roc_auc` |
| 5 | real attack label | RBA | May (all) | 44 | 0.9200741734370332 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_44/all/roc_auc and variants/c/seed_44/all/roc_auc` |
| 6 | real attack label | RBA | May (all) | mean of per-seed L | 0.920422061550794 (derived) | none | — | not evaluable (no interval) | `phase6_s1.json` `variants/{a,c}/seed_{42,43,44}/all/roc_auc` |
| 7 | real attack label | RBA | May (all) | L of seed-mean AUCs | 0.920386383593064 (derived) | none | — | not evaluable (no interval) | `phase6_s1.json` `variants/a/over_seeds/all/roc_auc/mean and variants/c/over_seeds/all/roc_auc/mean` |
| 8 | real attack label | RBA | May (new_attackers) | 42 | -0.09394098646811898 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_42/new_attackers/roc_auc and variants/c/seed_42/new_attackers/roc_auc` |
| 9 | real attack label | RBA | May (new_attackers) | 43 | -0.16072593865473445 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_43/new_attackers/roc_auc and variants/c/seed_43/new_attackers/roc_auc` |
| 10 | real attack label | RBA | May (new_attackers) | 44 | -0.07942305778577823 (derived) | none | — | not evaluable (no interval: no stored May per-event scores) | `phase6_s1.json` `variants/a/seed_44/new_attackers/roc_auc and variants/c/seed_44/new_attackers/roc_auc` |
| 11 | real attack label | RBA | May (new_attackers) | mean of per-seed L | -0.11136332763621055 (derived) | none | — | not evaluable (no interval) | `phase6_s1.json` `variants/{a,c}/seed_{42,43,44}/new_attackers/roc_auc` |
| 12 | real attack label | RBA | May (new_attackers) | L of seed-mean AUCs | -0.1104323227637876 (derived) | none | — | not evaluable (no interval) | `phase6_s1.json` `variants/a/over_seeds/new_attackers/roc_auc/mean and variants/c/over_seeds/new_attackers/roc_auc/mean` |
| 13 | 11.4 count-matched random | RBA | val_a | 42 (draw_1) | 1.2962087500264936 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_controls.json` `control/draws/draw_1/val_a/per_model_seed/seed_42/L (domain: control/draws/draw_1/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 14 | 11.4 count-matched random | RBA | val_a | 43 (draw_1) | 1.3043578863901304 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_1/val_a/per_model_seed/seed_43/L` |
| 15 | 11.4 count-matched random | RBA | val_a | 44 (draw_1) | 1.2606302698328287 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_1/val_a/per_model_seed/seed_44/L` |
| 16 | 11.4 count-matched random | RBA | val_a | mean over seeds (draw_1) | 1.2870656354164842 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_1/val_a/L_mean_over_model_seeds` |
| 17 | 11.4 count-matched random | RBA | val_b | 42 (draw_1) | 1.458019649386749 | none | **FLAG**: AUC_c < 0.5; L > 1 | **NOT SATISFIED: not a valid share** | `amendment11_controls.json` `control/draws/draw_1/val_b/per_model_seed/seed_42/L (domain: control/draws/draw_1/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 18 | 11.4 count-matched random | RBA | val_b | 43 (draw_1) | 1.480000252488919 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_1/val_b/per_model_seed/seed_43/L` |
| 19 | 11.4 count-matched random | RBA | val_b | 44 (draw_1) | 1.397571572661307 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_1/val_b/per_model_seed/seed_44/L` |
| 20 | 11.4 count-matched random | RBA | val_b | mean over seeds (draw_1) | 1.4451971581789917 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_1/val_b/L_mean_over_model_seeds` |
| 21 | 11.4 count-matched random | RBA | val_a | 42 (draw_2) | 0.9023681619444642 | none | — | satisfied | `amendment11_controls.json` `control/draws/draw_2/val_a/per_model_seed/seed_42/L (domain: control/draws/draw_2/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 22 | 11.4 count-matched random | RBA | val_a | 43 (draw_2) | 0.9228227317401753 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_2/val_a/per_model_seed/seed_43/L` |
| 23 | 11.4 count-matched random | RBA | val_a | 44 (draw_2) | 0.910625887939627 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_2/val_a/per_model_seed/seed_44/L` |
| 24 | 11.4 count-matched random | RBA | val_a | mean over seeds (draw_2) | 0.9119389272080888 | none | — | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_2/val_a/L_mean_over_model_seeds` |
| 25 | 11.4 count-matched random | RBA | val_b | 42 (draw_2) | 0.9078699344832453 | none | — | satisfied | `amendment11_controls.json` `control/draws/draw_2/val_b/per_model_seed/seed_42/L (domain: control/draws/draw_2/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 26 | 11.4 count-matched random | RBA | val_b | 43 (draw_2) | 0.9425931886822608 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_2/val_b/per_model_seed/seed_43/L` |
| 27 | 11.4 count-matched random | RBA | val_b | 44 (draw_2) | 0.9179116217928338 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_2/val_b/per_model_seed/seed_44/L` |
| 28 | 11.4 count-matched random | RBA | val_b | mean over seeds (draw_2) | 0.92279158165278 | none | — | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_2/val_b/L_mean_over_model_seeds` |
| 29 | 11.4 count-matched random | RBA | val_a | 42 (draw_3) | 1.2872560280147447 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_controls.json` `control/draws/draw_3/val_a/per_model_seed/seed_42/L (domain: control/draws/draw_3/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 30 | 11.4 count-matched random | RBA | val_a | 43 (draw_3) | 1.297078784841013 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_3/val_a/per_model_seed/seed_43/L` |
| 31 | 11.4 count-matched random | RBA | val_a | 44 (draw_3) | 1.2714952760872544 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_3/val_a/per_model_seed/seed_44/L` |
| 32 | 11.4 count-matched random | RBA | val_a | mean over seeds (draw_3) | 1.2852766963143374 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_3/val_a/L_mean_over_model_seeds` |
| 33 | 11.4 count-matched random | RBA | val_b | 42 (draw_3) | 1.4040103413364822 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_controls.json` `control/draws/draw_3/val_b/per_model_seed/seed_42/L (domain: control/draws/draw_3/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 34 | 11.4 count-matched random | RBA | val_b | 43 (draw_3) | 1.4323987642712728 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_3/val_b/per_model_seed/seed_43/L` |
| 35 | 11.4 count-matched random | RBA | val_b | 44 (draw_3) | 1.3840471739533953 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_controls.json` `control/draws/draw_3/val_b/per_model_seed/seed_44/L` |
| 36 | 11.4 count-matched random | RBA | val_b | mean over seeds (draw_3) | 1.406818759853717 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/draws/draw_3/val_b/L_mean_over_model_seeds` |
| 37 | 11.4 count-matched random | RBA | val_a | mean over draws and seeds | 1.16142708631297 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/over_draws/val_a/L_mean_over_draws` |
| 38 | 11.4 count-matched random | RBA | val_b | mean over draws and seeds | 1.2582691665618295 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_controls.json` `control/over_draws/val_b/L_mean_over_draws` |
| 39 | 11.6 distribution-matched random | RBA | val_a | 42 (draw_11) | 0.9635277296009894 | none | — | satisfied | `amendment11_6_controls.json` `draws/draw_11/val_a/per_model_seed/seed_42/L (domain: draws/draw_11/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 40 | 11.6 distribution-matched random | RBA | val_a | 43 (draw_11) | 0.9812581212839637 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_11/val_a/per_model_seed/seed_43/L` |
| 41 | 11.6 distribution-matched random | RBA | val_a | 44 (draw_11) | 0.9672735822569023 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_11/val_a/per_model_seed/seed_44/L` |
| 42 | 11.6 distribution-matched random | RBA | val_a | mean over seeds (draw_11) | 0.9706864777139518 | none | — | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_11/val_a/L_mean_over_model_seeds` |
| 43 | 11.6 distribution-matched random | RBA | val_b | 42 (draw_11) | 0.9444069835053107 | none | — | satisfied | `amendment11_6_controls.json` `draws/draw_11/val_b/per_model_seed/seed_42/L (domain: draws/draw_11/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 44 | 11.6 distribution-matched random | RBA | val_b | 43 (draw_11) | 0.9607871308935699 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_11/val_b/per_model_seed/seed_43/L` |
| 45 | 11.6 distribution-matched random | RBA | val_b | 44 (draw_11) | 0.9472783565970532 | none | — | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_11/val_b/per_model_seed/seed_44/L` |
| 46 | 11.6 distribution-matched random | RBA | val_b | mean over seeds (draw_11) | 0.9508241569986446 | none | — | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_11/val_b/L_mean_over_model_seeds` |
| 47 | 11.6 distribution-matched random | RBA | val_a | 42 (draw_12) | 1.13572823998943 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_6_controls.json` `draws/draw_12/val_a/per_model_seed/seed_42/L (domain: draws/draw_12/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 48 | 11.6 distribution-matched random | RBA | val_a | 43 (draw_12) | 1.1648921923423856 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_12/val_a/per_model_seed/seed_43/L` |
| 49 | 11.6 distribution-matched random | RBA | val_a | 44 (draw_12) | 1.1463729718232671 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_12/val_a/per_model_seed/seed_44/L` |
| 50 | 11.6 distribution-matched random | RBA | val_a | mean over seeds (draw_12) | 1.1489978013850275 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_12/val_a/L_mean_over_model_seeds` |
| 51 | 11.6 distribution-matched random | RBA | val_b | 42 (draw_12) | 1.1238889660164142 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_6_controls.json` `draws/draw_12/val_b/per_model_seed/seed_42/L (domain: draws/draw_12/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 52 | 11.6 distribution-matched random | RBA | val_b | 43 (draw_12) | 1.1535024245980936 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_12/val_b/per_model_seed/seed_43/L` |
| 53 | 11.6 distribution-matched random | RBA | val_b | 44 (draw_12) | 1.1326032012910319 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_12/val_b/per_model_seed/seed_44/L` |
| 54 | 11.6 distribution-matched random | RBA | val_b | mean over seeds (draw_12) | 1.136664863968513 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_12/val_b/L_mean_over_model_seeds` |
| 55 | 11.6 distribution-matched random | RBA | val_a | 42 (draw_13) | 1.175271220993033 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_6_controls.json` `draws/draw_13/val_a/per_model_seed/seed_42/L (domain: draws/draw_13/val_a/interval_seed_42/a_prime_roc_auc/low)` |
| 56 | 11.6 distribution-matched random | RBA | val_a | 43 (draw_13) | 1.1893504179341488 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_13/val_a/per_model_seed/seed_43/L` |
| 57 | 11.6 distribution-matched random | RBA | val_a | 44 (draw_13) | 1.1730436275488956 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_13/val_a/per_model_seed/seed_44/L` |
| 58 | 11.6 distribution-matched random | RBA | val_a | mean over seeds (draw_13) | 1.1792217554920257 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_13/val_a/L_mean_over_model_seeds` |
| 59 | 11.6 distribution-matched random | RBA | val_b | 42 (draw_13) | 1.1346184969083095 | none | **FLAG**: AUC_c < 0.5; L > 1 | satisfied | `amendment11_6_controls.json` `draws/draw_13/val_b/per_model_seed/seed_42/L (domain: draws/draw_13/val_b/interval_seed_42/a_prime_roc_auc/low)` |
| 60 | 11.6 distribution-matched random | RBA | val_b | 43 (draw_13) | 1.150312505672614 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_13/val_b/per_model_seed/seed_43/L` |
| 61 | 11.6 distribution-matched random | RBA | val_b | 44 (draw_13) | 1.1325612154664795 | none | **FLAG**: AUC_c < 0.5; L > 1 | not evaluable (interval computed at model seed 42 only) | `amendment11_6_controls.json` `draws/draw_13/val_b/per_model_seed/seed_44/L` |
| 62 | 11.6 distribution-matched random | RBA | val_b | mean over seeds (draw_13) | 1.1391640726824674 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `draws/draw_13/val_b/L_mean_over_model_seeds` |
| 63 | 11.6 distribution-matched random | RBA | val_a | mean over draws and seeds | 1.0996353448636684 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `over_draws/val_a/L_mean_over_draws` |
| 64 | 11.6 distribution-matched random | RBA | val_b | mean over draws and seeds | 1.0755510312165415 | none | **FLAG**: L > 1 | not evaluable (no interval on the aggregate) | `amendment11_6_controls.json` `over_draws/val_b/L_mean_over_draws` |
| 65 | LA6.1 induced source-user | LANL | days_8_11 | 42 | -0.10555849278790352 | [-0.4741668999948444, 0.7712688141994961] | — | satisfied | `lanl_la6_controls.json` `F/days_8_11/per_seed/seed_42/L (interval: .../L_ci95)` |
| 66 | LA6.1 induced source-user | LANL | days_8_11 | 43 | -0.1131463428954832 | [-0.4750747453381666, 0.7634767125566603] | — | satisfied | `lanl_la6_controls.json` `F/days_8_11/per_seed/seed_43/L (interval: .../L_ci95)` |
| 67 | LA6.1 induced source-user | LANL | days_8_11 | 44 | -0.189817748320177 | [-0.5770989431098822, 0.7155193463037424] | — | satisfied | `lanl_la6_controls.json` `F/days_8_11/per_seed/seed_44/L (interval: .../L_ci95)` |
| 68 | LA6.1 induced source-user | LANL | days_8_11 | L_mean_over_seeds | -0.13617419466785458 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_8_11/L_mean_over_seeds` |
| 69 | LA6.1 induced source-user | LANL | days_8_11 | L_of_seed_mean_aucs_secondary | -0.13509947682099613 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_8_11/L_of_seed_mean_aucs_secondary` |
| 70 | LA6.1 induced source-user | LANL | days_12_13 | 42 | 0.07738531621955692 | [-0.3057087118976807, 0.6854235964674588] | — | satisfied | `lanl_la6_controls.json` `F/days_12_13/per_seed/seed_42/L (interval: .../L_ci95)` |
| 71 | LA6.1 induced source-user | LANL | days_12_13 | 43 | 0.0650501690080084 | [-0.3077157251225034, 0.6560226412097464] | — | satisfied | `lanl_la6_controls.json` `F/days_12_13/per_seed/seed_43/L (interval: .../L_ci95)` |
| 72 | LA6.1 induced source-user | LANL | days_12_13 | 44 | 0.007919480751991075 | [-0.42407384359369976, 0.6430956860029995] | — | satisfied | `lanl_la6_controls.json` `F/days_12_13/per_seed/seed_44/L (interval: .../L_ci95)` |
| 73 | LA6.1 induced source-user | LANL | days_12_13 | L_mean_over_seeds | 0.05011832199318547 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_12_13/L_mean_over_seeds` |
| 74 | LA6.1 induced source-user | LANL | days_12_13 | L_of_seed_mean_aucs_secondary | 0.051000780463905215 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_12_13/L_of_seed_mean_aucs_secondary` |
| 75 | LA6.1 induced source-user | LANL | days_8_13 | 42 | -0.020499643143061675 | [-0.3796878674665268, 0.7345349686614857] | — | satisfied | `lanl_la6_controls.json` `F/days_8_13/per_seed/seed_42/L (interval: .../L_ci95)` |
| 76 | LA6.1 induced source-user | LANL | days_8_13 | 43 | -0.029950886923501955 | [-0.3920524850499637, 0.7248173557538563] | — | satisfied | `lanl_la6_controls.json` `F/days_8_13/per_seed/seed_43/L (interval: .../L_ci95)` |
| 77 | LA6.1 induced source-user | LANL | days_8_13 | 44 | -0.09733808910015163 | [-0.5033902051250276, 0.6854359521564759] | — | satisfied | `lanl_la6_controls.json` `F/days_8_13/per_seed/seed_44/L (interval: .../L_ci95)` |
| 78 | LA6.1 induced source-user | LANL | days_8_13 | L_mean_over_seeds | -0.049262873055571754 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_8_13/L_mean_over_seeds` |
| 79 | LA6.1 induced source-user | LANL | days_8_13 | L_of_seed_mean_aucs_secondary | -0.04829073617499084 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `F/days_8_13/L_of_seed_mean_aucs_secondary` |
| 80 | LA6.2 true red-team label | LANL | days_8_11 | 42 | 0.00037328429165495213 | [-0.0026093285021603807, 0.0030537573112912175] | — | satisfied | `lanl_la6_controls.json` `G/days_8_11/per_seed/seed_42/L (interval: .../L_ci95)` |
| 81 | LA6.2 true red-team label | LANL | days_8_11 | 43 | 0.004140245177475023 | [0.001712803383447431, 0.00733244724253113] | — | satisfied | `lanl_la6_controls.json` `G/days_8_11/per_seed/seed_43/L (interval: .../L_ci95)` |
| 82 | LA6.2 true red-team label | LANL | days_8_11 | 44 | -0.0007224927773274426 | [-0.0037486809854104107, 0.002449546813112324] | — | satisfied | `lanl_la6_controls.json` `G/days_8_11/per_seed/seed_44/L (interval: .../L_ci95)` |
| 83 | LA6.2 true red-team label | LANL | days_8_11 | L_mean_over_seeds | 0.0012636788972675108 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_8_11/L_mean_over_seeds` |
| 84 | LA6.2 true red-team label | LANL | days_8_11 | L_of_seed_mean_aucs_secondary | 0.00125693777091653 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_8_11/L_of_seed_mean_aucs_secondary` |
| 85 | LA6.2 true red-team label | LANL | days_12_13 | 42 | -0.002167483635620607 | [-0.007929467554970412, 0.0008139473571752499] | — | satisfied | `lanl_la6_controls.json` `G/days_12_13/per_seed/seed_42/L (interval: .../L_ci95)` |
| 86 | LA6.2 true red-team label | LANL | days_12_13 | 43 | 0.0009836099181308791 | [-0.001099346756450291, 0.0033500099939728005] | — | satisfied | `lanl_la6_controls.json` `G/days_12_13/per_seed/seed_43/L (interval: .../L_ci95)` |
| 87 | LA6.2 true red-team label | LANL | days_12_13 | 44 | 0.00018877195711851304 | [-0.001556376917770082, 0.0018260177704089897] | — | satisfied | `lanl_la6_controls.json` `G/days_12_13/per_seed/seed_44/L (interval: .../L_ci95)` |
| 88 | LA6.2 true red-team label | LANL | days_12_13 | L_mean_over_seeds | -0.00033170058679040493 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_12_13/L_mean_over_seeds` |
| 89 | LA6.2 true red-team label | LANL | days_12_13 | L_of_seed_mean_aucs_secondary | -0.0003359389744883592 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_12_13/L_of_seed_mean_aucs_secondary` |
| 90 | LA6.2 true red-team label | LANL | days_8_13 | 42 | 7.743998606618128e-05 | [-0.0027509274978141287, 0.002671176039960858] | — | satisfied | `lanl_la6_controls.json` `G/days_8_13/per_seed/seed_42/L (interval: .../L_ci95)` |
| 91 | LA6.2 true red-team label | LANL | days_8_13 | 43 | 0.0031479644125657104 | [0.0012221402312955715, 0.005690816297243302] | — | satisfied | `lanl_la6_controls.json` `G/days_8_13/per_seed/seed_43/L (interval: .../L_ci95)` |
| 92 | LA6.2 true red-team label | LANL | days_8_13 | 44 | -0.0003558004183614646 | [-0.002109860049895978, 0.0010395980626263675] | — | satisfied | `lanl_la6_controls.json` `G/days_8_13/per_seed/seed_44/L (interval: .../L_ci95)` |
| 93 | LA6.2 true red-team label | LANL | days_8_13 | L_mean_over_seeds | 0.0009565346600901424 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_8_13/L_mean_over_seeds` |
| 94 | LA6.2 true red-team label | LANL | days_8_13 | L_of_seed_mean_aucs_secondary | 0.0009516515750652478 | none | — | not evaluable (no interval on the aggregate) | `lanl_la6_controls.json` `G/days_8_13/L_of_seed_mean_aucs_secondary` |
| 95 | LA7 | LANL | days 8–11, 12–13, 8–13 | 42, 43, 44 | **MISSING** | **MISSING** | — | — | Task I not run |
