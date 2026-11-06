# Amendment 11 controls: random persistent entity label (11.4)

Written 2026-11-06. Governed by `eval/PROTOCOL.md` amendment 11, committed
on its own as `eb0b243` before any code. Development data only: the
stream is `datasets.load("dev")`, which opens only the February, March and April
2020 partitions. `data/rba_locked/`, the Phase 6 May cache and every month
from June 2020 onward were not read.

Script: `eval/amendment11_controls.py` (stage `control`). Values:
`results/amendment11_controls.json`, key `control`. Per-event scores:
`results/amendment11_cache/` (gitignored). The full run took 4,785.1 s.
JSON paths below are relative to `results/amendment11_controls.json` unless
another file is named.

## STOP CONDITION TRIGGERED

**Prediction 2 failed.** Construction (c') did not score the random label at
chance on draw 1 or draw 3, on either split. The bootstrap intervals for AUC_c'
lie wholly **below** 0.50. The prompt words the stop condition as "(c') ranks
the random label above chance", but amendment 11.4 states prediction 2 as "the
interval on AUC_c' contains 0.50", and the amendment governs. That
prediction failed, so I stopped as instructed. **Task B was not run.** Nothing
was run after Task A finished.

One check bears on the "fault in the rebuild" reading. Using the same code
path, the rebuilt real construction (a), seed 42, is **bit-identical** to the
cached Phase 3 decisions on all 2,337,227 val events. The rebuilt (c') is
bit-identical to the stored `score_p2var_c.npy`, seed 42 (details in A3). So
the rebuild reproduces the existing constructions exactly. Whether the result
below chance is a fault or a real property of the data is still to be resolved,
and it is not interpreted here.

---

## Freeze manifest

| When | Command (from `backend/`) | Output | Exit |
|---|---|---|---|
| Before any work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
| After all work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

HEAD before: `07c1ae3`. Tags were not moved: `v3.0.0` = 97a37f9…, and
`v3.0.0-frozen` = bb40c16….

---

## Task A

### A1. dev_train source addresses

| Quantity | Value | JSON path |
|---|---:|---|
| dev_train rows | 4,055,357 | `control/A1/dev_train_rows` |
| distinct source addresses | 947,226 | `control/A1/distinct_addresses` |
| A: addresses with at least one attack-labelled row | 22,095 | `control/A1/A_attack_labelled_addresses` |
| N: addresses with no attack-labelled row | 925,131 | `control/A1/N_no_attack_labelled_row` |
| A / (A + N) | 0.02332600667633701 | `control/A1/share_A` |

Label: `Is Attack IP | Is Account Takeover` (`Stream.truth`), the same label as
every earlier phase. The values match `results/amendment10_lookup.json`
`dev_train_attack_ips` (22,095) and `results/phase2_data_audit.json`
`splits/dev_train/ips` (947,226).

### A2. The three induced labels

N was ordered by address string. For each sampling seed d in {1, 2, 3}, S was
drawn as `numpy.random.Generator(PCG64(d)).choice(N, 22095, replace=False)`.
The induced label is 1 on every row of every address in S, across dev_train,
val_a and val_b, and 0 elsewhere. The amendment does not fix the order of N.
Address-string order is the choice I made.

| Draw | \|S\| | S ∩ A | S ⊆ N | Induced rows dev_train / val_a / val_b | S addresses seen in val_a / val_b |
|---|---:|---:|---|---|---|
| 1 | 22,095 | **0** | yes | 85,859 / 15,141 / 14,070 | 3,622 / 3,404 |
| 2 | 22,095 | **0** | yes | 87,413 / 16,435 / 15,724 | 3,628 / 3,380 |
| 3 | 22,095 | **0** | yes | 85,796 / 15,734 / 14,375 | 3,706 / 3,466 |

Source: `control/A2/draw_d/…`.

### A3. Constructions, fitted artefacts, constant features

Every construction calls the existing code: `phase4b.frame`, `phase4b.prepare`
(which calls `ml/train_from_dataset.fit_frequency_maps` and
`extract_features_freq`, plus a `StandardScaler`), `phase3_rules.raw_features`
with the 30-day windowed `failed_rate`, and `phase2_baseline.fit_forest`
(IsolationForest, `n_estimators=200, max_samples=100000, max_features=1.0`,
contamination 0.4). This is the same code as `phase6_secondary.stage_s1`.
The only change is that the induced label replaces `Stream.truth` when the
label-selected rows are chosen. The constructions were fitted on dev_train only,
with model seeds 42, 43 and 44.

- **(a')**: maps, known sets, scaler and forest all fitted on dev_train rows
  whose induced label is 0.
- **(c')**: everything fitted on all dev_train rows. (c') reads no label, so it
  is the same for every draw and is identical to the real construction (c).

Fitted artefacts (sizes):

| Construction | map / fit rows | ip map | user map | country map | device map | known IPs | known countries |
|---|---|---:|---:|---:|---:|---:|---:|
| real (a), seed 42 (check) | 3,672,966 / 3,672,966 | 925,137 | 985,535 | 218 | 6 | 925,137 | 218 |
| (c') | 4,055,357 / 4,055,357 | 947,226 | 1,061,753 | 218 | 6 | 947,226 | 218 |
| (a') draw 1 | 3,969,498 / 3,969,498 | 925,131 | 1,044,550 | 218 | 6 | 925,131 | 218 |
| (a') draw 2 | 3,967,944 / 3,967,944 | 925,131 | 1,044,388 | 218 | 6 | 925,131 | 218 |
| (a') draw 3 | 3,969,561 / 3,969,561 | 925,131 | 1,044,571 | 218 | 6 | 925,131 | 218 |

Each construction also fits a StandardScaler and an IsolationForest on its
fit rows. Sources: `control/real_construction_a_seed42`,
`control/construction_c_prime`, `control/draws/draw_d/construction_a_prime`.

**Constant on every fitted row** (zero variance in the scaler): `is_new_ip`
and `is_new_country`, in every construction, real (a), (c') and all three
(a'). Source: `…/constant_features_on_fit_rows`.

**Code-path checks** (seed 42, on the 2,337,227 val events):
- real (a) refit against `results/phase3_cache/ml_decision_v3.npy`:
  `bit_identical: true`, `max_abs_diff: 0.0`.
- (c') against `results/phase4_cache/score_p2var_c.npy`:
  `bit_identical: true`, `max_abs_diff: 0.0`.

### A4. Scores against the induced label

Event counts: val_a has 1,183,517 events and val_b has 1,153,710.
L = (AUC_a' − AUC_c') / (AUC_a' − 0.5).

**val_a**

| Draw | Base rate | Seed | ROC (a') | PR (a') | ROC (c') | PR (c') | L |
|---|---|---|---|---|---|---|---|
| 1 | 0.01279322561484119 | 42 | 0.5874744418789176 | 0.015968014578986812 | 0.47408930491178064 | 0.011434145576532065 | 1.2962087500264936 |
| | | 43 | 0.5874451973420401 | 0.015694818528688478 | 0.4733853645620088 | 0.011416550758293289 | 1.3043578863901304 |
| | | 44 | 0.5979441006631171 | 0.016060026997958526 | 0.47447280261563807 | 0.01143160241965994 | 1.2606302698328287 |
| | | **L seed mean** | | | | | **1.2870656354164842** |
| 2 | 0.013886577041140939 | 42 | 0.6078185018929992 | 0.018624866278607884 | 0.5105265185162078 | 0.014509736988748773 | 0.9023681619444642 |
| | | 43 | 0.6122692900492099 | 0.018431952181460935 | 0.5086646371154679 | 0.014380417081564581 | 0.9228227317401753 |
| | | 44 | 0.6125511944372168 | 0.018618715375682323 | 0.5100591630641607 | 0.014450576352447345 | 0.910625887939627 |
| | | **L seed mean** | | | | | **0.9119389272080888** |
| 3 | 0.013294274606955371 | 42 | 0.5961977213132982 | 0.0167693686199507 | 0.4723666246714726 | 0.011909028145175731 | 1.2872560280147447 |
| | | 43 | 0.5949357080567296 | 0.016580571749529007 | 0.4717966152124856 | 0.011896633768480262 | 1.297078784841013 |
| | | 44 | 0.60165939262106 | 0.016920080240674328 | 0.4723999551334827 | 0.011898094134105522 | 1.2714952760872544 |
| | | **L seed mean** | | | | | **1.2852766963143374** |

Secondary figure, the mean of the per-draw values of L on val_a:
**1.16142708631297** (`control/over_draws/val_a`).

**val_b**

| Draw | Base rate | Seed | ROC (a') | PR (a') | ROC (c') | PR (c') | L |
|---|---|---|---|---|---|---|---|
| 1 | 0.012195439061809293 | 42 | 0.564026723504027 | 0.014247135167933715 | 0.4706745025493032 | 0.010865164167128651 | 1.458019649386749 |
| | | 43 | 0.5635628249991388 | 0.014001164863459429 | 0.4694898279515044 | 0.010848054794609902 | 1.480000252488919 |
| | | 44 | 0.5733614109726343 | 0.014265638017986583 | 0.47083358846695733 | 0.010854941656210926 | 1.397571572661307 |
| | | **L seed mean** | | | | | **1.4451971581789917** |
| 2 | 0.013629074897504572 | 42 | 0.5852971678567181 | 0.016814531117309472 | 0.5078584336630331 | 0.013900710308140937 | 0.9078699344832453 |
| | | 43 | 0.5897217773281311 | 0.016676877080042302 | 0.5051506411421682 | 0.013745220495081596 | 0.9425931886822608 |
| | | 44 | 0.5897449093068836 | 0.016825286517880997 | 0.5073670140573513 | 0.013864837697817298 | 0.9179116217928338 |
| | | **L seed mean** | | | | | **0.92279158165278** |
| 3 | 0.012459803590156972 | 42 | 0.5716816951154383 | 0.014524596190225201 | 0.4710398538888341 | 0.011156541954371685 | 1.4040103413364822 |
| | | 43 | 0.5702816476048862 | 0.014362382806953658 | 0.46961030242469814 | 0.011125347306548131 | 1.4323987642712728 |
| | | 44 | 0.5767721961991177 | 0.014635477304755597 | 0.47051585501153326 | 0.0111248234228618 | 1.3840471739533953 |
| | | **L seed mean** | | | | | **1.406818759853717** |

Secondary figure, the mean of the per-draw values of L on val_b:
**1.2582691665618295** (`control/over_draws/val_b`).

Sources: `control/draws/draw_d/{val_a,val_b}/per_model_seed/seed_s/…`,
`…/L_mean_over_model_seeds` and `…/induced_label_event_base_rate`.

On draws 1 and 3, L is above 1 because AUC_c' < 0.5.

### A5. Intervals (model seed 42)

These are 95% percentile bootstrap intervals. Each of 1,000 resamples draws
source addresses with replacement, using `numpy Generator(PCG64(42))`. A
resample weights each event by its address's multiplicity. Both AUCs are
recomputed with ties averaged, on the same resamples. All 1,000 resamples
were valid in every case. The resamples are drawn from the addresses present
in each split: 348,248 in val_a and 345,496 in val_b.

| Split | Draw | AUC_a' 95% CI | AUC_c' 95% CI |
|---|---|---|---|
| val_a | 1 | [0.5642238351884369, 0.6092443878579016] | [0.4563070789033931, 0.4918771817363136] |
| val_a | 2 | [0.5736562949805777, 0.6395766879204565] | [0.4661351838090999, 0.5599153889623294] |
| val_a | 3 | [0.5746500327031364, 0.6159346619636497] | [0.454093270689435, 0.4928770447795384] |
| val_b | 1 | [0.5411034175924692, 0.5848314568150381] | [0.45495221254364865, 0.48828511329483987] |
| val_b | 2 | [0.5559721055929253, 0.6122071997117015] | [0.4675973685071122, 0.5490728825764527] |
| val_b | 3 | [0.5507893719984853, 0.5916589813570511] | [0.4542416564477419, 0.4893492092673473] |

Source: `control/draws/draw_d/{h}/interval_seed_42`.

### A6. Entity-lookup reference on the induced label

The lookup scores an event 1 if its address appears in any induced-label
dev_train row, which means it is in S. On every draw and both splits:
ROC-AUC 1.0, PR-AUC 1.0, precision of the score-1 set 1.0 and recall 1.0.
The flagged events equal the induced-label events: 15,141, 16,435 and 15,734
on val_a, and 14,070, 15,724 and 14,375 on val_b.
This holds by construction: the induced label is membership in S, on every
row. Source: `control/draws/draw_d/{h}/entity_lookup_reference`.

### A7. Fit-time absence count

Both figures come from the same code path, `phase4b.prepare` →
`fit_frequency_maps` → `len(known_ips_set)`:

| Label | Known IPs, all dev_train rows | Known IPs, label-0 rows | Difference |
|---|---:|---:|---:|
| real (`Stream.truth`) | 947,226 | 925,137 | **22,089** |
| induced, draw 1 / 2 / 3 | 947,226 | 925,131 | **22,095** each |

Sources: `control/real_label_fit_time_absence_count` and
`control/draws/draw_d/fit_time_absence_count`.

**Verifying the real-label derivation.** `PHASE4B_REPORT.md` is not in the
repository. It is at `C:\Users\Dell\audit_scratch\PHASE4B_REPORT.md`, which
records known IPs of 925,137 for (a) and 947,226 for (b) and (c) (lines 58–60).
Line 67 says "The maps differ by only 22,089 IPs". The same counts are stored
in `results/phase4b_diag.json` at `variants/a/build/known_ips` (925,137) and
`variants/c/build/known_ips` (947,226). This rerun reproduces both:
947,226 − 925,137 = 22,089. **Verified.**

The induced-label difference equals |S| = 22,095 because every row of an
address in S carries the induced label. The real-label difference is 6 lower
than `dev_train_attack_ips` (22,095). So 6 attack-labelled addresses also
have unlabelled dev_train rows: the real label is almost entirely persistent
per address, and the induced label is fully persistent.

### A8. The declared predictions

Each prediction holds only if it holds for all three draws on both splits.

| Prediction | val_a d1 | val_a d2 | val_a d3 | val_b d1 | val_b d2 | val_b d3 | Overall |
|---|---|---|---|---|---|---|---|
| 1. lower bound of AUC_a' CI > 0.60 | fail (0.5642) | fail (0.5737) | fail (0.5747) | fail (0.5411) | fail (0.5560) | fail (0.5508) | **FAILED** |
| 2. AUC_c' CI contains 0.50 | fail ([0.4563, 0.4919]) | held | fail ([0.4541, 0.4929]) | fail ([0.4550, 0.4883]) | held | fail ([0.4542, 0.4893]) | **FAILED** |
| 3. L seed mean > 0.85 | held (1.287) | held (0.912) | held (1.285) | held (1.445) | held (0.923) | held (1.407) | held |

The figures in brackets are rounded from the full values above. Source:
`control/predictions`.

- **Prediction 1 failed** on all six draw-split pairs.
- **Prediction 2 failed** on four of six: draws 1 and 3 on both splits, where
  (c') ranks the random label **below** chance.
- **Prediction 3 held** on all six. On draws 1 and 3 it holds only because
  AUC_c' is below 0.5, which pushes L above 1.

Amendment 11.4 states that a failed prediction is "reported as a failure,
and the scope condition in 11.1 is revised or withdrawn rather than restated."
This report does not make that revision.

---

## Task B: NOT RUN (stop condition)

Under the stop condition, no part of Task B was executed: no bootstrap on the
real label, no shares and no L for val_b. Before the stop, while I was
reading the code to write Task A, I observed the facts below. They are
recorded here and were not used to compute anything:

- **B1 (whether per-event scores exist).** Dev per-event scores exist for
  seed 42 only, covering all 6,392,584 dev events:
  - (a): `results/phase3_cache/ml_decision_v3.npy` (51,140,800 bytes),
  - (b): `results/phase4_cache/score_p2var_b.npy`,
  - (c): `results/phase4_cache/score_p2var_c.npy`.

  This run also saved the label-free (c), equal to (c'), on the val rows for
  seeds 42, 43 and 44 in `results/amendment11_cache/c_seed{42,43,44}_val.npy`.

  For May, `eval/phase6_secondary.stage_s1` writes only `save_json`
  summaries and no per-event scores. No file in `results/phase6_cache/` is
  named for S1; its files are `deployed*.npz`, `email_log*.json`, `store_day*`,
  `test_2020-05.parquet` and `X_v4*.npy`. No May file was opened. As far as
  file names and code show, May per-event scores for (a), (b) and (c) were
  not saved.
- **B3.** `results/phase4b_confirm.json` `d1_c_val_b/roc_auc` =
  0.506056815350325. I read it during inspection, before the stop. The val_b
  shares and L were **not computed**.
- **Refit cost** (measured in this run, on dev): about 280–300 s per forest
  seed, covering the fit and scoring 2.34M events, plus about 60 s for maps and
  features per construction. A May refit would need the locked month and is
  outside this amendment.

## Files

- Commit `eb0b243`: `backend/eval/PROTOCOL.md` (amendment 11, declaration only).
- Commit `96e8b50`: `backend/eval/amendment11_controls.py` and one `.gitignore`
  line for `backend/results/amendment11_cache/`.
- Written but not committed: `backend/eval/AMENDMENT11_CONTROLS.md` (this
  file) and `backend/results/amendment11_controls.json`.
