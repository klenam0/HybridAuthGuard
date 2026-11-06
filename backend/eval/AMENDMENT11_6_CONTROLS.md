# Amendment 11.6 controls, the real-label interval, and 11.4 point values

Written 2026-11-06. Governed by `eval/PROTOCOL.md` amendments 11.1 to 11.6.
Amendment 11.6 was committed on its own as `80155c3` before any of the code
below. Development data only: the stream is `datasets.load("dev")`, which
opens only the February, March and April 2020 partitions. `data/rba_locked/`,
the Phase 6 May cache and every month from June 2020 onward were not read.

Script: `eval/amendment11_controls.py`. Stages `matched` (Task C), `real`
(Task D) and `prev` (Task E). Values: `results/amendment11_6_controls.json`.
Per-event scores: `results/amendment11_cache/` (gitignored). JSON paths below
are relative to `results/amendment11_6_controls.json` unless another file is
named. Run times: Task C 3,988.6 s, Task D 372.6 s.

## Freeze manifest

| When | Command (from `backend/`) | Output | Exit |
|---|---|---|---|
| Before any work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
| After all work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

Tags were not moved: `v3.0.0` = 97a37f9…, `v3.0.0-frozen` = bb40c16….

## Step 0 commits

| Step | Commit | Content |
|---|---|---|
| 0a | `51b9387` | `eval/AMENDMENT11_CONTROLS.md` and `results/amendment11_controls.json` (the 11.4 run) |
| 0b | `454f2ec` | `eval/PHASE4B_REPORT.md`, copied byte for byte from `C:\Users\Dell\audit_scratch\PHASE4B_REPORT.md` |
| 0c | `80155c3` | `eval/PROTOCOL.md`, amendment 11.6 appended (no code) |

0b check. The source file's modification time is 2026-10-14 00:25:34 UTC, so
it was last changed before this session. Its SHA-256 is
`16d7647cdc5ef0bbd93cfaeda6b82f7709a2e40bd38add58c8701b90b2d80b2f`, and the
committed blob (`git cat-file -p HEAD:backend/eval/PHASE4B_REPORT.md`) hashes
to the same value. `cmp` of the source against the copy found no difference.
In the previous run I read only lines 56–67, 116, 160–248 (excerpts) of that
file, through `grep`. Those lines are unchanged. I had not read the rest, so I
can confirm it is unchanged only from the modification time.

---

## Task C. The distribution-matched control (11.6)

### C1. Rows per address

The bins are row counts per address in dev_train (4,055,357 rows).

| Bin | Real attack set: addresses | Real attack set: rows | Non-attack pool: addresses | Non-attack pool: rows |
|---|---:|---:|---:|---:|
| 1 | 8,949 | 8,949 | 450,346 | 450,346 |
| 2 | 3,562 | 7,124 | 179,926 | 359,852 |
| 3–5 | 3,974 | 14,795 | 178,696 | 656,901 |
| 6–10 | 1,992 | 15,088 | 65,051 | 482,529 |
| 11–20 | 1,383 | 20,274 | 32,861 | 477,769 |
| 21–50 | 976 | 30,706 | 14,581 | 408,877 |
| 51–100 | 394 | 26,449 | 1,286 | 86,022 |
| 101–500 | 855 | 248,633 | 2,296 | 623,858 |
| 501+ | 10 | 10,400 | 88 | 126,785 |
| **Total** | **22,095** | **382,418** | **925,131** | **3,672,939** |

Sources: `C1/real_attack_set/{addresses_per_bin,rows_per_bin}` and
`C1/non_attack_pool/…`.

- **p = 0.09429946611358754** (`C1/p`). This is the share of dev_train rows
  carried by the real attack-labelled addresses, counting all their rows,
  labelled or not: 382,418 / 4,055,357. For comparison, the attack-labelled
  rows alone are 382,391, a share of 0.09429280825337942
  (`C1/real_attack_set/attack_labelled_rows` and
  `…/share_of_dev_train_rows_attack_labelled`).
- Rows per address, real set: min 1, median 2, mean 17.307897714415027,
  p75 6, p99 326, max 1,345.
- Rows per address, non-attack pool: min 1, median 2, mean
  3.9701826011667536, p75 3, p99 28, max 6,796.

### C2. The three draws

Method: bins are drawn from the highest to the lowest. Each pool is ordered
by address string. Each draw uses one `numpy Generator(PCG64(seed))` with
seed 11, 12 or 13, called as `.choice(pool, need, replace=False)` once per
bin. Amendment 11.6 does not fix the order of the bins or of the pool, so
this order is my choice.

| Draw | Shortfalls | Addresses (target 22,095) | Row share (p = 0.09429946611358754) | dev_train rows | ∩ real attack set | Subset of pool |
|---|---|---:|---|---:|---:|---|
| 11 | **none** | 22,095 | 0.0905113902425853 | 367,056 | **0** | yes |
| 12 | **none** | 22,095 | 0.08967619866758957 | 363,669 | **0** | yes |
| 13 | **none** | 22,095 | 0.09229298431679381 | 374,281 | **0** | yes |

The fallback was never used. Every bin's pool held at least the number of
addresses required. The tightest was 101–500, which needed 855 of its 2,296
(37%). The
addresses in each bin match the real set exactly in all three draws. Sources:
`C2/draw_d/{shortfalls,achieved_addresses,achieved_row_share,intersection_with_real_attack_set}`.

Rows per address, induced set against the real set (`C2/draw_d/induced_distribution/rows_per_address`):

| Set | min | p25 | median | mean | p75 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| real attack set | 1 | 1 | 2 | 17.307897714415027 | 6 | 326 | 1,345 |
| draw 11 | 1 | 1 | 2 | 16.61262729124236 | 6 | 321.06 | 4,155 |
| draw 12 | 1 | 1 | 2 | 16.459334691106584 | 6 | 321 | 2,196 |
| draw 13 | 1 | 1 | 2 | 16.939624349400315 | 6 | 324 | 4,710 |

Induced-label rows in val_a and val_b were 108,929 and 98,396 for draw 11,
108,137 and 96,399 for draw 12, and 105,997 and 97,212 for draw 13. The drawn
addresses seen in val_a / val_b were 5,375 / 5,150, 5,345 / 5,082 and
5,387 / 5,155. In the 11.4 control the corresponding row counts were about
15,000.

### C3. Constructions, fitted artefacts, constant features

The code is the same as in 11.4: `phase4b.frame`, `phase4b.prepare`,
`phase3_rules.raw_features` and `phase2_baseline.fit_forest`, with the S1
forest settings. Constructions are fitted on dev_train only, with model
seeds 42, 43 and 44.

| Construction | map / fit rows | ip map | user map | country map | device map | known IPs | known countries |
|---|---|---:|---:|---:|---:|---:|---:|
| (c') | 4,055,357 | 947,226 | 1,061,753 | 218 | 6 | 947,226 | 218 |
| (a') draw 11 | 3,688,301 | 925,131 | 992,604 | 218 | 6 | 925,131 | 218 |
| (a') draw 12 | 3,691,688 | 925,131 | 990,432 | 218 | 6 | 925,131 | 218 |
| (a') draw 13 | 3,681,076 | 925,131 | 988,047 | **217** | 6 | 925,131 | **217** |

Every construction also fits a StandardScaler and an IsolationForest on its
fit rows. In draw 13, one country appears in dev_train only on rows of drawn
addresses, so it is absent from the (a') country map and known-country set.

**Constant on every fitted row:** `is_new_ip` and `is_new_country`, in every
construction. Sources: `construction_c_prime/…` and
`draws/draw_d/construction_a_prime/…`.

**Code-path checks:**
- (c') seed 42 is bit-identical to `results/phase4_cache/score_p2var_c.npy`
  on the 2,337,227 val events.
- (c') seeds 42, 43 and 44 are each bit-identical to the 11.4 run's
  `results/amendment11_cache/c_seed{42,43,44}_val.npy`.

Source: `construction_c_prime/check_vs_stored`.

### C4. Scores against the induced label

L = (AUC_a' − AUC_c') / (AUC_a' − 0.5). Event counts: val_a has 1,183,517
events and val_b has 1,153,710.

**val_a**

| Draw | Base rate | Seed | ROC (a') | PR (a') | ROC (c') | PR (c') | L |
|---|---|---|---|---|---|---|---|
| 11 | 0.09203839066105514 | 42 | 0.7292500101682221 | 0.15218874172720567 | 0.5083612683598313 | 0.130678068341841 | 0.9635277296009894 |
| | | 43 | 0.7214164625400363 | 0.14722836796177768 | 0.5041497604866592 | 0.130327362950743 | 0.9812581212839637 |
| | | 44 | 0.7213142624843094 | 0.14608527414938213 | 0.5072428230065671 | 0.1285845518500427 | 0.9672735822569023 |
| | | **L seed mean** | | | | | **0.9706864777139518** |
| 12 | 0.09136919875253165 | 42 | 0.7248520477590753 | 0.14759927999470074 | 0.4694812272996415 | 0.08316028616031822 | 1.13572823998943 |
| | | 43 | 0.7133910242732753 | 0.1410574867257899 | 0.4648134861813924 | 0.08260516338149565 | 1.1648921923423856 |
| | | 44 | 0.718453410691482 | 0.1431031578178457 | 0.4680243250721591 | 0.0832176570924067 | 1.1463729718232671 |
| | | **L seed mean** | | | | | **1.1489978013850275** |
| 13 | 0.08956102869667272 | 42 | 0.7231221273804145 | 0.14529367902245252 | 0.46089311230347174 | 0.08206121474574679 | 1.175271220993033 |
| | | 43 | 0.7302805185780655 | 0.14887661356458756 | 0.45639628756515077 | 0.08160076436819308 | 1.1893504179341488 |
| | | 44 | 0.7314362459108676 | 0.14950466279264849 | 0.4599514324612852 | 0.08207593306536173 | 1.1730436275488956 |
| | | **L seed mean** | | | | | **1.1792217554920257** |

Secondary figure, the mean of the per-draw values of L on val_a:
**1.0996353448636684** (`over_draws/val_a`).

**val_b**

| Draw | Base rate | Seed | ROC (a') | PR (a') | ROC (c') | PR (c') | L |
|---|---|---|---|---|---|---|---|
| 11 | 0.08528659715179725 | 42 | 0.7032710813798777 | 0.13147435438937963 | 0.5113004525800449 | 0.12321935968465508 | 0.9444069835053107 |
| | | 43 | 0.6954245007397241 | 0.12745408491014762 | 0.5076631553676962 | 0.12394342013206044 | 0.9607871308935699 |
| | | 44 | 0.6955795802781675 | 0.12642527084661517 | 0.5103112768883236 | 0.12140356718579673 | 0.9472783565970532 |
| | | **L seed mean** | | | | | **0.9508241569986446** |
| 12 | 0.08355565956782901 | 42 | 0.6998297292742648 | 0.12652488075072077 | 0.47524330146087135 | 0.07651127158999535 | 1.1238889660164142 |
| | | 43 | 0.6895940033374384 | 0.12154968997047381 | 0.4708968607984442 | 0.07608980943810639 | 1.1535024245980936 |
| | | 44 | 0.6940602378970069 | 0.12303518396477062 | 0.4742669912115577 | 0.0766395252108823 | 1.1326032012910319 |
| | | **L seed mean** | | | | | **1.136664863968513** |
| 13 | 0.08426034272044101 | 42 | 0.700777514569204 | 0.12913823493850432 | 0.47297163277570753 | 0.08415704349313886 | 1.1346184969083095 |
| | | 43 | 0.7074718021788462 | 0.1319396134217255 | 0.46881439355808474 | 0.08386460797612884 | 1.150312505672614 |
| | | 44 | 0.7083813829650348 | 0.13232944233928912 | 0.47237671059356906 | 0.08409833833055996 | 1.1325612154664795 |
| | | **L seed mean** | | | | | **1.1391640726824674** |

Secondary figure, the mean of the per-draw values of L on val_b:
**1.0755510312165415** (`over_draws/val_b`).

Sources: `draws/draw_d/{val_a,val_b}/per_model_seed/seed_s/…`,
`…/L_mean_over_model_seeds` and `…/induced_label_event_base_rate`. On draws
12 and 13, L is above 1 because AUC_c' < 0.5.

### C5. Intervals (11.4 specification, model seed 42)

These are 95% percentile bootstrap intervals. Each of 1,000 resamples draws
source addresses with replacement, using `numpy Generator(PCG64(42))`, and
recomputes both AUCs on the same resample. All 1,000 resamples were valid in
every case. The resamples are drawn from 348,248 addresses in val_a and
345,496 in val_b.

| Split | Draw | AUC_a' 95% CI | AUC_c' 95% CI (no prediction) |
|---|---|---|---|
| val_a | 11 | [0.7170396291417527, 0.7413217503486502] | [0.4700152922890416, 0.549919253624969] |
| val_a | 12 | [0.7115281454765894, 0.7379840186406766] | [0.4426807789460925, 0.49834559889061386] |
| val_a | 13 | [0.7102757112734116, 0.7353493378927609] | [0.4436876160602183, 0.47993589621877764] |
| val_b | 11 | [0.6900911479938056, 0.7159968070109818] | [0.4679039878691404, 0.5578932625440713] |
| val_b | 12 | [0.68489553972883, 0.7122569857782213] | [0.4491642963489227, 0.5034588063216678] |
| val_b | 13 | [0.6872464151031308, 0.7143091070097287] | [0.45015874018604746, 0.5010926804269414] |

Sources: `draws/draw_d/{h}/interval_seed_42` and
`c_prime_intervals_no_prediction`.

### C6. Fit-time absence count

Known IPs from all dev_train rows, minus known IPs from rows whose induced
label is 0, using the same code path as A7 (`phase4b.prepare` →
`len(known_ips_set)`): 947,226 − 925,131 = **22,095** for each of draws 11,
12 and 13. Source: `draws/draw_d/fit_time_absence_count`. The real-label
value from the 11.4 run is 22,089.

### C7. Declared predictions and the stop condition

Each prediction holds only if it holds for all three draws on both splits.

| Prediction | val_a d11 | val_a d12 | val_a d13 | val_b d11 | val_b d12 | val_b d13 | Overall |
|---|---|---|---|---|---|---|---|
| 1. lower bound of AUC_a' CI > 0.70 | held (0.7170) | held (0.7115) | held (0.7103) | **fail (0.6901)** | **fail (0.6849)** | **fail (0.6872)** | **FAILED** |
| 2. L seed mean > 0.85 | held (0.971) | held (1.149) | held (1.179) | held (0.951) | held (1.137) | held (1.139) | held |

The figures in brackets are rounded from the full values above. Source:
`predictions`.

- **Prediction 1 failed.** It held on all three draws on val_a and failed on
  all three draws on val_b, where the lower bounds were 0.6849 to 0.6901.
- **Prediction 2 held** on all six cases. On draws 12 and 13 it holds partly
  because AUC_c' < 0.5, which pushes L above 1.
- **AUC_c' intervals, no pass or fail:** the table in C5.
- **Stop condition** (lower bound of the AUC_c' interval > 0.60): **not
  triggered**. The highest lower bound was 0.4700 (`stop_condition`).

Amendment 11.6 declares the consequence of this outcome in advance: "If
prediction 1 fails while prediction 2 holds, then part of the original
construction's ranking came from genuine differences in the behaviour of
attacking addresses rather than from the filter, the paper must report that,
and L is presented as a decomposition of the apparent ranking rather than as a
measure of leakage alone." This outcome (prediction 1 failed, prediction 2
held) is that case. This report does not revise the scope condition in 11.1.

---

## Task D. The real-label statistic

Per-event development scores, model seed 42, for all 6,392,584 dev events
(`real/per_event_scores`):
- (a): `results/phase3_cache/ml_decision_v3.npy`. The score is −decision,
  which ranks the same as −`score_samples`.
- (b): `results/phase4_cache/score_p2var_b.npy`.
- (c): `results/phase4_cache/score_p2var_c.npy`.

Label: `Is Attack IP | Is Account Takeover`. Clusters: source addresses.

### Inputs

| Split | Construction | ROC-AUC | File and JSON path | Recomputed from per-event scores, equal? |
|---|---|---|---|---|
| val_a | a | 0.762999627767321 | `phase4b_diag.json` `variants/a/val_a/roc_auc` | yes |
| val_a | b | 0.5531101898878288 | `phase4b_diag.json` `variants/b/val_a/roc_auc` | yes |
| val_a | c | 0.5039329966694688 | `phase4b_diag.json` `variants/c/val_a/roc_auc` | yes |
| val_b | a | 0.750421331271785 | `phase4b_diag.json` `variants/a/val_b/roc_auc` | yes |
| val_b | b | 0.5552088718116418 | `phase4b_diag.json` `variants/b/val_b/roc_auc` | yes |
| val_b | c | 0.506056815350325 | `phase4b_confirm.json` `d1_c_val_b/roc_auc` | yes |

Source: `real/halves/{h}/roc_auc_stored`, `…/recomputed_equals_stored`.

### D2. Shares and L (point values, by script)

| Split | Share (b) | Share (c) | L |
|---|---|---|---|
| val_a | 0.2019401713177177 | 0.014954381125392126 | 0.9850456188746078 |
| val_b | **0.22046393384804353** | **0.024186499287280987** | **0.975813500712719** |

The val_a values equal those in `FEASIBILITY_AUDIT.md`. The val_b share (c)
and L are new. Source: `real/halves/{h}/{share_b,share_c,L}`.

### D1. Intervals (11.2, model seed 42)

These are 1,000 resamples of source addresses with replacement, using
`Generator(PCG64(42))`. On each resample all three AUCs and L are
recomputed. The resamples are drawn from 348,248 addresses in val_a and
345,496 in val_b. All 1,000 resamples were valid.

| Split | Base rate | AUC_a 95% CI | AUC_b 95% CI | AUC_c 95% CI | Domain condition (AUC_a CI low > 0.55) | **L 95% CI** |
|---|---|---|---|---|---|---|
| val_a | 0.1074382539498799 | [0.7496505177620156, 0.7749759675042339] | [0.5410831024573128, 0.5664477567885268] | [0.4918742679756369, 0.5173922970085546] | met | **[0.9359823493364369, 1.032443692081726]** |
| val_b | 0.09574763155385668 | [0.7358306653518014, 0.7633052724122404] | [0.5424509093710578, 0.5682436371376702] | [0.49340227486755434, 0.5192395571667794] | met | **[0.9256319143826766, 1.0272112243266462]** |

Source: `real/halves/{h}/interval`.

Under 11.2, L is the mean of per-seed values. On development data only seed
42 has stored per-event scores for (a), so the estimate and interval here are
for that one seed. The per-seed range for seeds 43 and 44 is **missing**,
because no per-event dev scores exist for construction (a) at those seeds.
For (c), the 11.4 and 11.6 runs produced label-free val scores at seeds 43
and 44 (`results/amendment11_cache/c_seed{43,44}_val.npy`). Those are not
used here, because construction (a) has no partner scores at those seeds.

### D3. May per-event scores

Checked by file names and code inspection only. No May file was opened. The
same record is in `D3` of the JSON.

- **None found for (a), (b) or (c).**
  - `eval/phase6_secondary.stage_s1` writes only the `save_json` summary
    `phase6_s1.json` (per-seed AUCs) and never saves per-event S1 scores.
  - `results/phase6_cache/` holds only `deployed*.npz`, `email_log*.json`,
    `store_day*`, `test_2020-05.parquet` and `X_v4*.npy`. None is named for
    S1.
  - The three stored score files are each 51,140,800 bytes. That is
    6,392,584 × 8 bytes plus a 128-byte header, so they cover development
    events only.
- **Refit cost.** Measured on dev in these runs: about 50–60 s per
  construction for maps, scaler and features, and about 237–300 s per forest
  seed to fit and score 2.34M events. A May refit of 3 constructions × 3 seeds
  would be 9 fits plus 3 feature builds, on the order of 45 minutes. It would
  also need the locked May month, which amendment 11 does not permit.

---

## Task E. Point values of the 11.4 run (copied, not recomputed)

Copied by `python -m eval.amendment11_controls prev` from
`results/amendment11_controls.json`. In that file the paths are
`control/draws/draw_d/{h}/per_model_seed/seed_s/{a_prime,c_prime}/roc_auc`
and `control/draws/draw_d/{h}/induced_label_event_base_rate`. They are
stored again under `E` with each source path.

| Split | Draw | Base rate | Seed | AUC_a' | AUC_c' |
|---|---|---|---|---|---|
| val_a | 1 | 0.01279322561484119 | 42 | 0.5874744418789176 | 0.47408930491178064 |
| | | | 43 | 0.5874451973420401 | 0.4733853645620088 |
| | | | 44 | 0.5979441006631171 | 0.47447280261563807 |
| val_a | 2 | 0.013886577041140939 | 42 | 0.6078185018929992 | 0.5105265185162078 |
| | | | 43 | 0.6122692900492099 | 0.5086646371154679 |
| | | | 44 | 0.6125511944372168 | 0.5100591630641607 |
| val_a | 3 | 0.013294274606955371 | 42 | 0.5961977213132982 | 0.4723666246714726 |
| | | | 43 | 0.5949357080567296 | 0.4717966152124856 |
| | | | 44 | 0.60165939262106 | 0.4723999551334827 |
| val_b | 1 | 0.012195439061809293 | 42 | 0.564026723504027 | 0.4706745025493032 |
| | | | 43 | 0.5635628249991388 | 0.4694898279515044 |
| | | | 44 | 0.5733614109726343 | 0.47083358846695733 |
| val_b | 2 | 0.013629074897504572 | 42 | 0.5852971678567181 | 0.5078584336630331 |
| | | | 43 | 0.5897217773281311 | 0.5051506411421682 |
| | | | 44 | 0.5897449093068836 | 0.5073670140573513 |
| val_b | 3 | 0.012459803590156972 | 42 | 0.5716816951154383 | 0.4710398538888341 |
| | | | 43 | 0.5702816476048862 | 0.46961030242469814 |
| | | | 44 | 0.5767721961991177 | 0.47051585501153326 |

---

## Code note

The `real` stage had been committed in `96e8b50` but never run. On its first
run it failed before computing anything, with
`AttributeError: module 'eval.phase3_rules' has no attribute 'load_json'`.
I changed it to `P3B.load_json`, the loader `amendment10_lookup.py` uses, and
reran it. No value had been produced before the fix.

## Files

- Code commit: `eval/amendment11_controls.py`, with the `matched` and `prev`
  stages, the `--out` option, and the loader fix in `real`.
- Results commit: `eval/AMENDMENT11_6_CONTROLS.md` (this file) and
  `results/amendment11_6_controls.json`.
