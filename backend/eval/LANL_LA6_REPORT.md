# LANL LA6: second-dataset controls for the entity-label leakage diagnostic

Written 2026-11-06. Governed by `eval/PROTOCOL_LANL.md` LA6, committed on its
own as `ec308fe` before any code, and by `eval/PROTOCOL.md` amendments 11.1 to
11.6.

**Development days 0 to 13 only.** Every auth read goes through
`eval.lanl_la3.day_table`, which raises on day 14 or later. The red-team rows
come from `eval.lanl_la3.redteam_dev`, which reads the three dev splits only.
`load_lanl("test")` was never called, and `results/lanl_test_access.log` has
no new line. No RBA data of any kind was read.

Script: `eval/lanl_la6.py`, with stages `codes`, `fit` and `metrics`. Values:
`results/lanl_la6_controls.json`. JSON paths below are relative to that file.
Per-day codes and scores are in `C:\Users\Dell\datasets\lanl\l2_work\la6\`,
outside the repository.

## Summary

| Prediction | Result |
|---|---|
| LA6.1: L > 0.85 on both scoring splits, all three seeds; entity lookup ROC-AUC > 0.90 | **FAILED.** L lies between −0.190 and 0.077 in all six split-and-seed cases. The lookup part held (ROC-AUC 0.99991 and 0.99997). |
| LA6.2: on both scoring splits and all three seeds, the interval on L contains 0 and its upper bound is below 0.30 | **FAILED.** The upper bound was below 0.30 in all six cases (largest 0.0073). The interval contained 0 in five of six. It did **not** contain 0 for seed 43 on days 8–11, where it is [0.0017, 0.0073]. |

The LA6.3 runtime contingency was not invoked. Under LA6.4, both failures
are reported as failures.

## Freeze manifest

| When | Command (from `backend/`) | Output | Exit |
|---|---|---|---|
| Before any work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
| After all work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

Tags were not moved: `v3.0.0` = 97a37f9…, `v3.0.0-frozen` = bb40c16….

## Step 0

- **0a, `8c5e9f4`.** The garbled passage quoted in the prompt ("The closest
  was 51 to 100, which needed 394 from 1,286. The addresses required. …")
  **was not in the committed file.** The earlier edit had replaced that
  sentence and was applied only once. The committed text was correct but had
  a broken line ("(37%). The / addresses in each bin …"). I rewrote the
  paragraph once, from the stored values:
  - `C2/draw_d/shortfalls` is empty for all three draws, and no address was
    moved.
  - The highest required share was in bin 101–500: 855 of 2,296
    (0.3724).
  - Bin 51–100 needed 394 of 1,286 (0.3064).
  - Every other bin needed less than 0.12 of its pool.

  In the same commit, the code note became a section headed "Disclosed
  deviation: Task D code fix".
- **0b, `ec308fe`.** LA6 was appended to `PROTOCOL_LANL.md`, verbatim. The
  first append dropped the final line of Part 1. I added it and amended that
  unpushed commit. A `diff` against Part 1 of the prompt is empty. The commit
  holds `PROTOCOL_LANL.md` only.

---

## Constructions (both controls)

LA6 asks for constructions "built to mirror the RBA construction's artefact
structure using LANL's available fields". The LANL D1 construction (LA3.5,
`eval/lanl_d.py`) already does that mapping. It was declared as "RBA S1
variant (c)". The constructions here therefore use D1's artefacts and
features.

| Artefact | Fields covered | RBA counterpart | Model input |
|---|---|---|---|
| frequency map (count / fitting rows; unseen → 0.0) | source computer | IP frequency | `src_freq` |
| frequency map | source user | user frequency | `user_freq` |
| frequency map | destination computer | none (added in LA3.5) | `dst_freq` |
| known-value set | source computer | known IPs | `is_new_src` |
| known-value sets | source user, destination computer | none | not model inputs; their (a)/(c) differences are reported as perturbation counts |
| StandardScaler | the 7 features | the same | — |
| IsolationForest: n_estimators 200, max_samples 100,000, max_features 1.0, contamination 0.4, seeds 42/43/44 | the 7 features | the S1 settings | score = −score_samples |
| dropped | country and device maps, known countries, `is_failed` | — | `is_failed` would be constant, since the LA3.3 filter keeps only successful logons |

`hour_sin`, `hour_cos` and `fail_rate_30d` do not depend on the label. They
are taken unchanged from the stored per-day D feature files.

LA6 says "frequency maps and known-value sets over source user, source
computer and destination computer". I read this as covering the artefact
*types* across those fields, mirroring RBA, where only the IP has a known set
that feeds the model. On that reading, (c) is exactly D1, and the checks
below confirm it. The other reading would add `is_new_user` and `is_new_dst`
as features. Those would be constant on every fitting row, as `is_new_src`
is, so they could not enter any forest split, but they would change the
random-number use and the scores would no longer be D1's.

- **(a):** maps, known set, scaler and forest are fitted on the dev_train
  (days 0–7) filtered rows whose label is 0.
- **(c):** everything is fitted on all of those rows. (c) is label-free, so
  it is shared by LA6.1 and LA6.2.

**Constant on every fitting row:** `is_new_src` in every construction and
every seed (`fit/<construction>/seed_s/constant_features_on_fit_rows`).

**Code-path checks** (`check_c_vs_stored_d1` and `fit/c/seed_42`):
- The (c) fitting-row count, 18,626,010, equals the stored D1 `maps.pkl` `n`.
  It also equals `results/lanl_d_maps.json` `dev_train_filtered_rows`.
- The src, user and dst maps equal the stored maps exactly.
- The rebuilt features equal the stored D feature files on all 14 days.
- (c) seed 42 scores on days 8–13 are **bit-identical** to the stored D1
  scores (`d1_day=08…13.npy`).
- The (c) seed 42 point ROC-AUC and its bootstrap interval reproduce
  `results/lanl_d_dev.json`:
  - val_a: 0.9797405381220861, [0.9702051272513433, 0.987992623243769].
  - val_b interval: [0.9592941367676144, 0.9916765507364607].
  - The val_b point value is 0.9807961935415549 here against
    0.9807961935415548 stored, a last-bit difference from summation order.

## Runtime (LA6.3)

| Construction / seed | Fitting rows | Fit (s) | Score days 8–13 (s) | Wall, fit and score (s) |
|---|---:|---:|---:|---:|
| F (a) / 42 | 18,093,778 | 671.2 | 80.7 | 763.1 |
| G (a) / 42 | 18,625,960 | 684.0 | 77.8 | 772.4 |
| (c) / 42 | 18,626,010 | 705.1 | 76.5 | 793.2 |
| F (a) / 43 | 18,093,778 | 661.8 | 74.3 | 748.8 |
| G (a) / 43 | 18,625,960 | 653.9 | 78.2 | 742.7 |
| (c) / 43 | 18,626,010 | 653.0 | 73.7 | 736.0 |
| F (a) / 44 | 18,093,778 | 644.0 | 74.4 | 727.7 |
| G (a) / 44 | 18,625,960 | 642.3 | 73.9 | 726.7 |
| (c) / 44 | 18,626,010 | 647.6 | 72.3 | 728.2 |

The longest was 793.2 s, against a 5,400 s threshold. **The contingency was
not invoked**, and all three seeds were run (`la6_3_contingency`, `fit`).

---

## Task F. Positive control: induced source-user label (LA6.1)

### F1. The induced label

A source user is labelled if it is the user of any red-team event in days
0–13. Every row of a labelled user, in days 0–13, carries label 1.
Source: `F1`.

| Quantity | Value |
|---|---:|
| labelled source users (red-team users, days 0–13) | 86 |
| … present in filtered rows, days 0–13 | 86 |
| … in days 0–7 filtered rows | 76 |
| … in days 8–13 filtered rows | 85 |
| … in both days 0–7 and days 8–13 | **75** |
| … only in days 8–13 | 10 |
| fitting rows (days 0–7, filtered) | 18,626,010 |
| labelled fitting rows | 532,232 |
| share of fitting rows the labelled users carry | **0.028574665212785778** |

Rows per labelled user:

| Period | Users | min | p25 | median | mean | p75 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| days 0–7 | 76 | 3 | 1,528.5 | 3,024.5 | 7,003.05 | 5,104.25 | 125,598 |
| days 8–13 | 85 | 1 | 530 | 2,198 | 4,831.62 | 3,341 | 91,477 |

### F2. Artefact perturbation: (a) against (c)

Source: `artefacts/F`. 532,232 rows were removed: (c) fits on 18,626,010
rows and (a) on 18,093,778.

| Field | Keys (a) / (c) | Keys only in (c) | Shared keys whose count changed | Shared keys whose frequency changed | Known-set symmetric difference |
|---|---|---:|---:|---:|---:|
| source computer | 11,194 / 11,492 | 298 | 1,158 | 11,194 (all) | 298 |
| source user | 11,994 / 12,070 | 76 | 0 | 11,994 (all) | 76 |
| destination computer | 2,444 / 2,724 | 280 | 349 | 2,444 (all) | 280 |

Frequency = count / fitting rows, so removing any row changes the frequency
of every shared key. "Count changed" isolates the keys whose underlying
count moved.

### F3. Scores against the induced label

The positives are the induced-label rows. Bootstrap clusters are the
labelled users with an induced-positive row in the scope, ordered by user
name. There are 79, 80 and 85 of them (≥ 20, so the bootstrap applies).
Intervals use `boot_weights` (numpy `default_rng(42)`), with 1,000 resamples
shared by (a), (c) and all seeds. Positives are weighted by their user's
multiplicity and negatives are fixed (LA3.7). All 1,000 resamples were
valid. The domain condition (lower bound of the AUC_a interval > 0.55) was
met in every case. AUC_c was never below 0.5, and L was never above 1.

**Days 8–11.** 8,569,072 rows, 241,698 positive. Base rate
0.02820585472966034.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.6927508434213223 [0.6450224410597966, 0.7335074864312552] | 0.04738947899040627 | 0.7130973319364743 [0.533384902793255, 0.8028259170875328] | 0.06565528554167194 | −0.10555849278790352 [−0.4741668999948444, 0.7712688141994961] |
| 43 | 0.6923817460712388 [0.6416381783037017, 0.7368499662298291] | 0.04695183238581292 | 0.714149037079047 [0.5344611335231428, 0.803649070739941] | 0.06605791556156233 | −0.1131463428954832 [−0.4750747453381666, 0.7634767125566603] |
| 44 | 0.6812453418662664 [0.6271283354165255, 0.7262426073624079] | 0.045125052497771045 | 0.7156489245528418 [0.5372209905761127, 0.8041652882082183] | 0.06614809338279967 | −0.189817748320177 [−0.5770989431098822, 0.7155193463037424] |

L, mean of the per-seed values: **−0.13617419466785458**. L of the seed-mean
AUCs (secondary): −0.13509947682099613.

**Days 12–13.** 6,383,434 rows, 168,990 positive. Base rate
0.02647321175404962.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.725214742730798 [0.6783348720438307, 0.7689283195944132] | 0.05272317735759024 | 0.707786428647269 [0.5661296212614828, 0.79638074949141] | 0.0685454232174349 | 0.07738531621955692 [−0.3057087118976807, 0.6854235964674588] |
| 43 | 0.724765364174637 [0.675630997374524, 0.7711792733025082] | 0.05192515074868809 | 0.7101443392479303 [0.5703935641740651, 0.7979952542112816] | 0.06864962302195755 | 0.0650501690080084 [−0.3077157251225034, 0.6560226412097464] |
| 44 | 0.7112285939764827 [0.659092020677221, 0.7597822273358932] | 0.05003019887857429 | 0.7095557731922159 [0.5695277791463542, 0.7972645538704629] | 0.06831835224929665 | 0.007919480751991075 [−0.42407384359369976, 0.6430956860029995] |

L, mean of the per-seed values: **0.05011832199318547**. L of the seed-mean
AUCs (secondary): 0.051000780463905215.

**Days 8–13 combined.** 14,952,506 rows, 410,688 positive. Base rate
0.02746616520334451.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.7069861491295095 [0.6634074767615787, 0.7478690608360665] | 0.04953276085783385 | 0.711229291322221 [0.5489040063075658, 0.7965794329338957] | 0.06645147918513758 | −0.020499643143061675 [−0.3796878674665268, 0.7345349686614857] |
| 43 | 0.7066001581042006 [0.6610448932951113, 0.7507989195657533] | 0.048761095438967804 | 0.7127880160779572 [0.551688142602122, 0.7970355183294702] | 0.06683800363123078 | −0.029950886923501955 [−0.3920524850499637, 0.7248173557538563] |
| 44 | 0.6945341901794758 [0.6470931770303899, 0.740111870228427] | 0.046937262052287806 | 0.7134697765161915 [0.5500808105789544, 0.7971867052941384] | 0.06663069802265766 | −0.09733808910015163 [−0.5033902051250276, 0.6854359521564759] |

L, mean of the per-seed values: **−0.049262873055571754**. L of the
seed-mean AUCs (secondary): −0.04829073617499084.

Source: `F/<scope>/per_seed/seed_s/…`, `F/<scope>/L_mean_over_seeds`.

### F4. Entity-lookup reference and fit-time absence count

The lookup scores a row 1 if its user appears in any induced-positive row of
days 0–7. It is scored with sklearn, ties averaged
(`F/<scope>/entity_lookup_reference`).

| Scope | ROC-AUC | PR-AUC | Precision (score 1) | Recall (score 1) | Positive users in scope / seen in days 0–7 |
|---|---|---|---|---|---|
| days 8–11 | 0.9999731069351008 | 0.9999477309539653 | 1.0 | 0.9999462138702017 | 79 / 74 |
| days 12–13 | 0.9999112373513226 | 0.9998271743674337 | 1.0 | 0.9998224747026452 | 80 / 74 |
| days 8–13 | 0.9999476488234378 | 0.9998981734190036 | 1.0 | 0.9998952976468755 | 85 / 75 |

The induced label covers days 0–13, so the reference is not degenerate. The
positive users first seen after day 7 carry 13, 30 and 43 rows in the three
scopes. That is the gap between recall and 1.

**Fit-time absence count** (11.4 definition, the known set from all fitting
rows minus the known set from label-0 rows, same code path for both
controls) (`F/fit_time_absence_count`):

| Field | Count |
|---|---:|
| source user (the labelled entity) | **76** |
| source computer | 298 |
| destination computer | 280 |

### F5. LA6.1 prediction

| Split | Seed 42: L > 0.85? | Seed 43 | Seed 44 | Lookup ROC-AUC > 0.90? |
|---|---|---|---|---|
| days 8–11 | **no** (−0.1056) | **no** (−0.1131) | **no** (−0.1898) | yes (0.99997) |
| days 12–13 | **no** (0.0774) | **no** (0.0651) | **no** (0.0079) | yes (0.99991) |

**The LA6.1 prediction FAILED.** L was not above 0.85 for any seed on either
split. The L intervals are wide, spanning roughly −0.58 to 0.77. Every L
interval contains 0 and every one excludes 0.85. In all six cases the AUC_c
interval is wider than the AUC_a interval.

The induced label is synthetic. In line with LA6.4, the entity counts are
stated here as the limitation: 86 labelled users in total, 75 of them in both
periods, and 79 to 85 per scope.

---

## Task G. Negative control: true event labels (LA6.2)

### G1. Rows removed and artefact perturbation

**50 rows were removed.** These are the LA3.1-positive dev_train filtered
rows, which are the matched red-team rows: (c) fits on 18,626,010 rows and
(a) on 18,625,960. The 50 rows fall on days 1, 2, 5, 6 and 7 (10, 15, 21, 3
and 1 rows), per `results/lanl_d_features.json` `per_day/positives`.

Source: `artefacts/G`.

| Field | Keys (a) / (c) | Keys only in (c) | Shared keys whose count changed | Shared keys whose frequency changed | Known-set symmetric difference |
|---|---|---:|---:|---:|---:|
| source computer | 11,492 / 11,492 | 0 | 3 | 11,492 (all, through n) | 0 |
| source user | 12,070 / 12,070 | 0 | 7 | 12,070 (all, through n) | 0 |
| destination computer | 2,723 / 2,724 | 1 | 23 | 2,723 (all, through n) | 1 |

**Fit-time absence count** (`G/fit_time_absence_count`): source computer 0,
source user 0, destination computer 1.

**G4.** The artefacts of (a) and (c) are **not** bit-identical.
- 50 fitting rows differ, which changes the denominator n.
- 33 keys change count (3 + 7 + 23).
- One destination computer leaves the map and the known-destination set.
- The fitting matrices differ, so the scaler and the forests differ too.

So L is a measurement here, not 0 by construction.

### G2. Scores against the true labels

Bootstrap clusters are the red-team users of the scope's red-team events, in
user-name order, as in `eval/lanl_d_metrics`: 45, 50 and 81. The procedure
is the same as F3 otherwise. The domain condition was met in every case, and
AUC_c was never below 0.5.

**Days 8–11.** 8,569,072 rows, 266 positive. Base rate
3.10418677775143e-05.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.9799196846016038 [0.9693355181102907, 0.9886615908509075] | 0.0025517265281393958 | 0.9797405381220861 [0.9702051272513433, 0.987992623243769] | 0.002225746857428962 | 0.00037328429165495213 [−0.0026093285021603807, 0.0030537573112912175] |
| 43 | 0.9729408844090909 [0.9617506453469911, 0.9824638889266195] | 0.0012013496699178517 | 0.9709827931931854 [0.9597524968838091, 0.9810481070039162] | 0.0015940620630867377 | 0.004140245177475023 [**0.001712803383447431**, 0.00733244724253113] |
| 44 | 0.9746573486250133 [0.964297162497332, 0.9839950039900298] | 0.0016064106376048966 | 0.9750002851311003 [0.9641926659922959, 0.9845284414266124] | 0.001881416131493659 | −0.0007224927773274426 [−0.0037486809854104107, 0.002449546813112324] |

L, mean of the per-seed values: **0.0012636788972675108**. L of the
seed-mean AUCs (secondary): 0.00125693777091653.

**Days 12–13.** 6,383,434 rows, 282 positive. Base rate
4.4176849012616096e-05.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.9797563295481738 [0.9560793578141373, 0.991669816919515] | 0.003795414703809608 | 0.9807961935415549 [0.9592941367676144, 0.9916765507364607] | 0.004906914894956722 | −0.002167483635620607 [−0.007929467554970412, 0.0008139473571752499] |
| 43 | 0.9761791222129845 [0.9512877741237863, 0.9888818466517763] | 0.0035215816922552355 | 0.975710747705569 [0.9508384533344231, 0.988790912675591] | 0.006649496628607447 | 0.0009836099181308791 [−0.001099346756450291, 0.0033500099939728005] |
| 44 | 0.9771265387160067 [0.9529157673798708, 0.9895802695722595] | 0.006204451381438577 | 0.9770364706055001 [0.9527825405386252, 0.9895260715221643] | 0.005182923113325583 | 0.00018877195711851304 [−0.001556376917770082, 0.0018260177704089897] |

L, mean of the per-seed values: **−0.00033170058679040493**. L of the
seed-mean AUCs (secondary): −0.0003359389744883592.

**Days 8–13 combined.** 14,952,506 rows, 548 positive. Base rate
3.6649375027838144e-05.

| Seed | ROC (a) [95% CI] | PR (a) | ROC (c) [95% CI] | PR (c) | L [95% CI] |
|---|---|---|---|---|---|
| 42 | 0.9793481627433229 [0.9649431533380465, 0.9883199211108524] | 0.0027683474661916894 | 0.9793110420282792 [0.9657114891451534, 0.9875623565172164] | 0.002733369362580698 | 7.743998606618128e-05 [−0.0027509274978141287, 0.002671176039960858] |
| 43 | 0.9734092938020041 [0.9579866875817757, 0.9834643403675396] | 0.00172365134696865 | 0.9719190181925376 [0.9561222223504307, 0.9825923286181594] | 0.002582266856276956 | 0.0031479644125657104 [0.0012221402312955715, 0.005690816297243302] |
| 44 | 0.97474262416817 [0.9600713482393012, 0.9842309248710027] | 0.0023985962777868623 | 0.9749115377924631 [0.9601027203470847, 0.9846756790736246] | 0.002428724786555206 | −0.0003558004183614646 [−0.002109860049895978, 0.0010395980626263675] |

L, mean of the per-seed values: **0.0009565346600901424**. L of the seed-mean
AUCs (secondary): 0.0009516515750652478.

Source: `G/<scope>/per_seed/seed_s/…`.

### G3. LA6.2 prediction

| Split | Seed | Interval on L contains 0? | Upper bound < 0.30? |
|---|---|---|---|
| days 8–11 | 42 | yes | yes (0.0031) |
| days 8–11 | 43 | **no**: [0.0017, 0.0073] | yes (0.0073) |
| days 8–11 | 44 | yes | yes (0.0024) |
| days 12–13 | 42 | yes | yes (0.0008) |
| days 12–13 | 43 | yes | yes (0.0034) |
| days 12–13 | 44 | yes | yes (0.0018) |

**The LA6.2 prediction FAILED.** The prediction requires both parts in all
six cases. The interval on L excludes 0 for seed 43 on days 8–11. On the
combined scope, which is not part of the prediction, seed 43 also excludes 0:
[0.0012, 0.0057]. The upper-bound part held in all six cases.

LA6.4 declares the consequence of a failure as follows: "If it fails, meaning
L is substantially above 0 where the label marks events and the labelled rows
are a negligible share of the fitting population, then L does not measure
what amendment 11 claims, and the diagnostic is reported as a procedure
without a validated summary statistic." The observed failure is an interval
of [0.0017, 0.0073], from 50 removed rows out of 18,626,010. This report
records the failure as declared. It does not decide whether that interval is
"substantially above 0" in the sense of the consequence clause. That reading
is the author's decision, and it is not made here.

---

## Disclosed deviation: bootstrap user order

On the first run of the `metrics` stage, the bootstrap columns were in
internal user-code order. `eval/lanl_d_metrics` puts them in user-name order.
The same `default_rng(42)` resamples were therefore assigned to different
users. That run's point values were identical to the final ones. Its intervals
differed: for example, the G days 8–11 seed 43 L interval was
[0.0018609832685864058, 0.007193559523255552]. On that first run the LA6.1
and LA6.2 verdicts were the same as in the final run, and LA6.2 failed in
the same case.

I noticed the difference when the (c) seed 42 intervals did not reproduce
`results/lanl_d_dev.json`. I changed the order to user name, as LA3.7 and
`lanl_d_metrics` use, and reran. The (c) seed 42 intervals then reproduced
`lanl_d_dev.json` exactly. Every value in this report is from the corrected
run.

## Files

- `ec308fe`: `eval/PROTOCOL_LANL.md` (LA6, declaration only).
- Code commit: `eval/lanl_la6.py`.
- Results commit: `eval/LANL_LA6_REPORT.md` (this file) and
  `results/lanl_la6_controls.json`.
