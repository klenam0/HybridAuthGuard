# Amendment 11.9 and LA8: the artefact-absence measurement, and the Task H share

Written 2026-11-07. Governed by `eval/PROTOCOL.md` amendments 11.1 to 11.9,
`eval/PROTOCOL_LANL.md` LA6, LA7 (as withdrawn by 11.9.2) and LA8. Nothing from the superseded first
version of the drafting document was committed.

Script: `eval/amendment11_9_absence.py`, with stages `rba` (Task K), `lanl`
(Task L) and `share` (Task M). Values: `results/amendment11_9_absence.json`.
JSON paths are relative to that file unless another file is named.

**Every figure here is descriptive. No pass or fail is attached anywhere**
(11.9.4, M3).

## Constraints observed

- **No model was fitted.** Only frequency maps and known-value sets were
  rebuilt. No scaler was fitted and no forest was trained. Task M reads
  stored per-event scores only.
- **RBA:** `datasets.load("dev")` only. The locked May month, the Phase 6
  May cache, and every month from June 2020 onward were not read.
- **LANL:** per-day codes and D feature files for days 0 to 13 only, through
  `eval.lanl_la6`. `results/lanl_test_access.log` had 8 lines before and 8
  after.
- **Freeze manifest:**

  | When | Command (from `backend/`) | Output | Exit |
  |---|---|---|---|
  | Before any work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |
  | After all work | `python -m eval.freeze --verify` | `freeze MATCHES` | 0 |

- **Tags and frozen files:** no tag was moved (`v3.0.0` = 97a37f9,
  `v3.0.0-frozen` = bb40c16). `eb6937b` (LA7) was not reverted. No frozen
  file was modified.

## Step 0

Each amendment was appended verbatim from the drafting document and
committed on its own. After each append, the tail of the file was compared
byte for byte (`cmp`) with the text as drafted, and each
matched exactly.

| Commit | File | Text |
|---|---|---|
| `cf4f524` | `PROTOCOL.md` | 11.9 (Part 1), 127 lines |
| `9e69644` | `PROTOCOL_LANL.md` | LA8 (Part 2), 8 lines |

---

## Task K. Authentication dataset (RBA)

**How construction (a) was rebuilt.**
- `ml/train_from_dataset.fit_frequency_maps` on the non-attack dev_train
  rows (`eval.phase4b.frame`), as `eval.phase4b.prepare` does, without its
  scaler.
- Scored-row keys are derived exactly as `eval.phase3_rules.raw_features`
  derives them for the model features.
- A row's indicator is 1 when its key is absent from the (a) artefact.
- Label: `Stream.truth` (Is Attack IP or Is Account Takeover).

**Key-count check (`K/key_count_check`).** The rebuilt counts equal the
stored construction (a) record in `amendment11_controls.json
control/real_construction_a_seed42`:
- 3,672,966 map rows
- 925,137 IP-map keys and 925,137 known IPs
- 985,535 user keys
- 218 country-map keys and 218 known countries
- 6 device keys

### K1. Fitted artefacts of construction (a) keyed on an entity (`K/K1_artefacts`)

| Artefact | Key field | Model input | Named in 11.9.4's list |
|---|---|---|---|
| `ip_freq_map` | source address (`IP Address`, stripped) | `ip_freq` | yes |
| `known_ips_set` | source address (`IP Address`) | `is_new_ip` | yes |
| `user_freq_map` | account (`User ID`) | `user_freq` | **no**: reported because 11.9.4's definition covers every entity-keyed artefact |
| `country_freq_map` | country (missing → `XX`, stripped) | `country_freq` | yes |
| `known_countries_set` | country (missing → `XX`) | `is_new_country` | no (shares its key with `country_freq_map`) |
| `device_freq_map` | device type (missing → `Unknown`, stripped) | `device_freq` | yes |

**Shared keys.** `ip_freq_map` and `known_ips_set` give identical indicators
on every scored row. So do `country_freq_map` and `known_countries_set`.
Each pair is reported once (`K/indicator_groups_identical_on_scored_rows`).

### K2. Indicator against the real attack label (`K/K2/<group>/<split>`)

| Artefact group | Split | ROC-AUC | PR-AUC | Share of rows set | Precision | Recall | Rows / positives / set |
|---|---|---|---|---|---|---|---|
| source address: `ip_freq_map` + `known_ips_set` | val_a | 0.8344363448932567 | 0.26660474988221505 | 0.40298195970146605 | 0.2666060016438264 | 0.9999921355825567 | 1,183,517 / 127,155 / 476,936 |
| source address: `ip_freq_map` + `known_ips_set` | val_b | 0.8223212188891391 | 0.22956628358860326 | 0.41708054883809625 | 0.22956628358860326 | 1.0 | 1,153,710 / 110,465 / 481,190 |
| account: `user_freq_map` | val_a | 0.5468085519485351 | 0.11854206243365317 | 0.35278242729086273 | 0.13288577423094242 | 0.4363414730053871 | 1,183,517 / 127,155 / 417,524 |
| account: `user_freq_map` | val_b | 0.5451571504235861 | 0.10529322758641081 | 0.3699421865113417 | 0.11688448615998838 | 0.45160910695695466 | 1,153,710 / 110,465 / 426,806 |
| country: `country_freq_map` + `known_countries_set` | val_a | 0.49999905335481587 | 0.1074382539498799 | 1.68987855687751e-06 | 0.0 | 0.0 | 1,183,517 / 127,155 / 2 |
| country: `country_freq_map` + `known_countries_set` | val_b | 0.4999995207261957 | 0.09574763155385668 | 8.667689454022241e-07 | 0.0 | 0.0 | 1,153,710 / 110,465 / 1 |
| device: `device_freq_map` | val_a | 0.5 | 0.1074382539498799 | 0.0 | undefined (no row set) | 0.0 | 1,183,517 / 127,155 / 0 |
| device: `device_freq_map` | val_b | 0.5 | 0.09574763155385668 | 0.0 | undefined (no row set) | 0.0 | 1,153,710 / 110,465 / 0 |

ROC-AUC and PR-AUC are computed with sklearn, ties averaged, as in the
entity-lookup references of amendment 10, 11.4 and LA6.

The source-address indicator is set on 40% to 42% of scored rows. It covers
essentially every attack row (recall 0.99999 and 1.0), but it also covers
many benign rows from addresses not seen in the warm-up period, which is the
churn that 11.9.4 anticipated. Its ROC-AUC (0.834 and 0.822) is therefore
below the amendment 10 lookup (0.9646 and 0.9550), which is a different
indicator.

---

## Task L. Enterprise dataset (LANL), per LA8

### L1. Rebuild and check (`L/L1_key_count_check`)

The LA6.1 construction (a) counts were rebuilt with
`eval.lanl_la6.fit_counts` (label `F`) from the per-day codes of days 0 to 7.

| Field | Keys only in (c), rebuilt | Declared in 11.9.4 | Stored (`lanl_la6_controls.json artefacts/F/<field>/keys_only_in_c`) | (a) map keys, rebuilt / stored |
|---|---:|---:|---:|---|
| source computer | 298 | 298 | 298 | 11,194 / 11,194 |
| source user | 76 | 76 | 76 | 11,994 / 11,994 |
| destination computer | 280 | 280 | 280 | 2,444 / 2,444 |

The (a) fitting rows also match: 18,093,778 rebuilt, 18,093,778 stored
(`artefacts/F/fitting_rows_a`). Every check is equal, so the task continued.
The rebuild and check took 1.1 s; the whole stage took 28.7 s.

**Shared key.** `is_new_src` comes from the known-source-computer set, which
has the same keys as the source-computer frequency map. It is reported once,
under source computer.

### L2. Indicator against the induced label (primary) and the true red-team label (`L/L2/<scope>/<field>/...`)

Scored rows: 8,569,072 on days 8–11 and 6,383,434 on days 12–13.

Positive rows:
- Induced label: 241,698 on days 8–11 and 168,990 on days 12–13.
- True label: 266 on days 8–11 and 282 on days 12–13.

| Scope | Artefact | Label | ROC-AUC | PR-AUC | Share of rows set | Precision | Recall | Rows set |
|---|---|---|---|---|---|---|---|---:|
| days 8–11 | source computer (`src_freq`, `is_new_src`) | **induced** | 0.7792778273974976 | 0.39832641282303755 | 0.023422022828142885 | 0.6818714033033557 | 0.5662231379655603 | 200,705 |
| days 8–11 | source computer | true | 0.4976874130395114 | 3.0926648167964466e-05 | 0.023422022828142885 | 2.4912184549463142e-05 | 0.018796992481203006 | 200,705 |
| days 8–11 | source user (`user_freq`) | **induced** | 0.9984713668438574 | 0.90470397556493 | 0.031176888232471382 | 0.90470397556493 | 1.0 | 267,157 |
| days 8–11 | source user | true | 0.9844265933900243 | 0.0009956692132341656 | 0.031176888232471382 | 0.0009956692132341656 | 1.0 | 267,157 |
| days 8–11 | destination computer (`dst_freq`) | **induced** | 0.5422384467262575 | 0.10583981068134336 | 0.0025238438888131646 | 0.9456697646460442 | 0.08461799435659377 | 21,627 |
| days 8–11 | destination computer | true | 0.7412267691925858 | 0.0029086751277896724 | 0.0025238438888131646 | 0.005964766264391732 | 0.4849624060150376 | 21,627 |
| days 12–13 | source computer | **induced** | 0.787926745726944 | 0.291417001929674 | 0.03326657720593649 | 0.4726001271455817 | 0.5938753772412568 | 212,355 |
| days 12–13 | source computer | true | 0.4957778723944686 | 4.3898507672909806e-05 | 0.03326657720593649 | 3.2963669327305694e-05 | 0.024822695035460994 | 212,355 |
| days 12–13 | source user | **induced** | 0.9960934558264585 | 0.7768083698010517 | 0.03407946255886722 | 0.7768083698010517 | 1.0 | 217,544 |
| days 12–13 | source user | true | 0.9829816053260207 | 0.0012962894862648476 | 0.03407946255886722 | 0.0012962894862648476 | 1.0 | 217,544 |
| days 12–13 | destination computer | **induced** | 0.5320490978865547 | 0.07764238041223188 | 0.0020817948458462954 | 0.8200015050041387 | 0.06448310550920172 | 13,289 |
| days 12–13 | destination computer | true | 0.6142123750702804 | 0.0011614131225144665 | 0.0020817948458462954 | 0.00489126345097449 | 0.23049645390070922 | 13,289 |

Against the induced label, the source-user indicator has recall exactly 1.0
in both scopes, as 11.9.4 stated would follow by construction.

### L3. Ordering, as an observation only

**Values of L used for the comparison:**
- **RBA, real label, seed 42:** 0.9850456188746078 on val_a and
  0.975813500712719 on val_b (`amendment11_6_controls.json real/halves/<split>/L`).
- **LANL, LA6.1, seeds 42 / 43 / 44:**
  - days 8–11: −0.10555849278790352, −0.1131463428954832 and −0.189817748320177.
  - days 12–13: 0.07738531621955692, 0.0650501690080084 and 0.007919480751991075.
  - Source: `lanl_la6_controls.json F/<scope>/per_seed/seed_s/L`.

**The ordering:**
- **The artefact on the labelled entity's own key** (the RBA source address,
  the LANL source user) separates the label more strongly on the enterprise
  dataset (ROC-AUC 0.998 and 0.996 against the induced label, 0.984 and
  0.983 against the true label) than on the authentication dataset (0.834
  and 0.822).
- **L orders the other way:** near 1 on the authentication dataset, near 0
  on the enterprise dataset.
- **The ordering of the absence indicator is the reverse of L's.** Under
  11.9.4, the paper reports this.
- **The indicator is also strongly predictive on both datasets**, at least
  0.82 on every entity-own-key artefact and split, while L is high on only
  one. In 11.9.4's terms: the presence of this information in the artefacts
  does not predict whether the mechanism occurs.

No explanation for the enterprise non-reproduction is claimed, and 11.9.3
stands.

---

## Task M. The share the Task H contrast represents

**Quantity:** (AUC_a − AUC_a′) / (AUC_a − 0.5) at model seed 42. It was not
declared in advance, it was computed after the controls were seen, and no
pass or fail is attached (`M/splits/<split>/<draw>/prediction` = null).

**Bootstrap:**
- The Task H bootstrap was rerun under the same specification
  (`eval.amendment11_7_la7.paired_bootstrap`): 1,000 resamples of source
  addresses, `Generator(PCG64(42))`.
- The numerator and the denominator use the same resampled rows, and the
  share is recomputed on each resample.
- **Reproduction:** for all six cases, the rerun interval on the difference
  equals the Task H interval exactly
  (`M/splits/<split>/<draw>/difference_interval_reproduces` = true).
- All 1,000 resamples were valid in every case.

| Split | Draw | AUC_a | AUC_a′ | AUC_a − AUC_a′ [95% interval] | Share | 95% interval on the share |
|---|---|---|---|---|---|---|
| val_a | 11 | 0.762999627767321 | 0.7292500101682221 | 0.03374961759909889 [0.025319638453121285, 0.04243628443608322] | 0.1283257238255774 | [0.09760252165439029, 0.15767307823030302] |
| val_a | 12 | 0.762999627767321 | 0.7248520477590753 | 0.038147580008245696 [0.02936357430007542, 0.0466984387075994] | 0.14504803802230218 | [0.11290074530013557, 0.17585469224065264] |
| val_a | 13 | 0.762999627767321 | 0.7231221273804145 | 0.03987750038690652 [0.03305694475589224, 0.04608344661930493] | 0.15162569135720083 | [0.12784827662480608, 0.17447622101897162] |
| val_b | 11 | 0.750421331271785 | 0.7032710813798777 | 0.0471502498919073 [0.03607211498568382, 0.05761727468620961] | 0.18828368035762347 | [0.14649589608689692, 0.22670370278423635] |
| val_b | 12 | 0.750421331271785 | 0.6998297292742648 | 0.05059160199752022 [0.041008198209100497, 0.060335721582056974] | 0.20202592862431756 | [0.16678969303544058, 0.23882317652723944] |
| val_b | 13 | 0.750421331271785 | 0.700777514569204 | 0.049643816702581 [0.040018808232813716, 0.059618799832901345] | 0.1982411659999604 | [0.16354036703326166, 0.23690161838926108] |

**Sources:**
- AUC_a: `amendment11_7_la7.json H/splits/<split>/auc_a/value`.
- AUC_a′: `.../<draw>/auc_a_prime/value`.
- Difference: `.../<draw>/difference_a_minus_a_prime`.
- Share and its interval: `M/splits/<split>/<draw>/share` and `.../share_interval`.

Bootstrap runtime: 159.5 s on val_a and 153.2 s on val_b.

**Reading.** Between 0.128 and 0.152 of the real construction's
above-chance ranking on val_a, and between 0.188 and 0.202 on val_b, is not
reproduced by a distribution-matched label with no attack content. That is
the descriptive reading of this quantity and nothing more.
