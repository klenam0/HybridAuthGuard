# Phase 4b report: the open ML questions from Phase 4

Branch `improve-phase4b`, created from `improve-phase4` (2e1c0fc). The working tree was clean at the start. Not pushed and not merged.

| Commit | Step |
|---|---|
| 24bb778 | 4b.1: amendment 5, committed on its own before any Phase 4b metric |
| c255fe1 | 4b.3: `eval/phase4b.py`, stages `diag`, `select`, `confirm`, `supervised` |
| 227b686 | D1 (variants a, b, c) and the candidates' dev_train thresholds |
| 4a12375 | `select` on val_a: **no candidate qualifies** |
| 29ea02d | `confirm` on val_b |
| c1ae952 | Supervised generalisation |
| 2f46707 | Legacy gate, byte-identical |

**Test-set rule held.** `load("test")` was never called and `FINAL_EVAL` was never set. `results/test_access.log` does not exist. `python -m eval.lock_test --verify` reports `test lock MATCHES`.

**Rules frozen.** No rule setting changed. The frozen rule incidents come from the same cached `phase3b_cache/chosen_rules.npz`.

**`model_v4.pkl` unchanged.** No candidate qualified, so the Phase 4 fallback stays: `alerting = False`, sha256 `7a6aab63…d8d0`, the same as Phase 4. Because nothing qualified:
- `workload` was not rerun;
- the real-agent replay was not needed and was not run.

Raw results in `backend/results/`:
- `phase4b_diag.json`
- `phase4b_thresholds.json`
- `phase4b_selection.json`
- `phase4b_select_timings.json`
- `phase4b_confirm.json`
- `phase4b_supervised.json`
- `phase4b_gate_legacy.txt`

The two new forest score arrays are in `results/phase4_cache/score_p2var_{b,c}.npy` (gitignored). Everything else was reused from `phase4_cache/`: the feature matrix, Freeman risks, HGB scores and thresholds.

## 1. Amendment 5 (`eval/PROTOCOL.md`, 24bb778)

It states the three questions and says openly that the candidates were proposed **after** seeing Phase 4's val_a results, and that val_b had not been computed for any of them. Its content:
- **D1:** three variants of the Phase 2 forest, as listed in the prompt.
- **Candidates:**
  - C1 = D1 (c);
  - C2 = Freeman with the placeholder ID set to the column minimum;
  - C3 = ASN failure ratio, IP failure ratio, and their maximum, higher meaning riskier.
- **Rules from amendment 4, unchanged:** thresholds, criterion, bars and ties. The choice is among C1 to C3 only.
- **Supervised measurement:** the cached HGB scores on cold IPs, new attackers and excluding the placeholder.

Decisions I wrote into the amendment, all before any metric:
- **D1 score.** Score = −`score_samples`, a constant shift of −decision, so the quantile thresholds pick the same events.
- **When (c) gets val_b.** D1 (c)'s val_b numbers are computed only in `confirm`, because (c) is also candidate C1.
- **C2's placeholder value.** The minimum of each beta's column over all development events.
- **New attackers.** Events whose IP has no attack-labelled dev_train event; benign events stay in as negatives.
- **HGB fits reported.** The prompt says "the four existing HGB fits", but eight exist (two feature sets × four settings). I report all eight and mark the two Phase 4 reference settings. Each fit uses its feature set's reference-row quantile: 20% for A–E, 10% without D.

## 2. Diagnostic D1: where the Phase 2 forest's ROC-AUC came from

The rebuild uses the exact Phase 2 code: `Prepared`, `fit_frequency_maps`, `extract_features_freq`, `StandardScaler`, and an Isolation Forest with 200 trees, 100k samples, contamination 0.4 and seed 42, scored with the 30-day v3 `failed_rate`. **Check: variant (a) refitted with this code is bit-identical to the cached `ml_decision_v3.npy`** (max abs diff 0.0).

| Variant | Maps / known sets from | Fit on | Known IPs | val_a ROC-AUC | val_a PR-AUC | val_a TPR @ 1% FPR | val_b ROC-AUC | val_b PR-AUC | val_b TPR @ 1% FPR |
|---|---|---|---|---|---|---|---|---|---|
| (a) original | 3,672,966 non-attack rows | non-attack rows | 925,137 | **0.763** | 0.193 | 0.0026 | **0.750** | 0.167 | 0.0028 |
| (b) | 4,055,357 rows (all) | non-attack rows | 947,226 | 0.553 | 0.113 | 0.0043 | 0.555 | 0.101 | 0.0041 |
| (c) label-free = C1 | all rows | all rows | 947,226 | **0.504** | 0.101 | 0.0024 | **0.506** | 0.090 | 0.0028 |

Base rates: val_a 0.107, val_b 0.096. The (c) val_b row was computed in `confirm`, after the choice was on disk.

- **Leak through the maps and known-IP set, (b) − (a):** −0.210 ROC-AUC on val_a and −0.195 on val_b.
- **Leak through the fit rows, (c) − (b):** −0.049 and −0.049.
- **The fully label-free forest ranks at chance** (0.504 / 0.506), and its PR-AUC equals the base rate.
- The maps differ by only 22,089 IPs, those seen only in attack-labelled rows. The label is a per-IP blocklist, so those IPs keep coming back in val. Variant (a) sees them as "new IP, frequency 0", which is the label in disguise.

## 3. Selection on val_a (C1–C3) and confirmation on val_b

**No candidate meets the criterion: 0 of 56 rows.**
- The best lower bound, among rows with at least 30 incremental incidents, is **C3 ASN failure ratio at q = 0.1%: 0.108**, against the 0.2149 bar.
- The Phase 4 fallback therefore stays in `model_v4.pkl` with `alerting = False`.
- `select` was run twice. The selection files were byte-identical (md5 `98a71c10…7dfb`); only the timings file differed.

The table shows each family's best row by lower bound; the lower bound is the bracket's first number. The 95% CIs are IP-clustered. "Inc." is incremental incidents; "att. IPs" is attacking IPs in incremental incidents.

| Row | q | val_a inc. | val_a incr. precision [CI] | val_a att. IPs | val_b inc. | val_b incr. precision [CI] | val_b att. IPs | val_a (bar 0.2149) | val_b bar 0.1915 | val_b bar 0.2149 |
|---|---|---|---|---|---|---|---|---|---|---|
| **Best lower bound = best C3**: ASN fail ratio (with D) | 0.1% | 1,514 | 0.130 [0.108, 0.152] | 142 | 1,397 | 0.121 [0.100, 0.143] | 129 | fails | fails | fails |
| Best C1: Phase 2 forest, label-free (without D) | 5% | 9,172 | 0.059 [0.053, 0.065] | 474 | 9,992 | 0.057 [0.051, 0.063] | 498 | fails | fails | fails |
| Best C2: Freeman without placeholder, β = 8 (without D) | 5% | 149,981 | 0.021 [0.020, 0.022] | 2,681 | 145,234 | 0.022 [0.021, 0.023] | 2,702 | fails | fails | fails |

Secondary metrics. "Alerts" are ML alerts after de-duplication, with ML-alone alert precision and its CI.

| Row | val_a ROC / PR / TPR@1% | val_a alerts, precision [CI] | val_b ROC / PR / TPR@1% | val_b alerts, precision [CI] |
|---|---|---|---|---|
| C3 ASN fail ratio, q 0.1% | 0.726 / 0.169 / 0.006 | 2,508, 0.160 [0.103, 0.247] | 0.736 / 0.157 / 0.007 | 2,351, 0.152 [0.104, 0.223] |
| C1, q 5% | 0.504 / 0.101 / 0.002 | 24,652, 0.105 [0.092, 0.120] | 0.506 / 0.090 / 0.003 | 25,897, 0.090 [0.078, 0.103] |
| C2 β = 8, q 5% | 0.468 / 0.106 / 0.002 | 248,378, 0.105 [0.099, 0.111] | 0.465 / 0.094 / 0.003 | 233,478, 0.095 [0.090, 0.100] |

Other rows, val_a only, each at its best lower bound:

| Row | q | Lower bound | ROC-AUC |
|---|---|---|---|
| C3 IP fail ratio | 30% | 0.046 | 0.650 |
| C3 maximum of the two ratios | 30% | 0.053 | 0.631 |
| C2 β = 0.5 | 5% | 0.019 | 0.461 |
| C2 β = 2 | 5% | 0.020 | 0.465 |

C3 ASN failure ratio across the quantiles on val_a:

| q | Incremental incidents | Precision | Lower bound | Att. IPs |
|---|---|---|---|---|
| 0.1% and 0.5% (identical alert sets) | 1,514 | 0.130 | 0.108 | 142 |
| 1% and 2% (identical) | 1,631 | 0.123 | 0.101 | 145 |
| 5% | 11,246 | 0.102 | 0.096 | 1,045 |
| 10% | 35,747 | 0.111 | 0.107 | 2,866 |
| 20% | 63,067 | 0.084 | 0.082 | 3,969 |
| 30% | 68,087 | 0.080 | 0.077 | 4,055 |

## 4. Supervised generalisation (cached HGB scores, no refits)

There are three subsets, each restricted to that half's events.
- **"Cold IPs":** IPs absent from dev_train.
- **"New attackers":** IPs with no attack-labelled dev_train event; the subset includes benign IPs, known or new.
- **"Excl. placeholder":** every event except those of the placeholder ID.

Subset sizes:

| Half | Subset | Events | Attack events | Base rate | Attacking IPs |
|---|---|---|---|---|---|
| val_a | all | 1,183,517 | 127,155 | 0.107 | 9,423 |
| | cold IPs | 358,781 | 8,999 | 0.025 | 3,951 |
| | new attackers | 1,065,360 | 9,000 | 0.008 | 3,952 |
| | excl. placeholder | 712,674 | 66,034 | 0.093 | 5,979 |
| val_b | all | 1,153,710 | 110,465 | 0.096 | 9,477 |
| | cold IPs | 380,658 | 9,933 | 0.026 | 4,244 |
| | new attackers | 1,053,178 | 9,933 | 0.009 | 4,244 |
| | excl. placeholder | 708,207 | 57,993 | 0.082 | 6,066 |

The table below shows the two reference settings; all eight fits are in `phase4b_supervised.json`. "Flagged" counts attacking IPs with an ML alert on one of their attack events in the subset.

| Fit (q) | Half | Subset | ROC / PR / TPR@1% | ML alerts, precision [CI] | Incremental inc., precision [CI] | Att. IPs flagged |
|---|---|---|---|---|---|---|
| HGB A–E, lr 0.1, 15 leaves (20%) | val_a | cold IPs | 0.776 / 0.094 / 0.085 | 350, 0.414 [0.266, 0.556] | 86, 0.488 [0.384, 0.595] | 58 / 3,951 |
| | | new attackers | 0.649 / 0.011 / 0.000 | 73,163, 0.002 [0.001, 0.003] | 5,809, 0.007 [0.005, 0.010] | 58 / 3,952 |
| | | excl. placeholder | 0.865 / 0.338 / 0.103 | 55,267, 0.316 [0.300, 0.332] | 3,995, 0.258 [0.243, 0.275] | 1,890 / 5,979 |
| | val_b | cold IPs | 0.772 / 0.096 / 0.080 | 569, 0.411 [0.318, 0.504] | 154, 0.325 [0.253, 0.400] | 91 / 4,244 |
| | | new attackers | 0.716 / 0.016 / 0.010 | 15,363, 0.015 [0.010, 0.021] | 3,312, 0.015 [0.011, 0.020] | 91 / 4,244 |
| | | excl. placeholder | 0.841 / 0.289 / 0.105 | 12,803, 0.371 [0.350, 0.393] | 2,750, 0.267 [0.245, 0.288] | 1,261 / 6,066 |
| HGB without D, lr 0.05, 63 leaves (10%) | val_a | cold IPs | 0.646 / 0.057 / 0.055 | 728, 0.227 [0.156, 0.313] | 135, 0.519 [0.437, 0.600] | 103 / 3,951 |
| | | new attackers | 0.538 / 0.010 / 0.017 | 67,722, 0.002 [0.002, 0.004] | 317, 0.221 [0.177, 0.270] | 103 / 3,952 |
| | | excl. placeholder | 0.823 / 0.268 / 0.043 | 61,678, 0.288 [0.271, 0.305] | 196, 0.194 [0.140, 0.254] | 1,098 / 5,979 |
| | val_b | cold IPs | 0.674 / 0.057 / 0.052 | 857, 0.223 [0.178, 0.275] | 160, 0.463 [0.387, 0.537] | 136 / 4,244 |
| | | new attackers | 0.577 / 0.010 / 0.009 | 53,842, 0.004 [0.003, 0.004] | 366, 0.202 [0.164, 0.246] | 136 / 4,244 |
| | | excl. placeholder | 0.826 / 0.258 / 0.049 | 48,555, 0.281 [0.264, 0.298] | 217, 0.152 [0.102, 0.202] | 1,003 / 6,066 |

Across the other six fits, new-attacker ROC-AUC ranges over:
- 0.649–0.693 on val_a and 0.716–0.751 on val_b with D;
- 0.537–0.538 and 0.573–0.577 without D.

At most **168 of 3,952** new attacking IPs are flagged on val_a (4.3%, A–E lr 0.1, 63 leaves) and **208 of 4,244** on val_b.

**Answer to the question: the supervised model does not generalise to new attacking IPs.**
- Its bar-clearing performance comes from IPs whose attack label it already saw in dev_train.
- On new attackers it flags 1.5% (val_a) and 2.1% (val_b) of attacking IPs at the reference setting.
- Its alerts in that subset are 99.8% (val_a) and 98.5% (val_b) benign.

## 5. Code inspection: label-filtered maps, known sets or training rows

Every one of these follows the same pattern: rows are split by `Is Attack IP | Is Account Takeover`, and the frequency maps, known-IP and known-country sets, scaler and Isolation Forest come only from the non-attack rows. None of the old batches was rerun; this section only reports which numbers depend on the pattern.

### The label filter itself

| # | File:line | What is filtered | Published numbers that depend on it |
|---|---|---|---|
| 1 | `ml/train_from_dataset.py:100` | Normal pool = `chunk[~is_any_attack]` (attack pool at `:105`). | Everything below that builds on `train_from_dataset`. |
| | `ml/train_from_dataset.py:137` | `train_df` taken from the normal pool only. | |
| | `ml/train_from_dataset.py:211–220` | Maps and known sets, scaler and IF fit on that `train_df`. | The deployed `data/model.pkl`, and so the legacy-mode ML and the legacy gate's E8 reproduction. |
| 2 | `ml/train_from_dataset_v2.py:154` | Normal pool (attack pool at `:160`). | Batch 1 (leakage experiments). |
| | `ml/train_from_dataset_v2.py:242` | Temporal split: `train_df` from the normal pool. | |
| | `ml/train_from_dataset_v2.py:274` | User-disjoint split: `train_df` from the normal pool. | |
| | `ml/train_from_dataset_v2.py:309–312` | Label encoders fitted on that `train_df` (raw-ID features of `ml/legacy_features.py`). | |
| | `ml/train_from_dataset_v2.py:325–336` | Scaler and IF fit. | |

### Callers of the filter

| # | File:line | What it does | Published numbers that depend on it |
|---|---|---|---|
| 3 | `ml/legacy_features.py` (whole file) | No filter of its own. Its encoders and known sets are passed in from #2 (`:309–312`), so it inherits the filter. | Batch 1 |
| 4 | `ml/train_from_dataset_v3.py:98` | Imports `stream_dataset` and the splits from v2. | Batch 2 (encoding comparison, contamination tuning that chose 0.4) |
| | `ml/train_from_dataset_v3.py:246` | Maps from the normal-only `train_df`. | |
| | `ml/train_from_dataset_v3.py:186–196` | Scaler and IF fit. | |
| 5 | `ml/train_from_dataset_v3_extend.py:160–167` | Same splits. | Batch 2 grid extension |
| | `ml/train_from_dataset_v3_extend.py:93` | Maps from the normal-only rows. | |
| 6 | `ml/evaluate_hybrid_and_baselines.py:475–487` | v2 split, maps from `train_df`, IF fit. | Batch 3 hybrid and baselines (LOF and autoencoder fitted on the same rows, `:418`, `:437`) |
| | `ml/evaluate_hybrid_batch37.py:393–403` | Same. | Batch 3.7 |
| | `ml/evaluate_hybrid_batch38.py:58–67` | Same. | Batch 3.8 |
| | `ml/evaluate_hybrid_batch39.py:129–139` | Same. | Batch 3.9 (0.7449 in `batch3_9_final_sweep_results.json`) |
| | `ml/evaluate_hybrid_campaign_and_cooldown.py:253–263` | Same. | Campaign / cooldown batch |
| | `ml/evaluate_hybrid_fix.py:282–292` | Same. | Hybrid fix batch |
| 7 | `ml/batch4_baselines_and_diagnostics.py:409` | v2 user-disjoint split. | **Batch 4: IF ROC-AUC 0.755** (`batch4_summary.txt`, full10, split A; 0.773 split B; 0.731 / 0.750 without `user_freq`) |
| | `ml/batch4_baselines_and_diagnostics.py:416` | Maps from the normal-only `train_df`. | The single-feature ROC-AUCs (`is_new_ip` and `ip_freq` 0.790 are this same leak, measured directly) |
| | `ml/batch4_baselines_and_diagnostics.py:270–277` | Scaler and IF on those rows; LOF (`:296–298`) and autoencoder (`:309–313`) too. | LOF and autoencoder rows |
| 8 | `ml/batch5_hybrid_ci_and_blocking.py:313` | Split. | **Batch 5**: hybrid recall, FPR and their CIs, benign IPs blocked, users affected |
| | `ml/batch5_hybrid_ci_and_blocking.py:319–321` | Maps, scaler. | |
| | `ml/batch5_hybrid_ci_and_blocking.py:291–293` | IF fit. | |
| 9 | `ml/batch5b_deployed_policy.py:104–108` | Split, maps, scaler and IF, all from the normal-only `train_df`. | **Batch 5b** (deployed-threshold policy, 10,071 users affected, campaign recall 0.5998) |
| 10 | `eval/phase2_baseline.py:86` | `tr = df.iloc[:n_train][~truth[:n_train]]`. | **Phase 2**: IF ROC-AUC **0.745** / PR-AUC 0.171 (seeds 42–44) |
| | `eval/phase2_baseline.py:129–134` | `Prepared`: maps, known sets and scaler from `tr`. | Hybrid metrics, TPR at 1% FPR, dev_val_cold results |
| | `eval/phase2_baseline.py:166` | Fit. | |
| 11 | `eval/phase3_rules.py:562` | `train_frame`: the same `~S.truth` filter. | **Phase 3**: ML step ROC-AUC 0.757 (v3 `failed_rate`) and its criterion verdict |
| | `eval/phase3_rules.py:582` | `Prepared`. | |
| | `eval/phase3_rules.py:601` (fit) and `:616` (save) | Fit; `ml_decision_v3.npy` saved. | |
| 12 | `eval/phase3b.py:47` | Loads `ml_decision_v3.npy` (no new filter, inherits #11). | **Phase 3b**: ML-alone alert criterion ("fails by 0.0003"); the "+ Phase 2 ML" workload rows; budget curves (e.g. 0.438 at B = 100, the gain over rules alone) |
| 13 | `eval/phase4.py:249` | Candidate 1 = cached `ml_decision_v3.npy` (inherits #11, as amendment 4 states). | **Phase 4**: Phase 2 forest row (0.763 / 0.750); "best without D"; its strata; the "+ Phase 2 ML" workload and budget rows |

**Not affected:**
- `ml/anomaly_model.py`:
  - `train()` (`:357`) fits on a synthetic normal-only JSON file, not the RBA labels; it is the runtime fallback.
  - The runtime feature path (`:290`, `:307`) only looks up maps loaded from `model.pkl`, so it inherits #1.
- The Phase 4 features (`ml/features_v4.py`) and the Phase 4 forests: no label is read.
- The v3 rules.

**A second, separate label dependence in the Batch 1–5b evaluations.**
- Their validation and test sets are built from a "normal pool" and an "attack pool" chosen by label, with fixed targets (`train_from_dataset.py:100–107`, `train_from_dataset_v2.py:153–163`). So the evaluation mix of attack and benign rows is set by the label, not by the stream.
- This is not training leakage, but the base rates and precision in those batches are not stream base rates. For example, Batch 4's PR-AUC of 0.50 sits on an attack mix of about 33% (implied by its P, R and FPR).

## 6. Gates

| Gate | Result |
|---|---|
| Full suite | **47 passed** (122.5 s) |
| Legacy gate | `phase4b_gate_legacy.txt` md5 **`f925b387a116ee65b5e066939da40f93`**, byte-identical to Phase 4 |
| `eval.lock_test --verify` | `test lock MATCHES`; no `test_access.log` |
| `model_v4.pkl` | unchanged (sha256 `7a6aab63…d8d0`) |
| Replay | not required (no C2/C3 chosen), not run |

## 7. Runtimes

Every command was estimated under 10 minutes and finished under 10 minutes, so no advance notice was needed. Nothing overran.

| Step | Time |
|---|---|
| `diag --check-a` (refit (a), compare with the cache) | 203 s |
| `diag --variants b` | 212 s (fit + score 196 s) |
| `diag --variants c` | 221 s (fit + score 203 s) |
| `select` (56 rows) | 125 s; second run for the reproducibility check about the same |
| `confirm` | 21 s |
| `supervised` (8 fits × 2 halves × 4 subsets) | 58 s |
| Legacy gate / full suite | 27 s / 123 s |

## 8. Results against expectations / anything unexpected

1. **The Phase 2 forest's ranking was almost entirely label leakage.**
   - What I expected: Phase 4's report suspected "part of it". In fact, with maps from all rows its ROC-AUC falls from 0.763 to 0.553, and fully label-free it is 0.504 on val_a and 0.506 on val_b, which is chance.
   - Magnitudes: the maps and known-IP set carry about 0.21, the fit rows about 0.05.
   - Wider consequence: no label-free version of the Phase 2 design has shown any event-ranking ability on this data. The "+ Phase 2 ML" budget gains in Phases 3b and 4 (for example 0.438 vs 0.246 at B = 100) and every Phase 2–4 statement about the forest adding anomaly signal rest on that leak.
2. **Unexpected: removing the leak barely changes incremental precision.**
   - The label-free forest (C1, q 5%) has incremental precision 0.059 [0.053, 0.065] with 474 attacking IPs. The leaky original has 0.060 [0.055, 0.065] with 517.
   - The leaked signal (returning blocklisted IPs look "new") seems to mostly flag IPs the frozen rules already cover. This fits the Phase 4 finding that the forest adds nothing incremental. I have not tested this reading beyond the numbers above.
3. **Freeman without the placeholder ranks below chance** (ROC-AUC 0.461–0.468), not near 0.5.
   - On real accounts, attack events are less novel per user than benign ones, the same direction as "new IP for user" (0.475) in Phase 4.
   - Users with no history all score log risk 0, so ties at the threshold make the q = 5% rows alert on about 250,000 events. At smaller q they alert far less, with lower bounds around 0.02 at most.
   - Excluding the placeholder removed the artefact Phase 4 found, but it left no signal.
4. **The ASN failure ratio, read in the a priori direction, is the strongest label-free ranking signal found in Phases 4 and 4b:** ROC-AUC 0.726 on val_a and 0.736 on val_b. That is close to the leaky Phase 2 forest, with no label use.
   - Its very top (q 0.1%, 2,508 alerts) still reaches only 0.130 incremental precision (lower bound 0.108 against 0.2149), and val_b holds the same level (0.121 [0.100, 0.143]).
   - Its alert sets are coarse: q 0.1% = 0.5% and 1% = 2%, because whole ASNs share one ratio.
   - It is a ranking signal, not an alerting one. It is a better candidate for Phase 5's ranking role than the Phase 4 fallback (D-alone forest, ROC-AUC 0.548 / 0.652). By protocol, the fallback remains the one recorded.
   - Direction of the ratios: the IP failure ratio alone (0.650) and the maximum of the two (0.631) are weaker than the ASN ratio alone. Phase 4's permutation result (the forest isolating IP failure ratio in the "wrong" direction) was a forest artefact, not a sign that the ratio points the other way.
5. **The supervised reference does not find new attackers.**
   - Most attack traffic in val comes from blocklisted IPs it saw in dev_train: 93% of val_a attack events and 58% of val_a attacking IPs.
   - Every val attacking IP that appears in dev_train was already attack-labelled there. "New attackers" equals the cold-IP attackers, differing by one IP on val_a and none on val_b.
   - On the remaining 3,952 / 4,244 new attacking IPs, the reference flags 58 / 91, and its alerts in that subset are under 2% precision.
   - So Phase 4's "the reference clears the bar, so signal exists" mostly means "the label is learnable from IP history", not that new attacks are detectable.
   - Two smaller observations:
     - Within cold IPs, the few alerts it does raise are precise (0.41 at the A–E reference, about 16× the cold-IP base rate), but there are only 350 / 569 of them.
     - The without-D model's incremental incidents on new attackers reach about 0.20–0.22 precision, but on only about 300–370 incidents and about 70 attacking IPs.
6. **Excluding the placeholder, the without-D reference no longer holds on val_b:** lower bound 0.102 against 0.1915. The A–E reference still holds (0.245).
7. **Process.**
   - All steps ran within their estimates.
   - `select` was byte-reproducible on a second run.
   - The amendment's "four HGB fits" became eight (a superset; section 1).
   - The only val_b numbers for ineligible models are D1 (a) and (b), as the amendment states.

Stopped here, as instructed.
