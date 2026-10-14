# Experiment results

Raw JSON output of the leakage-controlled re-evaluation. Each file is written
by the script named next to it (in `backend/ml/`); re-running that script
overwrites it here.

| File | Script | What it tests |
| --- | --- | --- |
| `leakage_fix_results_temporal.json` | `train_from_dataset_v2.py` | Batch 1: leakage fix, temporal split |
| `leakage_fix_results_user_disjoint.json` | `train_from_dataset_v2.py` | Batch 1: leakage fix, user-disjoint split |
| `leakage_fix_results_temporal_frequency.json` | `train_from_dataset_v3.py` | Batch 2: frequency encoding, temporal split |
| `leakage_fix_results_user_disjoint_frequency.json` | `train_from_dataset_v3.py` | Batch 2: frequency encoding, user-disjoint split |
| `leakage_fix_results_temporal_behavioral_only.json` | `train_from_dataset_v3.py` | Batch 2: behaviour-only ablation, temporal split |
| `leakage_fix_results_user_disjoint_behavioral_only.json` | `train_from_dataset_v3.py` | Batch 2: behaviour-only ablation, user-disjoint split |
| `leakage_fix_results_temporal_frequency_extended.json` | `train_from_dataset_v3_extend.py` | Batch 2.5: extended grid, frequency encoding, temporal split |
| `leakage_fix_results_user_disjoint_frequency_extended.json` | `train_from_dataset_v3_extend.py` | Batch 2.5: extended grid, frequency encoding, user-disjoint split |
| `leakage_fix_results_temporal_behavioral_only_extended.json` | `train_from_dataset_v3_extend.py` | Batch 2.5: extended grid, behaviour-only, temporal split |
| `leakage_fix_results_user_disjoint_behavioral_only_extended.json` | `train_from_dataset_v3_extend.py` | Batch 2.5: extended grid, behaviour-only, user-disjoint split |
| `batch3_hybrid_and_baselines_results.json` | `evaluate_hybrid_and_baselines.py` | Batch 3: hybrid vs Isolation Forest vs LOF, autoencoder, Random Forest |
| `batch3_5_hybrid_fix_results.json` | `evaluate_hybrid_fix.py` | Batch 3.5: the blocking-state fix |
| `batch3_6_campaign_and_cooldown_results.json` | `evaluate_hybrid_campaign_and_cooldown.py` | Batch 3.6: campaign recall and ML re-alert cooldown |
| `batch3_7_results.json` | `evaluate_hybrid_batch37.py` | Batch 3.7: operating-point frontier |
| `batch3_8_results.json` | `evaluate_hybrid_batch38.py` | Batch 3.8: internal-IP guard |
| `batch3_9_final_sweep_results.json` | `evaluate_hybrid_batch39.py` | Batch 3.9: final sweep, prevalence table, and ROC/PR/histogram curve data |

Batch 1 (`train_from_dataset_v2.py`) reproduces the original raw-ID baseline
using `backend/ml/legacy_features.py`, the label-encoder feature extraction
copied verbatim from the pre-revision pipeline (commit 48c66c0). The deployed
model does not use it.

All scripts read the RBA Dataset CSV from `RBA_DATASET_PATH` (set in
`backend/.env`), defaulting to `backend/data/rba-dataset.csv`.

## Label dependence of the legacy model (`data/model.pkl`)

`data/model.pkl`, the legacy-mode Isolation Forest (`ML_MODE = "legacy"`), was
trained by `ml/train_from_dataset.py` with **label-filtered rows**: the
training pool is `chunk[~is_any_attack]` (`train_from_dataset.py:100`,
`:137`), so its frequency maps, known-IP and known-country sets, scaler and
forest were all fitted on the rows whose `Is Attack IP` / `Is Account
Takeover` labels are false (`:211-220`). Its features therefore encode "seen
in the label-free part of training", which on this dataset is mostly the
label itself: the label is a per-IP blocklist, and attacking IPs that recur
look "new" to the model. Phase 4b (`audit_scratch/PHASE4B_REPORT.md`, section
2 and section 5) measured this on the Phase 2 rebuild of the same design:
val_a ROC-AUC 0.763 with label-filtered maps and fit, 0.553 with maps from all
rows, and 0.504 (chance) fully label-free. Every Batch 1-5b and Phase 2-3b
number that uses this design inherits the dependence (Phase 4b section 5
lists them by file and line). The legacy model is kept only so the legacy
reproduction gate stays byte-identical; the default configuration
(`RULES_MODE = "v3"`, `ML_MODE = "v4"`) does not load it.

## Phase 5 (incident triage and response policy)

| File | Stage of `eval/phase5.py` | Contents |
| --- | --- | --- |
| `phase5_t3.json` | `fit` | T3 logistic regression on dev_train incidents (labels; amendment 6 exception) |
| `phase5_selection.json` | `select` | T0-T3 on val_a, the choice (T2), tier rates calibrated on val_a |
| `phase5_confirm.json` | `confirm` | val_b for every candidate and the tiers |
| `phase5_response.json` | `response` | the deployed causal run: tiers, response cost per stratum, emails per day, rule detectors on new vs returning attackers |
| `phase5_store.json` | `store` | SQLite alert store insert and query cost on a 1-day replay |
| `phase5_replay_check.json` | `replay` | real agents with the new defaults vs `response` |
