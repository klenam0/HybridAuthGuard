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
