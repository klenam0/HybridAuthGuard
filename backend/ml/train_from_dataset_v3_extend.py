# backend/ml/train_from_dataset_v3_extend.py
"""
Grid-extension addendum to Batch 2.

WHY THIS EXISTS
================
All four of Batch 2's runs (temporal x {frequency, behavioral_only} and
user_disjoint x {frequency, behavioral_only}) selected contamination=0.2 on
validation, the highest value tested. That means the true optimum might sit
above 0.2, and the specific precision/recall/F1 numbers already reported are
provisional until we know whether F1 keeps climbing, peaks nearby, or falls
back down.

This does NOT reopen the ROC-AUC finding from Batch 2. ROC-AUC was already
confirmed contamination-invariant at a fixed seed (visible directly in your
own printed tuning grid: 0.707 at every contamination value tested for
temporal_frequency). The headline result, that frequency encoding recovers
real signal under the user-disjoint split, already stands. This addendum
only settles the specific operating point for the confusion-matrix numbers.

WHAT IT DOES
=============
For each of the four (split strategy, feature variant) combinations:
  1. Reloads the existing leakage_fix_results_{strategy}_{variant}.json
     Batch 2 produced.
  2. Tests six new, higher contamination candidates (0.25 through 0.5)
     against the SAME validation set, never touching test.
  3. Merges these with the tuning results Batch 2 already found, and
     picks the true overall best by F1.
  4. If that best is still 0.2 (the old answer), nothing changes, the
     existing seed_results and summary from Batch 2 are carried forward
     unmodified, since they are already the correct final answer.
  5. If a higher contamination now wins, refits and reevaluates across
     the same 10 seeds against the untouched test set at the NEW
     contamination, exactly once, same discipline as every batch before
     this one.

It writes four NEW files (does not overwrite Batch 2's originals, so
there is a full audit trail):
    leakage_fix_results_temporal_frequency_extended.json
    leakage_fix_results_temporal_behavioral_only_extended.json
    leakage_fix_results_user_disjoint_frequency_extended.json
    leakage_fix_results_user_disjoint_behavioral_only_extended.json

HOW TO RUN
==========
Save in backend/ml/, alongside the other three scripts. From backend/:

    python ml/train_from_dataset_v3_extend.py

This is much shorter than Batch 2, at most 6 new tuning fits plus,
only if the optimum actually moved, 10 new seed fits, per combination,
24 to 64 fits total depending on how many combinations shift. Expect
10 to 25 minutes, not the 1.5 to 2 hours Batch 2 took, since streaming
and splitting are the same deterministic operations as before and
reproduce identical train/val/test sets.

Send the four output files back, along with whatever the console printed
about whether each combination's best contamination changed.
"""

import os
import sys
import json
import numpy as np
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_from_dataset_v2 import (
    stream_dataset, temporal_split, user_disjoint_split,
    RESULTS_DIR, N_SEEDS, SEED_BASE,
)
from train_from_dataset_v3 import fit_frequency_maps, fit_and_score

EXTENDED_CANDIDATES = [0.25, 0.3, 0.35, 0.4, 0.45, 0.5]


def extend_one(strategy_name, feature_variant, train_df, val_df, test_df):
    print("\n" + "=" * 60)
    print(f"  EXTENDING: {strategy_name} | {feature_variant}")
    print("=" * 60)

    prior_path = os.path.join(RESULTS_DIR,
                               f"leakage_fix_results_{strategy_name}_{feature_variant}.json")
    if not os.path.exists(prior_path):
        print(f"   Prior result file not found at {prior_path} — skipping.")
        return None

    with open(prior_path) as f:
        prior = json.load(f)

    freq_maps, known_ips_set, known_countries_set = fit_frequency_maps(train_df)

    print("   Testing higher contamination candidates on VALIDATION only:")
    new_tuning_results = []
    for c in EXTENDED_CANDIDATES:
        t0 = datetime.now()
        r = fit_and_score(train_df, val_df, freq_maps, known_ips_set, known_countries_set,
                           contamination=c, seed=SEED_BASE, feature_variant=feature_variant)
        elapsed = (datetime.now() - t0).seconds
        print(f"      contamination={c:<6} -> P={r['precision']:.3f} R={r['recall']:.3f} "
              f"F1={r['f1']:.3f} ROC-AUC={r['roc_auc']:.3f}  ({elapsed}s)")
        new_tuning_results.append(r)

    merged_tuning = prior["tuning_grid_results"] + new_tuning_results
    overall_best = max(merged_tuning, key=lambda r: r["f1"])
    old_best_contamination = prior["best_contamination"]
    new_best_contamination = overall_best["contamination"]

    result = dict(prior)
    result["tuning_grid_results"] = merged_tuning
    result["best_contamination"] = new_best_contamination
    result["grid_extension_candidates_tested"] = EXTENDED_CANDIDATES

    if new_best_contamination == old_best_contamination:
        print(f"\n   Still best at contamination={old_best_contamination} "
              f"(F1={overall_best['f1']:.3f}) — no candidate above 0.2 won. "
              f"Keeping Batch 2's seed_results and summary unchanged.")
        result["grid_extension_changed_optimum"] = False
    else:
        print(f"\n   NEW optimum found: contamination={new_best_contamination} "
              f"(F1={overall_best['f1']:.3f}), previously {old_best_contamination}. "
              f"Refitting across {N_SEEDS} seeds, evaluated ONCE on the untouched TEST set.")
        seed_results = []
        for i in range(N_SEEDS):
            seed = SEED_BASE + i
            t0 = datetime.now()
            r = fit_and_score(train_df, test_df, freq_maps, known_ips_set, known_countries_set,
                               contamination=new_best_contamination, seed=seed,
                               feature_variant=feature_variant)
            elapsed = (datetime.now() - t0).seconds
            print(f"      seed={seed} -> P={r['precision']:.3f} R={r['recall']:.3f} "
                  f"F1={r['f1']:.3f} ROC-AUC={r['roc_auc']:.3f}  ({elapsed}s)")
            seed_results.append(r)

        metrics_arr = {k: np.array([r[k] for r in seed_results])
                       for k in ["precision", "recall", "f1", "accuracy", "roc_auc", "pr_auc"]}
        summary = {
            k: {"mean": round(float(v.mean()), 4), "std": round(float(v.std()), 4),
                "min": round(float(v.min()), 4), "max": round(float(v.max()), 4)}
            for k, v in metrics_arr.items()
        }
        print(f"\n   UPDATED FINAL TEST-SET RESULT ({N_SEEDS} seeds, contamination={new_best_contamination}):")
        for k, s in summary.items():
            print(f"      {k:10s}: mean={s['mean']:.4f}  std={s['std']:.4f}  "
                  f"min={s['min']:.4f}  max={s['max']:.4f}")

        result["seed_results"] = seed_results
        result["summary"] = summary
        result["grid_extension_changed_optimum"] = True

    return result


if __name__ == "__main__":
    print("\nStarting grid-extension addendum...\n")
    overall_start = datetime.now()

    normal_df, attack_df = stream_dataset()
    os.makedirs(RESULTS_DIR, exist_ok=True)

    for strategy_name, split_fn in [
        ("temporal", temporal_split),
        ("user_disjoint", user_disjoint_split),
    ]:
        train_df, val_df, test_df = split_fn(normal_df, attack_df)

        for feature_variant in ["frequency", "behavioral_only"]:
            result = extend_one(strategy_name, feature_variant, train_df, val_df, test_df)
            if result is None:
                continue
            out_path = os.path.join(
                RESULTS_DIR, f"leakage_fix_results_{strategy_name}_{feature_variant}_extended.json"
            )
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)
            print(f"\nSaved -> {out_path}")

    elapsed = (datetime.now() - overall_start).seconds
    print(f"\nAll done in {elapsed // 60}m {elapsed % 60}s.")
    print("Send all four *_extended.json files back, plus whichever combinations")
    print("reported a changed optimum, for the paper rewrite.")
