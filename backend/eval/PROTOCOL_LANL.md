# LANL evaluation protocol

Second dataset: LANL "Comprehensive, Multi-Source Cyber-Security Events"
(files and hashes in eval/LANL_FILES.md). Time origin t0 = the time of the
first event in auth.txt.gz; day index = floor((time - t0) / 86400).

## Amendment LA1 (declared before any split boundary was computed)

LA1.1 Splits. Sort red-team events by time. Let q(p) be the time of the red-team event at the p-th percentile (nearest-rank). Cut points c1, c2, c3 are q(0.50), q(0.625), q(0.75), each moved forward to the next day boundary (a cut already on a boundary stays). Splits:
  dev_train = [t0, c1); val_a = [c1, c2); val_b = [c2, c3); test = [c3, end of auth data].
  The end of auth data is fixed by phase L1 (conversion); it does not change c3.

LA1.2 Adequacy. Each of val_a, val_b and test must contain >= 30 red-team events and red-team events on >= 2 distinct days. dev_train has no minimum.

LA1.3 Fallback (used at most once). If LA1.2 fails, recompute with q(0.40), q(0.55), q(0.70). If LA1.2 fails again, do not choose any split: stop and report.

LA1.4 Roles. val_a = selection; val_b = confirmation; test = scored once at the final evaluation. State is causal from t0 through every split, with no reset; test is scored with state carried over from val_b.

LA1.5 Strata (declared now, computed for dev only in this phase). For a red-team event in a period P: its user is "returning" if the same user field appears in any red-team event before P starts, otherwise "new"; its source computer and its destination computer are classified the same way, separately. Report results for all events and for each stratum.

LA1.6 Test access. The test is read through one guarded loader, only with FINAL_EVAL=1, logged to backend/results/lanl_test_access.log. In phase L1, every test-period row from auth.txt.gz will be written to separate partition files whose SHA-256 is recorded without computing any statistic on them.
