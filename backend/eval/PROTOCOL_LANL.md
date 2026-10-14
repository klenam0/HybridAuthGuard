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

## Amendment LA2 (post hoc)

LA2 (post hoc). Written after LA1 failed. Seen before writing: LA1's cut days, its per-split event and day counts, and the day-12 cluster. Not seen: the per-day layout of red-team events before the test. LA2 supersedes LA1.1 to LA1.3; LA1.4 (roles, causal state), LA1.5 (strata) and LA1.6 (test access) stay in force.

LA2.1 Test. c3 = LA1.1's c3, read from results/lanl_split.json (not retyped). Test = [c3, test end]. The test end is the last auth day found in phase L1 and is recorded there.

LA2.2 val_b. Starting from the day before c3 and moving back one whole day at a time, val_b = the shortest block of whole days [b, c3) that contains >= 30 red-team events on >= 2 distinct days.

LA2.3 val_a. The same search, moving back from b: val_a = the shortest block [a, b) with >= 30 red-team events on >= 2 distinct days.

LA2.4 dev_train. dev_train = [first day, a) and must contain at least 5 whole days. It needs no red-team events (it is state warm-up).

LA2.5 Fallback (used at most once). If val_a cannot be formed before the first day, or dev_train has fewer than 5 whole days, use a single validation split: val = [b, c3) from LA2.2, and dev_train = [first day, b), which must contain at least 5 whole days. val is used for both selection and confirmation, and the paper states that LANL had no separate confirmation half. If val_b cannot be formed, or this dev_train is still under 5 days, choose no split: stop and report.

LA2.6 Small-sample reporting. For any split or stratum with fewer than 20 distinct red-team users, report every measure as exact counts (numerator / denominator), with no bootstrap interval. With 20 or more, use a 95% bootstrap interval clustered by red-team user (1,000 resamples).

LA2.7 Counts reported for the test in L0: red-team event count, distinct red-team days and distinct red-team user count only (the last decides LA2.6). No identities, histograms or strata. The number of test days with no red-team events is computed and reported in phase L1, once the test end is known.
