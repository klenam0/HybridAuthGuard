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

## Amendment LA3

LA3. Purpose: LANL tests the paper's central ML claim where RBA could not: RBA's label is a per-IP blocklist, under which label-free anomaly detection showed no usable detection (S1 variant (c), ROC-AUC 0.520). LANL's labels are event-level and its attack is lateral movement with valid credentials, which should be anomalous. LA3 asks: does label-free anomaly detection work under those conditions? It adds no detector to the frozen system. A runs the frozen rules unchanged; D evaluates fixed label-free scorers offline. Declared before any LANL metric; no tuning.

LA3.1 Labels. An auth row is red-team (positive) if its time, source computer and destination computer equal those of a red-team event and its source user equals the red-team user. Every auth row matching a red-team event is positive. A red-team event that matches no auth row is "unmatched": it is not a positive in any scored population, and it counts as missed in the all-red-team line (LA3.6).

LA3.2 User. "User" means the source user@domain, everywhere in LA3.

LA3.3 Event filter (D only; from field properties, no labels). Keep a row if: success/failure = "Success"; source computer != destination computer; the source user's name before "@" matches ^U[0-9]+$ (the documentation states that well-known system accounts were not de-identified; this also drops machine accounts ending in "$"). The filtered rows are D's scored population. Red-team events outside the filter count as missed in the all-red-team line.

LA3.4 A: frozen-rule transfer. The frozen v3 system (tag v3.0.0-frozen) runs unchanged on the full, unfiltered auth stream, mapped as: ip = source computer; user = source user; status = SUCCESS for "Success", FAILED for "Fail"; timestamp from time. ASN is set to one constant value for every event, so the triage tie-break is constant (dropped) with no code change. Country, region, user agent, browser, OS and RTT are set to constants. Hour of day = ((time − 1) mod 86400) // 3600; this is an offset from the start of the data, not a clock hour (the timeframe is undisclosed), and Suspicious Login Time is reported with that caveat. Incident = (source computer, day). Detector settings, triage keys, caps (step-up 200/day, queue 500/day), floor and email rules stay as frozen. State runs causally from day 0.

LA3.5 D: label-free scorers (offline; fixed; no labels used to build or fit them). Causal state from day 0 over the filtered stream.
  D1 Isolation Forest, label-free construction (as RBA S1 variant (c)): features hour_sin, hour_cos (from the LA3.4 offset hour); source-computer frequency, user frequency and destination-computer frequency (maps from all dev_train filtered rows); source computer's failure rate over the prior 30 days (computed causally on the unfiltered stream); is_new_source_computer (not seen in dev_train filtered rows). RBA features with no LANL field (country, device, is_new_country) are dropped and nothing replaces them. StandardScaler and Isolation Forest (200 trees, max_samples 100,000, max_features 1.0, seed 42) fit on all dev_train filtered rows. Score = −score_samples.
  D2 New edge: 1 if the (user, source computer, destination computer) triple has not occurred earlier in the filtered stream, else 0.
  D3 New destinations: number of distinct destination computers the user reached in the trailing 24 h that the user had never reached before that 24 h window, counted at the event (inclusive).
  Ties in any score are broken by stream order (earlier event ranks first).

LA3.6 Metrics. For each split and each D scorer, on the filtered population: ROC-AUC; PR-AUC (average precision); for daily top-k with k in {100, 1,000, 10,000} (ranked within each day): red-team events caught, red-team users caught, precision, and lift = precision / the split's filtered base rate. Plus an all-red-team line: events and users caught at each k over all red-team events in the split, counting unmatched and filter-excluded events as missed. For A, per detector and per tier: alerts, red-team events and users caught (of all red-team events in the split), precision, legitimate users challenged per day.

LA3.7 Intervals. LA2.6 applies: fewer than 20 distinct red-team users in a split or stratum: exact counts only; otherwise a 95% bootstrap over red-team users (1,000 resamples, seed 42), resampling the positive events by user and keeping the negatives fixed (the negatives outnumber the positives by several orders of magnitude). Strata: LA1.5 new vs returning users (source and destination computer strata are reported as descriptive counts only; L0 found 2 to 3 per split).

LA3.8 Verdict for D (evaluated on test only; dev is reported, not judged). A scorer "works" if, on test: ROC-AUC 95% lower bound > 0.50; at k = 1,000, lift lower bound >= 10; and at k = 1,000 it catches >= 20% of the test's red-team users. All three scorers are reported whatever the verdict; none is selected over another.

LA3.9 Test plan. The test is read once in a later phase, through load_lanl("test") with FINAL_EVAL=1, and runs exactly LA3.4 to LA3.8 with state carried from val_b. Nothing else is computed on test.
