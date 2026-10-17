# LANL phase L2 report

**Outcome.** Amendment LA3 was committed on its own (e219327) before any LANL
feature, score or metric code existed. Both parts ran on dev only; the test
was not read.

**A (the frozen v3 rules):** the frozen system ran unchanged on all 239,471,628
dev events. The real agents reproduce the offline twin with 0 mismatches. A
catches some red-team events, but only through Success After Failures and
Multiple IP Login, always at log tier, and at precision near 1e-5. The step-up
tier caught no red-team event and challenged 11,901 to 21,784 legitimate users
per day.

**D (label-free scorers):** D1 (Isolation Forest) has dev ROC-AUC 0.980 on
val_a and 0.981 on val_b, against 0.520 on RBA. Daily top-1,000 recall is very
low (D1 reaches 1 of 45 val_a users), so a good ROC-AUC does not mean the top
of each day's list is useful. LA3.8 judges only the test, so no verdict is
given here.

Every number below comes from a file in `backend/results/` named next to it.
The gates all print MATCHES.

Branch `lanl-l2` from `lanl-l1`. Not pushed or merged.

| commit | group |
|---|---|
| e219327 | LA3 (`eval/PROTOCOL_LANL.md`, that file alone) |
| 8065683 | Step 2 checks: `eval/lanl_la3.py`, `eval/lanl_l2_checks.py`, `lanl_l2_checks*.json` |
| d3ff215 | D: `eval/lanl_d.py`, `eval/lanl_d_metrics.py`, `lanl_d_*.json` |
| c708d53 | A: `eval/lanl_a.py`, `eval/lanl_a_metrics.py`, `lanl_a_*.json` |
| (this commit) | this report |

D was committed before A because it finished first. Both were committed after
LA3. No file in LA3 changed after any dev result was seen. The first LANL
metric code, `eval/lanl_la3.py`, is in 8065683, which comes after e219327.

## 1. Step 2: checks of LA3's inputs (lanl_l2_checks.json; dev only)

| split | filtered rows / day (min, mean, max) | filtered share | red-team events | matched | unmatched | positive rows | events / users passing LA3.3 |
|---|---|---|---|---|---|---|---|
| dev_train | 1452770, 2328251.25, 3091343 | 0.1399 | 50 | 50 | 0 | 50 | 50 / 7 |
| val_a | 1565075, 2142268.0, 3066800 | 0.1304 | 288 | 276 | 12 | 266 | 276 / 45 |
| val_b | 3089692, 3191717.0, 3293742 | 0.1569 | 290 | 288 | 2 | 282 | 288 / 50 |

- **LA3.1 rows per matched event.** Every matched red-team event matches
  exactly 1 auth row (min 1, max 1). Over dev, 614 of 628 events are matched
  and 14 are unmatched.
- **All positives pass LA3.3.** All 614 matched events (86 users) pass.
- **Several events can share one auth row.** val_a has 276 matched events but
  266 positive rows; val_b has 288 and 282. Some red-team lines repeat the
  same time, user, source and destination, so two events land on one auth row.
- **Placeholder accounts.** No row's normalised account is in
  `config.UNKNOWN_ACCOUNT_IDS` (0 on every dev day).
- **Duplicate check without event IDs.** If events carried no `event_id`, the
  frozen duplicate check (`rules_v3._is_duplicate`: same second, ip, account,
  status and constant fields) would drop 22,241,494 dev_train rows,
  10,687,968 val_a rows and 6,589,392 val_b rows. A therefore gives every event
  `event_id` = its global stream position, as the RBA replay did with its row
  index. LA3.4 does not mention event IDs; without them the "full, unfiltered
  stream" would not reach the detectors.
- **Casefolding.** It merges no accounts: day 08 has 32,251 src_user strings
  and 32,251 accounts after casefolding, and the twin's account total (62,681)
  equals L1's distinct src_user.

### Frozen-system field handling (code inspection plus the day 7-8 run)

- **ip = source computer.**
  - `rules_v3.ip_prefix("C17693")` returns None, so the `same_prefix`
    exemption never applies. It is not configured anyway: `V3_MULTI_IP_EXEMPT`
    is `("known_ip",)`.
  - `is_internal_ip` is only used for ML, and ML is retired.
  - The ingest validator `utils/event_schema.normalize_event` rejects a
    non-IP `ip`. It is called only in live mode
    (`MonitoringAgent.stream_live`). The replay entry point the RBA evaluation
    used (`MonitoringAgent._process_event`) does not call it.
  - So A runs with no code change, but a live LANL feed would be rejected at
    ingest.
- **Constant ASN.** LA3.4 says the triage tie-break becomes constant. In the
  frozen code it does not. `triage.AsnReputation` keeps one record per ASN
  value, so with one constant ASN it returns the share of failures among
  *all* earlier events. T2 then uses the running daily maximum of that value
  per IP. The second score component is therefore a slowly varying global
  failure share, not a constant. The twin reproduces this exactly. The code
  was not changed, and LA3 was not changed.
- **Constants.** country, region, user agent, browser, OS and device type are
  all "LANL", RTT is 0.0 and ASN is 0. Only `device_type` and `country` are
  read by the v3 rules, and only inside the duplicate key, where event IDs
  make them irrelevant.
- **"?" values.** "?" occurs only in auth_type and logon_type (L1), which the
  frozen system never reads.
- **Event time.** T = 2000-01-01 00:00:00 + (time − 1) s. The frozen day
  (T // 86400) is then the LANL day + 10957, and the clock hour read from the
  timestamp string is the LA3.4 offset hour.
- **Missing fields.** None the frozen v3 path requires. The run raised no
  exception, made no ML alert and dropped no duplicate events
  (lanl_a_replay_fresh7_8.json).

## 2. A: frozen-rule transfer (LA3.4)

### Twin-agent equivalence (lanl_a_replay_fresh7_8.json)

The twin carries state from day 0, and the real agents cannot be started in
that state without replaying days 0-7 (133,093,773 events at the measured 58.4 µs/event, about 2.2 h). So
both the real agents (frozen defaults) and the twin were started from empty
state on day 7 and run through day 8. Day 7 closes with incidents, which sets
the tier cutoffs. Day 8, the required day, then exercises tiers, challenges
and email.

A fresh single-day check was also run on the first 300,000 events of day 8
(lanl_a_replay_fresh8_smoke.json: equivalent). With no earlier day it cannot
reach any tier, which is why the two-day run was needed.

| day | events | alerted events | by tier (agents) | challenged events | emails (agents) | mismatches |
|---|---|---|---|---|---|---|
| 07 | 19394277 | 1431318 | log 1431318 | 0 | none | 0 everywhere |
| 08 | 19374681 | 1553569 | log 771687, queue 84613, step_up 697269 | 4675733 | sent 100, digest 100 | 0 everywhere |

"0 everywhere" covers:
- per-detector rule alerts for all 8 detectors
- tiers, T2 scores and alerted events missing
- challenge state before every event, and blocked events (0)
- email outcomes, and the email log (104 entries, 0 mismatches)

`"equivalent": true`.

A bug was found and fixed during this check, before any A metric was
computed. The twin's Multiple IP Login lookup used the wrong permutation, and
on the first 300,000 day-8 events it gave 2,573 alerts against the agents'
31,514. The 300k smoke above was rerun after the fix and then matched; the
earlier, wrong twin outputs were regenerated. Only the twin code changed; the
frozen code did not.

### A metrics (lanl_a_dev.json; causal run from day 0, lanl_a_twin_causal.json)

The operational definitions are in the file's `definitions` field. In short:
- An event is caught by a detector or tier if its matched row raised that
  detector's alert, or was an alerted event at that tier.
- Precision is computed over alerted rows.
- Legitimate users per day counts distinct source accounts with a non-positive
  event from a challenged IP.

Intervals use a 95% user-cluster bootstrap where there are at least 20 users.

| split | detector | alerts | positive alerts | precision | events caught | users caught |
|---|---|---|---|---|---|---|
| dev_train (warm-up) | Success After Failures | 9084467 | 14 | 1.5e-06 | 14 / 50 | 5 / 7 |
| dev_train | Multiple IP Login | 252094 | 2 | 7.9e-06 | 2 / 50 | 1 / 7 |
| val_a | Success After Failures | 4795512 | 60 | 1.25e-05 [1.08e-05, 1.42e-05] | 60 / 288 [0.163, 0.280] | 43 / 45 [0.889, 1.0] |
| val_a | Multiple IP Login | 33305 | 12 | 3.6e-04 [2.1e-04, 5.4e-04] | 12 / 288 [0.023, 0.070] | 12 / 45 [0.156, 0.400] |
| val_b | Success After Failures | 2842386 | 80 | 2.8e-05 [2.25e-05, 3.48e-05] | 82 / 290 [0.187, 0.434] | 48 / 50 [0.90, 1.0] |
| val_b | Multiple IP Login | 15748 | 12 | 7.6e-04 [3.8e-04, 1.14e-03] | 12 / 290 [0.018, 0.083] | 12 / 50 [0.12, 0.36] |

Brute Force, Slow Brute Force, Credential Stuffing, Distributed Brute Force
and Suspicious Login Time raised alerts (for example in val_a: 3220, 20692,
12644, 19911 and 844480) but caught 0 red-team events in every split.
Invalid Account Spraying raised none. Any rule alert caught 60/288 events
(43/45 users) in val_a and 82/290 (48/50) in val_b.

Tiers (block is off, rate 0):

| split | tier | alerted events at tier | red-team events caught | incidents (final tier) | incidents with a positive |
|---|---|---|---|---|---|
| val_a | step_up | 1219996 | 0 | 277 | 0 |
| val_a | queue | 1454720 | 0 | 1059 | 0 |
| val_a | log | 2954558 | 60 | 35314 | 1 |
| val_b | step_up | 1202725 | 0 | 400 | 0 |
| val_b | queue | 868969 | 0 | 766 | 0 |
| val_b | log | 1195729 | 82 | 19647 | 3 |

| | dev_train | val_a | val_b |
|---|---|---|---|
| red-team events from a challenged source | 0 | 0 | 0 |
| legitimate users challenged per day (mean) | 8096.25 | 11900.75 | 21783.5 |
| daily | 0, 0, 0, 0, 11958, 21850, 12654, 18308 | 22481, 12287, 0, 12835 | 22848, 20719 |

LA1.5 user strata (events / users caught by any rule alert):

| split | new users | returning users |
|---|---|---|
| val_a | 57 / 42 (44 users, 278 events; bootstrap) | 3 / 1 (1 user, 10 events; exact) |
| val_b | 50 / 34 (35 users, 145 events; bootstrap) | 32 / 14 (15 users, 145 events; exact) |

Step-up and challenged-source catches are 0 in every stratum. Source and
destination computer strata are given only as descriptive counts, in L0
(`results/lanl_split_la2.json`).

Suspicious Login Time is based on an offset hour (LA3.4), not a clock hour,
so its 0 catches say nothing about real off-hours activity.

## 3. D: label-free scorers (LA3.5)

### Build

- **Frequency maps** (lanl_d_maps.json): built from 18,626,010 dev_train
  filtered rows, covering 11,492 source computers, 12,070 users and 2,724
  destination computers.
- **Fit** (lanl_d_fit.json): the scaler and forest were fit on those
  18,626,010 rows. The model is at `<work>/d/d1_model.pkl` with SHA-256
  `48bf2436ff8a4403eb140cfe1ce1d55a8118893c356d385aa91bd6a5edaccfb3`.
- **Scored rows** (lanl_d_score.json): 8,569,072 in val_a and 6,383,434 in
  val_b. Score arrays are under `<work>/d/`, outside the repo.

Feature definitions are in the `lanl_d.py` docstring. The frequency maps and
the 30-day failure rate follow the RBA code (`fit_frequency_maps`,
`windowed_failed_rate`). The failure rate covers the 30 calendar days up to and
including the event, on the unfiltered stream.

**Ties.** LA3.5 breaks ties by stream order, so every ranking is strict. ROC-AUC
and PR-AUC are computed on that strict ranking and match sklearn applied to
it (`check_strict_ranking_vs_sklearn`). Because D2 is binary and D3 a small
integer, a day's top-k for them is the earliest of the highest-scoring events.

### Results, all users (lanl_d_dev.json)

95% user-cluster bootstrap; val_a has 45 users and val_b 50, so both use
bootstrap mode.

| split | scorer | ROC-AUC | PR-AUC | k=100 events / users caught | k=1,000 events / users, precision, lift | k=10,000 events / users, precision, lift |
|---|---|---|---|---|---|---|
| val_a | D1 | 0.9797 [0.9702, 0.9880] | 0.00223 [0.0009, 0.00624] | 0 / 0 | 27/288, 1/45, 0.00675, 217.4 [0.0, 657.4] | 141/288, 23/45, 0.00353, 113.6 [75.8, 145.0] |
| val_a | D2 | 0.9299 [0.9090, 0.9517] | 0.00473 [0.00343, 0.00648] | 0 / 0 | 0, 0, 0.0, 0.0 | 22/288, 10/45, 0.00045, 14.5 [5.4, 26.9] |
| val_a | D3 | 0.9398 [0.9063, 0.9640] | 0.00080 [0.00038, 0.00136] | 0 / 0 | 0, 0, 0.0, 0.0 | 17/288, 5/45, 0.00043, 13.7 [4.3, 23.1] |
| val_b | D1 | 0.9808 [0.9593, 0.9917] | 0.00491 [0.00079, 0.02236] | 0 / 0 | 0, 0, 0.0, 0.0 | 89/290, 3/50, 0.00445, 100.7 [0.0, 201.0] |
| val_b | D2 | 0.8409 [0.7929, 0.8743] | 0.00376 [0.00166, 0.00726] | 0 / 0 | 0, 0, 0.0, 0.0 | 108/290, 35/50, 0.0054, 122.2 [77.1, 154.8] |
| val_b | D3 | 0.9105 [0.8177, 0.9575] | 0.00126 [0.00023, 0.00413] | 1/290, 1/50 | 2/290, 2/50, 0.001, 22.6 [0.0, 56.3] | 52/290, 3/50, 0.0026, 58.9 [0.0, 97.7] |

The events and users columns are the all-red-team line. They count every
red-team event of the split, so unmatched events count as missed: 12 in val_a
and 2 in val_b. No event was excluded by the filter. Further intervals (users
caught share, precision, events caught share) are in lanl_d_dev.json.

### LA1.5 user strata

| split | stratum | users / events | D1 ROC-AUC | D2 ROC-AUC | D3 ROC-AUC | mode |
|---|---|---|---|---|---|---|
| val_a | new | 44 / 278 | 0.9794 [0.9687, 0.9876] | 0.9291 [0.9049, 0.9510] | 0.9384 [0.9036, 0.9631] | bootstrap |
| val_a | returning | 1 / 10 | 0.9894 | 0.9554 | 0.9861 | exact counts |
| val_b | new | 35 / 145 | 0.9804 [0.9613, 0.9883] | 0.8462 [0.7696, 0.9042] | 0.8882 [0.7693, 0.9464] | bootstrap |
| val_b | returning | 15 / 145 | 0.9812 | 0.8355 | 0.9334 | exact counts |

Strata with fewer than 20 users get point values without intervals. Their
top-k counts are in lanl_d_dev.json; for example, val_b returning users at
k = 10,000 under D1 has 83 / 145 events and 1 / 15 users.

No verdict is given: LA3.8 is evaluated on the test only.

## 4. Runtimes and peak memory

Each runtime estimate came from a one-day smoke before the full run.

| pass | estimate (smoke) | actual | peak working set |
|---|---|---|---|
| Step 2 checks | 193 s (lanl_l2_checks_smoke.json) | 170.5 s | 4233113600 B |
| A twin, days 0-13 | day 0: 32.1 s for 15740952 events (lanl_a_twin_smoke0.json) | 709.4 s | 7717265408 B |
| real agents, fresh, days 7-8 | 920 s per day (lanl_a_replay_fresh8_smoke.json); over 10 minutes, stated before the run | 2265.5 s (58.4 µs/event) | 6187544576 B |
| A metrics | not estimated (reads saved arrays plus dev labels) | 30.6 s | 3108507648 B |
| D maps | 18 s (lanl_d_maps_smoke.json) | 19.5 s | 2794921984 B |
| D features | day 0: 8.0 s (lanl_d_features_smoke_day0.json) | 135.3 s | 5156429824 B |
| D1 fit | not estimated (see section 5) | 398.9 s | 6695219200 B |
| D1 scoring | 37 s val_a, 28 s val_b (lanl_d_score_smoke.json); far under the 3-hour stop | 29.9 s, 20.3 s | 1145958400 B |
| D metrics | not estimated (saved arrays) | 76.9 s | 1630896128 B |

Some passes overlapped. The real-agent replay ran while the D passes and the
causal twin ran, so its µs/event, and the twin's 709.4 s (against roughly
490 s scaled from the smoke), are inflated by contention. The A twin smoke
JSON was re-saved after the Multiple IP Login fix; the printed estimate before
the full run (32.3 s for day 0) came from the run before the fix.

## 5. Gates

| check | before | after |
|---|---|---|
| `python -m eval.freeze --verify` | freeze MATCHES | freeze MATCHES |
| `python -m eval.lock_test --verify` | test lock MATCHES | test lock MATCHES |
| `python -m eval.lanl_lock --verify` | LANL test lock MATCHES | LANL test lock MATCHES |
| RBA `results/test_access.log` | 1 line | 1 line |
| `results/lanl_test_access.log` | the one CONVERT line | the one CONVERT line |

`git diff phase6-final` over the frozen files listed in FREEZE.json is empty.
No test partition or test red-team row was read; `lanl_la3.day_table` refuses
days >= 14.

## 6. Unexpected findings and departures to note

- **ASN tie-break is not constant** (section 1). LA3.4's description of the
  constant-ASN effect is inaccurate for the frozen code. The run follows the
  frozen code, and LA3 is unchanged.
- **Event IDs are required** (section 1). Without them the frozen duplicate
  check would silently drop about 39.5M dev rows. The run supplies one per
  event; this is a mapping choice LA3.4 does not state.
- **The equivalence check started fresh on day 7** rather than on day 8 alone,
  so that tiers, challenges and email were exercised (section 2).
- **D1's `is_new_src` is constant (0) in all fit rows**: the scaler mean is
  0.0 and its scale is set to 1.0. Every dev_train filtered row's source
  computer is in the map by construction, so the forest never sees the feature
  vary and cannot use it. On val rows it is 1 for unseen computers, but no tree
  splits on it. D1 is effectively a 6-feature model. This follows from LA3.5
  as written (the map and the fit use the same rows) and was not changed.
- **High ROC-AUC with weak daily top-k.** D1 ranks positives above 98% of
  negatives overall. But each day has 1.5 to 3.3 million filtered rows, so
  98% still leaves tens of thousands of rows ahead of a typical positive, and
  top-1,000 catches at most 1 user. This matters for LA3.8: the k = 1,000
  criteria are far harder than the ROC-AUC criterion.
- **The step-up tier catches no red-team event in any split.** Its admissions
  come from the floor detectors, and on LANL those (Slow Brute Force,
  Credential Stuffing, Distributed Brute Force, Success After Failures) fire
  overwhelmingly on benign traffic. It challenged about 12,000 to 22,000
  legitimate users per day.
- **No exact-count measure for A's precision or D's AUC.** LA2.6 asks for
  "exact counts" in small strata. For AUC there is no count to give, so those
  strata report point AUC without an interval.
- **D1 fit took 398.9 s and was not estimated beforehand.** I read constraint
  4 as covering passes over auth data, and the fit reads saved features. A
  smoke would have been more cautious. It stayed under 10 minutes.
- **Duplicate red-team lines** make positive rows fewer than matched events
  (266 vs 276 in val_a, 282 vs 288 in val_b).

Phase L2 stops here. The test has not been read, and no verdict is given.
