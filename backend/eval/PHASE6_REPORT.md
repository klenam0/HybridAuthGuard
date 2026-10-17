# Phase 6 report: final evaluation on the locked May 2020 test month

Branch `phase6-final`, created from tag `v3.0.0-frozen` (bb40c16). The working tree was clean. Not pushed and not merged.

Before anything else, `eval.freeze --verify` printed `freeze MATCHES` and `eval.lock_test --verify` printed `test lock MATCHES`. Both still pass after scoring. Nothing in the frozen system changed.

## Commits and the amendment

| Commit | Step |
|---|---|
| d0fd715 | 6.1: **amendment 9**, the test plan, committed on its own before the test was read |
| eb1aa5e | Evaluation code (`eval/phase6.py`, `phase6_primary.py`, `phase6_secondary.py`), checked on dev data only before the test was read (section 7) |
| 08b77fd | Test read once into a cache; offline twin over dev + May; P1–P4 and S4 |
| 11c9929 | Real-agent replay over dev + May (equivalent), S5 |
| 55e08db | S6 functional test; S1 dev check scored in chunks (bug-policy entry 1) |
| 42d732f | S1 |
| b872c59 | S2 |
| 617abb3 | S3 |
| 0fb3567 | Post-scoring gates and the test access log |

**Amendment 9** (`eval/PROTOCOL.md`) declares every number computed here, before any May row was decoded.
- **Stream.** One causal stream: dev, then May. All state (rule windows, de-duplication, triage counters, ASN ratios, cutoffs, email cooldowns) runs through dev without a reset. The 1 May cutoff comes from 30 April.
- **Bars.** 2 × May's base rate, and val_a's 0.2149.
- **May strata:**
  - all events;
  - excluding the placeholder;
  - cold users (no event before 1 May);
  - new attackers (IP with no attack-labelled event before 1 May);
  - returning attackers.

  The val_a and val_b columns keep their earlier, dev_train-based definitions.
- **Results declared:** primary P1–P4; secondary S1–S6.
- **Gates:** agents vs twin with 0 mismatches over dev and May; freeze before and after; legacy gate byte-identical.

Nothing below is post hoc unless it is labelled so.

## Test access log

`backend/results/test_access.log` (committed), complete:

```
2026-10-14T09:11:49	ALLOWED	pid=57564	argv=C:\Users\Dell\HybridAuthGuard\backend\eval\phase6.py cache
```

**Exactly one access, ALLOWED.** `FINAL_EVAL=1` was set only for `python -m eval.phase6 cache`, which wrote all 2,158,083 rows (2020-05-01 to 2020-05-31) to `results/phase6_cache/test_2020-05.parquet` (gitignored). Every later stage, including the reruns of S1–S3, read that cache. `load("test")` was never called again.

## Data at a glance

| | val_a | val_b (seen) | **May** |
|---|---|---|---|
| Days | 16 | 16 | **31** |
| Events (per day) | 1,183,517 (74.0k) | 1,153,710 (72.1k) | **2,158,083 (69.6k)** |
| Base rate | 0.1074 | 0.0957 | **0.0926** |
| 2 × base | 0.2149 | 0.1915 | **0.1852** |
| Attacking IPs | 9,423 | 9,477 | **13,988** |
| Attacking IPs with no rule alert | 5,904 (63%) | 5,952 (63%) | **9,208 (66%)** |

## P1: rule detectors (alert precision, 95% IP-clustered interval)

All events. May is judged against 0.1852 (2 × base) and 0.2149. A setting meets a bar if it has at least 30 alerts and its lower bound is at or above the bar.

| Detector | val_a | val_b (seen) | **May**: alerts, precision [CI] | Attacking / benign IPs (May) | Meets 2 × base / 0.2149 (May) |
|---|---|---|---|---|---|
| Brute Force | 0.297 [0.244, 0.358] | 0.213 [0.160, 0.268] | 110, **0.136 [0.076, 0.206]** | 15 / 87 | no / no |
| Slow Brute Force | 0.263 [0.248, 0.278] | 0.253 [0.238, 0.267] | 108,139, **0.245 [0.231, 0.259]** | 1,494 / 14,157 | **yes / yes** |
| Credential Stuffing | 0.273 [0.259, 0.289] | 0.261 [0.247, 0.276] | 108,450, **0.253 [0.238, 0.268]** | 1,740 / 13,650 | **yes / yes** |
| Invalid Account Spraying | 0.231 [0.219, 0.244] | 0.220 [0.208, 0.233] | 246,350, **0.219 [0.207, 0.231]** | 3,628 / 42,290 | yes / no |
| Distributed Brute Force | 0.252 [0.229, 0.274] | 0.231 [0.201, 0.262] | 3,706, **0.210 [0.1846, 0.238]** | 486 / 2,269 | **no** (by 0.0006) / no |
| Success After Failures | 0.246 [0.229, 0.261] | 0.229 [0.213, 0.246] | 131,442, **0.224 [0.207, 0.239]** | 1,382 / 13,150 | yes / no |
| Multiple IP Login | 0.146 [0.123, 0.167] | 0.124 [0.105, 0.145] | 1,959, **0.137 [0.121, 0.152]** | 250 / 1,628 | no / no |
| Suspicious Login Time | 0.131 [0.124, 0.138] | 0.113 [0.107, 0.120] | 68,637, **0.114 [0.108, 0.120]** | 2,386 / 39,121 | no / no |

**May strata** (precision; `phase6_primary.json` also has the intervals and IP counts):

| Detector | Excl. placeholder | Cold users | New attackers | Returning |
|---|---|---|---|---|
| Brute Force | 0.136 | 0.141 | 0.000 (95 alerts) | 1.000 (15) |
| Slow Brute Force | 0.245 | 0.261 | **0.001** | 1.000 |
| Credential Stuffing | 0.253 | 0.265 | **0.001** | 1.000 |
| Invalid Account Spraying | – (placeholder only) | – | **0.008** | 1.000 |
| Distributed Brute Force | 0.210 | 0.236 | **0.008** | 1.000 |
| Success After Failures | 0.224 | 0.253 | **0.001** | 1.000 |
| Multiple IP Login | 0.137 | 0.153 | 0.008 | 1.000 |
| Suspicious Login Time | 0.114 | 0.167 | 0.006 | 1.000 |

Returning attackers are 1.000 by construction: the label is per IP, and these IPs carry an attack label before May.

## P2: triage at fixed daily budgets (T2 deployed, T0 baseline)

Mean daily incident precision [day-clustered 95% CI] / mean daily attacking IPs caught / attacking IPs caught over the half.

| Budget | Score | val_a | val_b (seen) | **May** |
|---|---|---|---|---|
| B = 100 | T2 | 0.464 [0.422, 0.509] / 46.4 / 473 | 0.389 [0.362, 0.413] / 38.9 / 397 | **0.550 [0.534, 0.569] / 55.0 / 634** |
| | T0 | 0.289 / 28.9 / 354 | 0.246 / 24.6 / 309 | 0.253 [0.243, 0.263] / 25.3 / 523 |
| B = 500 | T2 | 0.351 [0.339, 0.364] / 175.8 / 1,310 | 0.338 [0.328, 0.347] / 168.9 / 1,234 | **0.343 [0.332, 0.354] / 171.4 / 1,506** |
| | T0 | 0.282 / 140.9 / 798 | 0.265 / 132.4 / 770 | 0.270 [0.264, 0.277] / 134.9 / 873 |
| B = 2,000 | T2 | 0.312 [0.309, 0.315] / 624.2 / 1,439 | 0.305 / 610.1 / 1,390 | **0.291 [0.286, 0.296] / 582.4 / 1,685** |
| | T0 | 0.291 / 581.8 / 1,195 | 0.283 / 565.4 / 1,193 | 0.274 [0.270, 0.277] / 547.5 / 1,406 |

**Amendment 6's test holds on May**: T2's lower bound at B = 500 is 0.332, against T0's point value of 0.270.

May strata at B = 500, T2:

| Stratum | Precision | Attacking IPs caught (share) |
|---|---|---|
| Excl. placeholder | 0.343 | 1,504 (0.178) |
| Cold users | 0.334 | 1,409 (0.246) |
| **New attackers** | **0.001** [0.001, 0.002] | 13 (0.002) |
| Returning attackers | 1.000 | 1,517 (0.197) |

## P3: response tiers as deployed

| Tier | val_a | val_b (seen) | **May**: incidents (per day), precision [CI], attacking IPs | Meets 2 × base / 0.2149 |
|---|---|---|---|---|
| block | 0 | 0 | **0** | – |
| step-up | 3,142 (196.4), 0.456 [0.429, 0.484], 753 | 2,885 (180.3), 0.388 [0.362, 0.415], 679 | **5,611 (181.0), 0.336 [0.316, 0.357], 1,062** | **yes / yes** |
| queue | 7,935 (495.9), 0.284, 770 | 6,940 (433.8), 0.275, 770 | **9,718 (313.5), 0.292 [0.274, 0.311], 913** | yes / yes |
| log | 103,867 (6,491.7), 0.160, 3,441 | 106,485 (6,655.3), 0.151, 3,471 | **204,428 (6,594.5), 0.153 [0.147, 0.160], 4,737** | – |

Step-up by May stratum:

| Stratum | Incidents | Precision | Attacking IPs |
|---|---|---|---|
| Cold users | 5,062 | 0.332 | 973 |
| **New attackers** | 3,732 | **0.0019** | **6** |
| Returning attackers | 1,879 | 1.000 | 1,056 |

### Step-up cost

| | val_a | val_b (seen) | **May** |
|---|---|---|---|
| Legitimate users challenged: total (per day; max day) | 1,092 (69.4; 189) | 1,433 (90.3; 210) | **3,250 (105.8; 200)** |
| Benign IPs challenged (per day) | 1,294 | 1,377 | **2,273 (120.2)** |
| Attacking IPs challenged (per day) | 753 | 679 | **1,062 (60.8)** |
| Benign events / successes challenged | 3,734 / – | 4,326 / – | **8,890 / 3,204** |
| Attack events challenged | 2,741 | 2,592 | **4,299** |

May response cost per stratum:

| Stratum | Legitimate users | Benign / attacking IPs |
|---|---|---|
| Cold users | 2,569 (83.5/day) | 2,232 / 1,055 |
| New attackers | 3,250 | 2,273 / **6** |
| Returning attackers | 0 | 0 / 1,056 |

### Other P3 figures

| | val_a | val_b (seen) | **May** |
|---|---|---|---|
| Log tier's share of attacking IPs with an attack incident | 0.613 (2,157 / 3,519) | 0.656 (2,313 / 3,525) | **0.722 (3,452 / 4,780)** |
| Blocks placed | 0 | 0 | **0** |
| Emails + digests per day: mean (max) | 169.4 (197) | 132.5 (199) | **90.8 (166; minimum 46)** |
| Maximum admissions per day: step-up / queue | 200 / 499 | 200 / 498 | **200 / 500** |
| Floor binding: kept out of step-up (attack); days | 8 (0); 5 | 9 (1); 6 | **4 (0); 2** |

May email outcomes: 2,775 sent, 2,664 in digests, 172 cooldown. Step-up challenges were placed on 19,299 alerted events.

## P4: rule incidents

| Stratum | val_a: incidents/day, precision [CI] | val_b (seen) | **May** | May rule alerts/day |
|---|---|---|---|---|
| All | 7,184.0, 0.176 [0.169, 0.184] | 7,269.4, 0.164 [0.157, 0.171] | **7,088.9, 0.164 [0.157, 0.171]** | 21,574 |
| Excl. placeholder | 4,989.6, 0.185 | 5,116.8, 0.170 | **4,867.1, 0.169** | 13,627 |
| Cold users | 3,677.0, 0.229 | 3,831.9, 0.209 | **3,253.2, 0.219** | 9,156 |
| New attackers | 5,964.9, 0.008 | 6,140.9, 0.010 | **5,971.5, 0.008** | 16,926 |
| Returning attackers | 1,219.1, 1.000 | 1,128.5, 1.000 | **1,117.4, 1.000** | 4,648 |

## S1: leakage replication (Phase 2 forest variants)

ROC-AUC, mean (min–max) over seeds 42, 43 and 44. All variants are fitted on dev_train rows only.

| Variant | val_a (seed 42) | val_b (seed 42, seen) | **May, all events** | **May, new attackers** |
|---|---|---|---|---|
| (a) original: maps and fit on non-attack rows | 0.763 | 0.750 | **0.746** (0.742–0.749) | 0.572 (0.570–0.575) |
| (b) maps from all rows, fit on non-attack rows | 0.553 | 0.555 | **0.572** (0.569–0.576) | 0.573 (0.569–0.579) |
| (c) label-free | 0.504 | 0.506 | **0.520** (0.518–0.521) | 0.580 (0.579–0.581) |

**Other S1 figures:**
- **PR-AUC on May (all events):** (a) 0.161, (b) 0.102, (c) 0.091, against a base rate of 0.093.
- **TPR at 1% FPR:** at most 0.004 for every variant.
- **New attackers:** PR-AUC 0.009 for every variant, against a base rate of 0.0081.
- **(a) at seed 42 on May** reproduces the stopped run's figures exactly (ROC-AUC 0.7487, PR-AUC 0.1633, TPR 0.0030).
- **The (a)/42 refit** reproduces the cached Phase 3 decisions on all 6,392,584 dev events **bit for bit** (max |diff| 0).

**The leakage finding replicates on May.** Almost all of the original forest's ROC-AUC comes from frequency maps and known-IP sets built from label-filtered rows. Fully label-free, the design is close to chance (0.52).

## S2: supervised reference (the eight cached Phase 4 HGB fits, not refitted)

The Phase 4 features were recomputed in one causal pass over dev + May. They equal the Phase 4 cache on all 6,392,584 dev rows.

ROC-AUC / PR-AUC / TPR at 1% FPR:

| Fit | val_a, all | val_b (seen), all | **May, all** | val_a / val_b, new attackers | **May, new attackers** |
|---|---|---|---|---|---|
| **A-E reference** (lr 0.1, 15 leaves) | 0.854 / 0.359 / 0.107 | 0.826 / 0.319 / 0.119 | **0.802 / 0.262 / 0.081** | 0.649 / 0.716 (PR 0.011 / 0.016) | **0.747 / 0.056 / 0.082** |
| **-D reference** (lr 0.05, 63 leaves) | 0.808 / 0.281 / 0.043 | 0.812 / 0.273 / 0.049 | **0.813 / 0.270 / 0.052** | 0.538 / 0.577 (PR 0.010) | **0.555 / 0.008 / 0.010** |
| A-E, other three settings | 0.811–0.849 | 0.732–0.810 | 0.732–0.804 | 0.656–0.693 / 0.719–0.751 | 0.753–0.773 (PR 0.032–0.062) |
| -D, other three settings | 0.807 | 0.811–0.812 | 0.811–0.813 | 0.537–0.538 / 0.573–0.577 | 0.554–0.558 (PR 0.008–0.009) |

## S3: the legacy system on May

Settings:
- `RULES_MODE` and `ML_MODE` legacy;
- `data/model.pkl`, SHA-256 b47e9533…870be, checked;
- real agents through `eval/harness` with the exact batch scorer;
- state empty at 1 May 00:00, as declared.

**Overall:**

| Measure | Value |
|---|---|
| Alerts | 331,087 (one per alerted event) |
| Alert precision | **0.070** [0.068, 0.072], below the May base rate (0.093) |
| Event recall | 0.116 |
| Campaign recall | 0.495 |
| FPR | 0.157 |
| Emails | 62,534 (about 2,017 a day) |

| Legacy alert type | Alerts | Precision [CI] | Attacking / benign IPs |
|---|---|---|---|
| Brute Force | 23,981 | 0.099 [0.096, 0.103] | 2,384 / 21,597 |
| Slow Brute Force | 7,771 | 0.035 [0.031, 0.039] | 273 / 7,498 |
| Credential Stuffing | 5,762 | 0.085 [0.078, 0.092] | 492 / 5,270 |
| Multiple IP Login | 2,010 | 0.112 [0.096, 0.126] | 216 / 1,679 |
| Suspicious Login Time | 68,637 | 0.114 [0.108, 0.120] | 2,386 / 39,121 |
| ML anomaly (High) | 23,010 | 0.075 [0.070, 0.080] | 1,096 / 15,431 |
| ML anomaly (Medium) | 199,916 | 0.051 [0.050, 0.053] | 4,881 / 110,090 |

**HIGH-alert simulated blocks (permanent in legacy):**
- 47,487 benign IPs and 3,967 attacking IPs blocked;
- 676,270 benign events and 201,371 benign successes after a block;
- **166,028 benign users affected** (166,027 excluding the placeholder ID).

The frozen v3 system, on the same month:
- 0 blocks;
- 3,250 legitimate users challenged by a simulated, unenforced step-up;
- step-up precision 0.336.

## S4: label audit on May (descriptive)

Medians / 90th percentiles per IP. "Returning" means an attack-labelled event before 1 May.

| Group | IPs (val_b, seen) | **IPs May** | Events/IP | Active days | Failure ratio | Accounts | Placeholder attempts | Successes | ≤ 5 events | ASN cue |
|---|---|---|---|---|---|---|---|---|---|---|
| R (returning, alerted) | 2,719 | **3,719** | 13 / 161 | 6 / 30 | 0.71 | 4 / 62 | 7 / 73 | 3 / 49 | 23% | 100% |
| N alerted | 806 | **1,061** | 4 / 13 | 1 / 3 | 1.00 | 1 / 3 | 3 / 8 | 0 / 4 | 65% | 97.3% |
| N not alerted | 3,438 | **5,240** | 1 / 3 | 1 / 1 | 1.00 | 1 / 2 | 1 / 2 | 0 / 1 | 98% | 98.4% |
| BA (benign, alerted) | 52,487 | **88,489** | 5 / 16 | 2 / 8 | 0.56 | 2 / 8 | 2 / 7 | 2 / 9 | 53% | 87.6% |
| BN (benign, not alerted) | 283,532 | **464,302** | 1 / 3 | 1 / 2 | 0.25 | 1 / 2 | 0 / 1 | 1 / 2 | 96% | 86.4% |

**Strict misuse among BA** (≥ 20 placeholder attempts and no success over the IP's whole history to 31 May):
- 434 IPs (0.49% of BA), with 130,143 May events and 31,545 alerted events: 7.3% of BA's 434,933 alerted events.
- R reference: 107 of 3,719.

This matches val_a and val_b: most new attacking IPs are one-shot (median 1 event), and a few hundred benign-labelled IPs look like unlisted misuse.

## S5: operations (from the real-agent replay, May events only)

| Stage | µs per May event |
|---|---|
| Rules (`detector.analyze`) | 30.1 |
| Triage and response (`status`, `observe`, `assess`, `decide`, `take_action`) | 29.4 |
| Analysis (per alerted event: 668,793 alerts) | 6.4 |
| Store (the replay's recorder, plus SQLite inserts for the store day only, 2020-05-15) | 13.7 |
| **Whole `_process_event`**: mean / median / p99 | **87.0 / 24.2 / 363.2** |

**SQLite insert per alert** (2020-05-15, 23,327 alerts): mean 1.19 ms, median 0.26 ms, p99 55.6 ms. The store bucket is almost entirely that one day's inserts (23,327 × 1.19 ms ≈ 27.7 s, or 12.8 µs per May event).

**Whole replay** (8,550,667 events): 696.9 s, 81.5 µs per event, peak memory **7.8 GB**. The timer overhead is inside each bucket.

**State at the end:**
- rules: 165,313 IPs, 52,887 accounts, 511,282 account-history entries;
- triage: 118 days closed, 8,024 ASNs.

## S6: functional test (no RBA data, no metrics)

**Setup.** A copy of the frozen backend in a scratch directory, with:
- an empty `data/` holding only `model_v4.pkl` and `model_metrics.json`;
- email variables blanked;
- one seeded previous day (`phase5c_demo/warmup_yesterday.py`, 50 events);
- `live_simulator.py --rate 4 --attack-interval 15` for 150 s.

Record: `results/phase6_s6.json`.

**Result.** 8 incidents formed: 5 step-up, 3 log.
- **Step-up:** all four simulated attacks (fast brute force, slow brute force, credential stuffing, and the external half of the multiple-IP scenario), plus Akua's usual IP 192.168.1.11 through Success After Failures, the recorded known limitation.
- **Log:** Daisy's off-hours-only login (Suspicious Login Time) and the seeded day's two incidents.
- **Pipeline stats were written while the pipeline ran:** 88 events and 14 alerts at 09:33:50, before shutdown (the 5c fix works).
- **Other:** 0 blocks; 5 emails recorded as `disabled`.

The live stats' `avg_event_time_ms` (2,895.8) is wall time divided by events, including idle waiting, so it is not a processing time. That's a display quirk, noted only.

## Bug-policy entries

1. **S1 memory (evaluation code; uses no test result).**
   - **What happened.** The first S1 run (and S2, run in parallel) was stopped by Claude Code because the machine ran critically low on memory. S1 was then scoring all 6,392,584 dev events at once for the declared variant (a)/42 check against Phase 3's cached decisions, while S2's feature pass held about 2M events of state.
   - **What changed** (55e08db, `eval/phase6_secondary.py`): that dev check now scores the dev events in 1M-row chunks and concatenates the results. The arithmetic is unchanged (`score_samples` is row-wise), and nothing is chosen from any result.
   - **Rerun.** S1, then S2, then S3, strictly one at a time, with free memory checked before each: 13.7 GB before S1, 17.6 GB before S2, 17.9 GB before S3.
   - **Before and after values.** The only May value computed before the stop, variant (a) seed 42 (ROC-AUC 0.7487, PR-AUC 0.1633, TPR 0.0030; new attackers 0.5745 / 0.0094 / 0.0009), is **reproduced exactly** by the rerun. The check passes (bit-identical, max |diff| 0). No other S1–S3 value existed before the stop.
2. **No defect was found in the frozen system.**

**Development note (before the test was read, so not a bug-policy entry).** The first dev-only check of the Phase 6 stream re-sorted IP categories, which changed IP codes. That gave different bootstrap clusters and incident tie-breaks, so the val_a and val_b intervals differed from earlier phases. Fixed before reading the test: dev IP codes now keep Phase 3's order. Afterwards P1 (val_a), P2 (val_a and val_b) and P3 equal Phases 3b, 5 and 5c exactly.

## Gates

| Gate | Result |
|---|---|
| `freeze --verify`, before the test was read / after scoring | `freeze MATCHES` / `freeze MATCHES` |
| `lock_test --verify`, before / after | `test lock MATCHES` / `test lock MATCHES` |
| Test access log | exactly one line, `ALLOWED` (the cache read) |
| Offline twin, dev part | equal to Phase 3b rule alerts, Phase 5 ASN ratios, and Phase 5c tiers, scores, blocks, challenges and email log |
| **Real agents vs twin, dev + May** | **equivalent** (below) |
| val_a / val_b recomputation | P1 val_a = Phase 3b; P2 val_a = Phase 5 selection and val_b = Phase 5 confirm; P3 tiers = Phase 5c (all exact) |
| S1 variant (a)/42 vs cached Phase 3 decisions (dev) | bit-identical |
| S2 feature pass vs Phase 4 cache (dev) | equal on all 6,392,584 rows |
| Legacy gate | `phase6_gate_legacy.txt` md5 **f925b387a116ee65b5e066939da40f93**, byte-identical |

Replay details (`phase6_replay_check.json`):
- **Run:** 8,550,667 events.
- **Rule alerts:** 0 mismatches for every detector on dev_train, val_a, val_b and May.
- **Scores and tiers:** 2,156,548 alerted events compared, 0 score and 0 tier mismatches, none missing.
- **Response state:** 0 blocked-state and 0 challenged-state mismatches.
- **Email:** 0 mismatches in the email log (14,319 entries) and in the per-incident outcomes.
- **Totals:** 0 ML alerts, 0 blocks.

## Runtimes

| Step | Time |
|---|---|
| Dev-only checks before the test (twin, P1–P4, S4, replay smoke, S1/S2/S3 smokes) | about 15 min in total |
| Test cache (one read) | 3.7 s |
| Offline twin, dev + May | 73 s |
| P1–P4 | 117 s |
| S4 | 62 s |
| Real-agent replay (announced, estimate 16–20 min) | **12.1 min** |
| S6 live test | about 5 min |
| First S1 + S2 attempt (stopped for low memory) | about 10 min lost |
| **S1** | **23.6 min** |
| **S2** (feature pass 674 s) | **14.7 min** |
| **S3** | **3.5 min** |
| Legacy gate | about 30 s |

## Results against expectations / anything unexpected

**How May differs from April:**

1. **Lower base rate, more attacking IPs per day.**
   - Base rate 0.0926 (val_a 0.107, val_b 0.096), so the 2 × base bar is lower (0.185).
   - May has 13,988 distinct attacking IPs in 31 days, against 9,423 and 9,477 in the two 16-day halves. Distinct-IP counts over windows of different lengths are not directly comparable per day.
   - 66% of May's attacking IPs raise no rule alert (63% in April).
2. **The detectors keep degrading slowly in precision** (val_a → val_b → May): Slow Brute Force 0.263 → 0.253 → 0.245; Credential Stuffing 0.273 → 0.261 → 0.253.
   - Of the five Phase 3b survivors, **four meet 2 × May's base rate**.
   - **Distributed Brute Force misses** by 0.0006 in its lower bound (0.1846 against 0.1852).
   - **Only Slow Brute Force and Credential Stuffing meet the val_a bar 0.2149**, the same two that held against it on val_b.
   - **Brute Force collapses**: 110 alerts at 0.136. It had already failed on val_b and is outside the floor.
3. **Triage generalises.**
   - T2 beats T0 at every budget on May, and amendment 6's test holds.
   - At B = 100, T2's May precision (0.550) is higher than on either half (0.464, 0.389).
   - At B = 2,000 it is lower (0.291 against 0.312 / 0.305).
4. **Step-up precision falls but clears both bars.**
   - May: 0.336 [0.316, 0.357]; val_a 0.456; val_b 0.388.
   - May is below the val_b interval. The val_a → val_b → May decline is monotone.
5. **The step-up cost is higher in May than on either half.**
   - 105.8 legitimate users challenged a day on average (val_a 69.4, val_b 90.3).
   - The busiest day reached exactly 200. U = 200 bounds the mean, which it still does, but only with a margin of about 94.
   - Benign IPs challenged: 2,273 in May (120.2 per day, mean of daily distinct counts).
6. **Almost no new attackers are challenged.**
   - 6 new attacking IPs in the month (May new-attacker step-up precision 0.0019); 1,056 of the 1,062 attacking IPs challenged are returning.
   - All 3,250 legitimate users challenged sit in the new-attacker stratum, by construction.
   - As before, the step-up tier mostly re-finds IPs the blocklist already knew.
7. **The queue was under-used**: 313.5 incidents a day against a cap of 500 (val 496 / 434), though the cap was reached on at least one day. I have not analysed why; that would be a post hoc question.
8. **More attacking IPs end at log**: the log tier holds 72% of attacking IPs with an attack incident (61% and 66% on the halves). This is the cap's coverage cost with more attackers.
9. **Fewer emails**: 90.8 a day (169 and 133 on the halves), although step-up admissions per day were similar (181 against 196 and 180). The cause, perhaps the per-IP 24-hour cooldown with more repeat IPs, was not analysed; any analysis would be post hoc.
10. **Rule workload is stable**: 7,089 incidents a day at 0.164 precision, the same as val_b.
11. **S1 replicates the leakage finding.**
    - The original forest scores ROC-AUC 0.746 on May.
    - Rebuilt with maps from all rows it scores 0.572, and label-free 0.520.
    - The Phase 2 / thesis-era forest's ranking power came mainly from label-filtered training artefacts.
12. **S2, unexpected.** The A-E supervised reference does **better on May's new attackers** than on either dev half:
    - ROC-AUC 0.747 against 0.649 / 0.716;
    - PR-AUC 0.056 against 0.011 / 0.016;
    - TPR at 1% FPR 0.082.

    Without group D (reputation) it stays near chance on new attackers (0.555). This is consistent with the ASN / IP reputation features carrying over to May attackers in ASNs seen before.

    This is the supervised reference only. It is never deployable and was not refitted, and nothing is concluded beyond the measurement.
13. **S3: the legacy system is worse than its base rate on May.**
    - Alert precision 0.070 against a base rate of 0.093.
    - Its permanent HIGH-alert blocks reach 166,028 benign users in one month, against 3,250 challenged (not blocked) by the frozen v3 system.
    - Its ML "High" confidence (0.075) is not more precise than its rules.
14. **Operations.**
    - The frozen pipeline averages 87 µs per event (median 24 µs, p99 363 µs) without the forest.
    - SQLite inserts have a long tail (p99 56 ms; cause not measured).
    - Peak memory in a whole-stream replay is 7.8 GB (process total; I did not break it down).
15. **Process.**
    - My first S1/S2 attempt ran in parallel and exhausted memory (bug-policy entry 1).
    - The test was not re-read: the reruns used the cache, and the access log has one line.
    - Phase 6 changed no frozen file, and `freeze --verify` passed before and after.

Stopped here, as instructed.
