# LANL phase L2b report

Branch `lanl-l2b` from `lanl-l2`. Not pushed or merged. The LANL test was not
read, and nothing was re-run on RBA data. No frozen file, LA3 procedure or saved
L2 result changed: `git diff lanl-l2 -- results/` shows only the new
`lanl_l2b_stepup.json`.

| commit | content |
|---|---|
| 7b381ff | Q2 numbers: `eval/lanl_l2b_stepup.py`, `results/lanl_l2b_stepup.json` (saved L2 arrays only) |
| f3e1ceb | **Erratum LA4**, committed alone: "LANL erratum LA4: corrections to LA3's description, no procedure change" |
| bd7a185 | Arithmetic fix in LA4.2: the sum is 39,518,854. I wrote 39,519,854 in f3e1ceb and corrected it in a separate commit rather than amending |
| (this commit) | this report |

## Q1. Twin bug provenance: independent of the RBA twin

**The bug.** It was in `eval/lanl_a.py`, `Twin._multi` (Multiple IP Login),
in the step that maps the previous-success time of each (account, source
computer) pair back to account-sorted order. It was fixed before
`eval/lanl_a.py` was first committed (350097c, which added the file;
`git log --diff-filter=A`). The buggy version therefore exists in no commit.
The before text below is from the L2 session's edit; the after text is the
committed code at `eval/lanl_a.py:300-302`.

```diff
-        # back to the account-sorted order
-        pp_stream = np.empty(n, np.int64)
-        pp_stream[o2] = prev_pair
-        pp = pp_stream[o]
+        # back to the account-sorted order (o2 permutes the account-sorted arrays)
+        pp = np.empty(n, np.int64)
+        pp[o2] = prev_pair
```

`o2` (`eval/lanl_a.py:277`) sorts `pk`, which is built from the
*account-sorted* arrays (`:276`). So `pp[o2] = prev_pair` is already in
account-sorted order. The extra `[o]` applied the account sort a second time.
That paired each success with another success's previous-pair time, which
corrupted the `known_ip` exemption (`:303`). It surfaced as 2,573 twin alerts
against the agents' 31,514 on the first 300,000 day-8 events.

**Independent of RBA.**
- `eval/lanl_a.py` imports nothing from the RBA evaluation modules: its
  imports (`:43-48`) are config, agents.rules_v3, agents.triage, eval.lanl_la3
  and eval.lanl_convert.
- The RBA Phase 6 twin computes Multiple IP Login with
  `eval/phase3_rules.multi_ip_stats` (`eval/phase3_rules.py:273`; called at
  `eval/phase6.py:213`, filtered by the exemptions at `:214-217`).
- That function uses pandas `groupby(...).shift(1)` in stream order and has no
  sort-and-unsort step.
- Separately, Phase 6's real-agent replay compared the agents to that twin
  directly, with 0 mismatches over 8,550,667 events
  (`results/phase6_replay_check.json`).

Nothing about the bug applies to RBA, so there is nothing to re-run.

## Q2. Step-up challenged users vs U = 200

**How U is applied.** U is a selection constraint, not a runtime cap.
- `eval/phase5b.py:171-176`, `choose(rows, u)`, keeps step-up rates whose
  val_a mean legitimate users challenged per day is <= u. `eval/phase5b.py:50`
  sets U = 200 and `:231` applies it.
- `eval/PROTOCOL.md:727-739` defines U as "a ceiling on that mean", chosen
  a priori.
- The chosen rate, 200, is frozen as `config.py:267`
  (`RESPONSE_TIER_RATES = {"block": 0, "step_up": 200, "queue": 500}`).

**What the frozen code enforces at run time.**
- **Incidents, not users, are capped.** At most 200 step-up *incidents* a day,
  where an incident is (source IP, day) (`agents/triage.py:5`). Admission
  stops once `self.admitted[tier] < k` fails (`agents/triage.py:193-195`).
- **A challenge covers the whole source.** Each step-up alerted event places
  or extends a challenge on the source IP (`agents/response_agent.py:113`),
  lasting `STEP_UP_TTL_SECONDS = 3600` (`config.py:295`, BlockList
  `agents/response_agent.py:30, :40`). Every later login from that source
  within the TTL is "challenged" (`agents/response_agent.py:86-91`;
  `agents/monitoring_agent.py:86, :100`), whoever the user is.
- **Users per day are unbounded.** Nothing in the frozen code limits users
  per incident or per day.

**Why RBA stayed near 200 and LANL did not.** On RBA, the frozen rate was
chosen so that val_a's *mean* stayed <= 200, and an RBA IP carries few users.
The saved daily maxima (`results/phase6_primary.json`,
`P3/response_cost/all/step_up/legitimate_users_daily`) are 189 for val_a, 210
for val_b and 200 for May. So "exactly 200" was May's busiest day, and val_b
exceeded it.

On LANL a source computer can carry thousands of accounts: the busiest one
challenged 13,579 users in a day (table below). About 200 such incidents
therefore reach 12,000 to 23,000 users a day.

**Per val day** (`results/lanl_l2b_stepup.json`, from the saved L2 causal twin
arrays). Users are distinct normalised source accounts with a non-positive
event from a challenged source computer. The daily totals equal
`lanl_a_dev.json` (`check_equals_lanl_a_dev_daily: true` for both splits).

| split | day | step-up incidents | legitimate users challenged | challenged source computers | 5 largest (source computer: users) |
|---|---|---|---|---|---|
| val_a | 08 | 200 | 22481 | 324 | C612 13457, C529 13414, C1065 13343, C528 13142, C467 12953 |
| val_a | 09 | 0 | 12287 | 159 | C528 4318, C529 4193, C612 4169, C1065 4137, C467 4061 (none is a day-9 step-up incident) |
| val_a | 10 | 0 | 0 | 0 | none |
| val_a | 11 | 77 | 12835 | 77 | C612 8330, C529 8315, C1065 8209, C528 8078, C457 7808 |
| val_b | 12 | 200 | 22848 | 218 | C1065 13579, C529 13474, C612 13446, C528 13150, C467 13139 |
| val_b | 13 | 200 | 20719 | 339 | C612 11994, C529 11885, C467 11852, C528 11811, C1065 11766 |

On days 8, 11, 12 and 13, every top-5 computer is a step-up incident that
day.

Day 9 has no step-up incidents but 12,287 challenged users. The saved file
does not show where those challenges were placed. The likely cause is
challenges placed on day 8 that are still inside their 3,600 s TTL in day 9's
first hour; I infer this from the TTL and did not measure it.

Day 10 has neither step-up incidents nor challenges.

## Check: RBA S1 variant (c), is_new features on fit rows: yes, 0 on every fit row

- **The maps and the fit use the same rows.** `eval/phase6_secondary.py:83`
  sets `maps_rows, fit_rows = (allr, allr)` for (c), and `:85` makes `fit_df`
  the same frame as `maps_df`. `eval/phase4b.py:118-119` builds the known sets
  from `maps_df` and computes the fit features on `fit_df`.
- **Every fit row is therefore known.** `ml/train_from_dataset.py:172-173`
  takes `known_ips_set` and `known_countries_set` from all map rows.
  `:197-198` sets `is_new_ip` and `is_new_country` to 1 only for values not
  in those sets. Every fit row is a map row, so both features are 0 on every
  fit row.
- **The scaler and forest see a constant.** `eval/phase4b.py:120` fits the
  scaler on that matrix and `eval/phase6_secondary.py:93` fits the forest on
  it. In S1 variant (c), `is_new_ip` and `is_new_country` were constant on
  the fit rows: the scaler's mean for them is 0, and the forest never sees
  them vary.
- **The same holds for (a) and (b).** In (a), maps and fit are the same
  benign frame. In (b), the fit rows (benign) are a subset of the map rows
  (all).

This belongs in the paper's S1 description.

## Gates

| check | before | after |
|---|---|---|
| `python -m eval.freeze --verify` | freeze MATCHES | freeze MATCHES |
| `python -m eval.lock_test --verify` | test lock MATCHES | test lock MATCHES |
| `python -m eval.lanl_lock --verify` | LANL test lock MATCHES | LANL test lock MATCHES |
| RBA `results/test_access.log` | 1 line | 1 line |
| `results/lanl_test_access.log` | the one CONVERT line | the one CONVERT line |

Phase L2b stops here. Phase L3 has not been started.
