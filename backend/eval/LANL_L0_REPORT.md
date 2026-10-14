# LANL phase L0 report

**Outcome: LA1.2 failed under LA1.1 and again under the LA1.3 fallback. Under
LA1.3 no split is chosen, so the phase stopped after Step 3.** There is no c3,
so Step 4 did not run: no test lock, no guarded loader and no
lanl_test_access.log. Every number below comes from `results/lanl_inspect.json`,
`results/lanl_split.json` or the printed command output named next to it.

Branch `lanl-l0` from `phase6-final` (16696a8). Not pushed or merged.

| commit | content |
|---|---|
| 33495e8 | Steps 0-1: `eval/lanl_inspect.py`, `eval/LANL_FILES.md`, `results/lanl_inspect.json` |
| caee2e3 | Amendment LA1: `eval/PROTOCOL_LANL.md` and a one-line pointer at the end of `eval/PROTOCOL.md` (no code) |
| a7f61a4 | Step 3: `eval/lanl_split.py`, `results/lanl_split.json` |
| (this commit) | this report |

## 1. File integrity (results/lanl_inspect.json)

| file | bytes | SHA-256 |
|---|---|---|
| auth.txt.gz | 7626505158 | 9c6b0cc261b0edd19324f6fd1839743224938a7f644ed202ca70bd70a89bf672 |
| redteam.txt.gz | 4846 | 606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669 |

- redteam.txt.gz: decompressed in full and is valid gzip (22986 bytes).
- auth.txt.gz: only line 1 was decoded, and it decodes as UTF-8. The script feeds
  64-byte compressed pieces to zlib until a newline appears, then throws away
  any decompressed bytes after it without reading them.
- Source URL: redteam.txt.gz has one in its Zone.Identifier stream (referrer
  https://csr.lanl.gov/data/cyber1/; signed host URL recorded with the token
  redacted). auth.txt.gz: not recorded. See `eval/LANL_FILES.md`.

## 2. Red-team format (results/lanl_inspect.json)

No local copy of the dataset documentation was found, so the field meanings
are labelled "unconfirmed".

- First 5 lines:
  ```
  150885,U620@DOM1,C17693,C1003
  151036,U748@DOM1,C17693,C305
  151648,U748@DOM1,C17693,C728
  151993,U6115@DOM1,C17693,C1173
  153792,U636@DOM1,C17693,C294
  ```
- Fields per line: 4 on all 749 rows. Field 0 is an integer time. Fields 1-3
  are unconfirmed. By value pattern they look like user@domain, source
  computer and destination computer, and LA1.5 and lanl_split.py treat them
  that way.
- Rows: 749. Malformed rows: 0. Empty lines: 0.
- Time min 150885, max 2557047. Sorted (non-decreasing): yes.
- auth.txt.gz line 1, time of the first event: **t0 = 1**.
- Every red-team time is >= t0: yes. Red-team day indices run from 1 to 29
  (day = floor((time - t0) / 86400)), so day boundaries are at 1 + k*86400.

## 3. Applying LA1 (results/lanl_split.json)

Nearest-rank uses rank ceil(p*N) with N = 749 (ranks printed:
0.5→375, 0.625→469, 0.75→562, 0.4→300, 0.55→412, 0.7→525).

### LA1.1: q(0.50), q(0.625), q(0.75) failed LA1.2

| | q time | q day | cut (time) | cut day |
|---|---|---|---|---|
| c1 | 1072660 | 12 | 1123201 | 13 |
| c2 | 1080147 | 12 | 1123201 | 13 |
| c3 | 1163440 | 13 | 1209601 | 14 |

| split | red-team events | distinct days | LA1.2 |
|---|---|---|---|
| dev_train | 547 | 8 | (no minimum) |
| val_a | 0 | 0 | fail |
| val_b | 81 | 1 | fail |
| test | 121 | 9 | pass |

### LA1.3 fallback: q(0.40), q(0.55), q(0.70) failed LA1.2

| | q time | q day | cut (time) | cut day |
|---|---|---|---|---|
| c1 | 771340 | 8 | 777601 | 9 |
| c2 | 1075345 | 12 | 1123201 | 13 |
| c3 | 1095853 | 12 | 1123201 | 13 |

| split | red-team events | distinct days | LA1.2 |
|---|---|---|---|
| dev_train | 323 | 6 | (no minimum) |
| val_a | 224 | 2 | pass |
| val_b | 0 | 0 | fail |
| test | 202 | 10 | pass |

**Rule used: none.** LA1.3 says: "If LA1.2 fails again, do not choose any
split: stop and report."

For the test period, only event and distinct-day counts were computed, as
LA1.2 requires. No users, computers, per-day histogram or strata were
computed for it.

## 4. Dev-only strata (LA1.5)

Not computed. LA1.5 strata are defined per chosen period, and no period was
chosen. Distinct users and computers were also not computed for the same
reason.

## 5. Gates

| check | before | after |
|---|---|---|
| `python -m eval.freeze --verify` | freeze MATCHES | freeze MATCHES |
| `python -m eval.lock_test --verify` | test lock MATCHES | test lock MATCHES |
| `python -m eval.lanl_lock --verify` | n/a | not run: no c3, so no lock was created |
| RBA `results/test_access.log` | 1 line (Phase 6 ALLOWED) | unchanged, 1 line |
| `results/lanl_test_access.log` | n/a | not created (Step 4 did not run) |

auth.txt.gz was not read past line 1.

## 6. Unexpected findings

- The red-team events are concentrated on a few days. Three of the six
  candidate percentile times fall on day 12 (1072660, 1075345, 1080147), and
  so does 1095853. Rounding forward to the next day boundary therefore puts
  two cuts on the same boundary in both rules: c1 = c2 in LA1.1 and c2 = c3
  in LA1.3. Each time this leaves one validation split empty.
- Even without that collapse, LA1.1's val_b has its 81 events on a single
  day (day 13). So the 2-day minimum cannot be met by any period that covers
  only day 13.
- The test window starting at c3 passed LA1.2 under both rules (121 events
  on 9 days, and 202 events on 10 days).

## 7. Decision needed (not taken here)

LA1 allows no third attempt. Any new split rule would be a new amendment
(for example LA2), and it would be written after the failed boundaries and
the per-split counts above have been seen. It is not blind the way LA1 was.
The choice of rule, and whether that loss of blindness is acceptable,
belongs to Dr. Ansong and the user. No split, lock or loader exists yet.
