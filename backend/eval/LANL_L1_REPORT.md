# LANL phase L1 report

**Outcome.** auth.txt.gz was converted into 58 daily partitions: days 0-13
under `auth\dev\` and days 14-57 under `auth\test\`. The test end is day 57
(LA2.1). Every line became a row, with no malformed lines, and time is
non-decreasing across the whole file. The lock now also covers the 44 test
partition files and the test row total. All gates match. No detector was
mapped and no metric was computed.

Every number below comes from a saved file or from printed output named next to it:
`results/lanl_l1_smoke.json` (smoke), `results/lanl_l1_convert.json` (convert),
`results/lanl_l1_dev_checks.json` (dev checks), `results/lanl_l1_coverage.json`
(coverage) and `eval/LANL_TEST_LOCK.json` (lock).

Branch `lanl-l1` from `lanl-l0` (76214fd). Not pushed or merged.

| commit | group |
|---|---|
| 1bb2e00 | Documentation: `eval/LANL_FILES.md` (documentation URL, date read, field lists, note on failed events) |
| 8060012 | Conversion code: `eval/lanl_convert.py`, smoke record `results/lanl_l1_smoke.json` |
| 9da0f53 | Conversion output and checks: `results/lanl_l1_convert.json`, `eval/lanl_dev_checks.py` + `results/lanl_l1_dev_checks.json`, `eval/lanl_l1_coverage.py` + `results/lanl_l1_coverage.json`, the CONVERT line in `results/lanl_test_access.log` |
| 9c2364d | Lock and loader: `eval/lanl_lock.py`, `eval/LANL_TEST_LOCK.json`, `eval/lanl_data.py` |
| (this commit) | Report |

## 1. Documentation recorded

`eval/LANL_FILES.md` now records:
- the documentation URL https://csr.lanl.gov/data/cyber1/, read on 14 Oct 2026
- 58 consecutive days, with time starting at 1 at 1-second resolution
- the nine auth fields and the four red-team fields, in documented order
- that missing values are written "?"
- that red-team events are "taken from the authentication data"
- that failed events are included only for users with a success somewhere

The red-team field meanings are now confirmed. `LANL_L0_REPORT.md` was left
as written. The Parquet column names are time (int64), src_user, dst_user,
src_computer, dst_computer, auth_type, logon_type, auth_orientation and
success. Every column except time is a string kept exactly as written.

## 2. Resources and estimates

| | value | source |
|---|---|---|
| free disk on C:\ (output drive) before the full run | 86820241408 bytes | convert `resources_before` |
| total memory / available before the full run | 34135404544 / 17168216064 bytes | convert `resources_before` |
| smoke run: lines | 5000000 (all day 0, all before c3; test rows 0) | smoke |
| smoke run: rows/second | 930745 | smoke |
| smoke run: peak working set | 654381056 bytes | smoke |
| smoke run: output bytes per million rows | 6265709 | smoke |
| estimated full time | 1223 s (over 10 minutes; stated before the full run started) | smoke `estimate_full` |
| estimated full output | 7092880497 bytes = 0.0817 of free disk (under the 0.80 limit) | smoke `estimate_full` |
| estimated full lines | 1132015554 | smoke `estimate_full` |

The estimates scale the smoke run by the ratio of the file size to the
compressed bytes the smoke run consumed (scale 226.4). The smoke output was
deleted after the run.

The first smoke attempt failed on a bug in the script, and the second recorded
a peak memory of 0 because a Windows API call failed. Both were fixed before the
recorded smoke run above, and neither attempt wrote anything to the repo or to
the access log.

## 3. Conversion counts and integrity checks (convert)

| check | value |
|---|---|
| lines read (counted on decompressed bytes, independently of the CSV parser) | 1051430459 |
| rows written, dev (days 0-13) | 239471628 |
| rows written, test (days >= 14) | 811958831 |
| rows written, total | 1051430459 |
| lines read = rows written (dev + test) | true |
| malformed lines (not 9 fields; empty lines not skipped) | 0 (sidecar `malformed_lines.tsv` is empty: SHA-256 e3b0c442...b855) |
| time non-decreasing over the whole file | true |
| decompressed bytes | 73413019178 |
| compressed bytes consumed | 7626505158 (the whole file) |
| dev partitions written | days 00-13 |
| output bytes (dev + test partitions) | 7345818123 |
| elapsed | 1061.0 s (990989 rows/s) |
| peak working set | 2144256000 bytes |
| pyarrow peak pool | 870167988 bytes |

Output root: `C:\Users\Dell\datasets\lanl\parquet\`, outside the repo. Dev
partitions are at `auth\dev\day=DD\part-0.parquet` and test partitions at
`auth\test\day=DD\part-0.parquet`. No dev path or glob reaches `auth\test`.
Row order is preserved, and nothing was recoded: "?" is kept as written.

Over test rows, the conversion computed only the test end, the total test row
count, their part of the whole-file time-order check, and (in `lanl_lock.py`)
the partition SHA-256 values. Test partitions were not opened after writing.

`results/lanl_test_access.log` holds exactly one line:
`2026-10-14T16:01:09	CONVERT	no statistics	C:\Users\Dell\HybridAuthGuard\backend\eval\lanl_convert.py`.

## 4. Test end (LA2.1)

The test end is **day 57**, the day index of the last row of auth.txt.gz
(convert `test_end_day`). The test is [day 14, day 57], which is **44 days**
(coverage `test_days`). Days 0-57 are 58 days, consistent with the
documentation.

## 5. Dev checks (dev checks; dev partitions only)

Each dev day's row count matches both the Parquet footer and the conversion
record (`rows_match_convert_json` is true for all 14 days). Their total is
239471628, which matches convert `rows_written_dev`.

The table gives each day's row count and its share of "?" in auth_type and
logon_type, rounded to 4 decimals from the printed output. The share of "?" was
exactly 0.0 on every dev day in src_user, dst_user, src_computer, dst_computer,
auth_orientation and success (printed min = max = 0.0). The success field takes
two values, `Success` and `Fail`.

| day | rows | "?" auth_type | "?" logon_type | Fail rows (share) | Success rows (share) |
|---|---|---|---|---|---|
| 00 | 15740952 | 0.5786 | 0.1581 | 109734 (0.0070) | 15631218 (0.9930) |
| 01 | 17562370 | 0.5755 | 0.1481 | 110709 (0.0063) | 17451661 (0.9937) |
| 02 | 15585920 | 0.5780 | 0.1478 | 90713 (0.0058) | 15495207 (0.9942) |
| 03 | 13473144 | 0.5714 | 0.1339 | 76012 (0.0056) | 13397132 (0.9944) |
| 04 | 13398091 | 0.5711 | 0.1327 | 75573 (0.0056) | 13322518 (0.9944) |
| 05 | 18557390 | 0.5786 | 0.1552 | 116984 (0.0063) | 18440406 (0.9937) |
| 06 | 19381629 | 0.5808 | 0.1571 | 111487 (0.0058) | 19270142 (0.9942) |
| 07 | 19394277 | 0.5801 | 0.1565 | 125131 (0.0065) | 19269146 (0.9935) |
| 08 | 19374681 | 0.5806 | 0.1555 | 121254 (0.0063) | 19253427 (0.9937) |
| 09 | 18141675 | 0.5745 | 0.1409 | 84517 (0.0047) | 18057158 (0.9953) |
| 10 | 14170706 | 0.5709 | 0.1300 | 59866 (0.0042) | 14110840 (0.9958) |
| 11 | 14012614 | 0.5713 | 0.1303 | 89125 (0.0064) | 13923489 (0.9936) |
| 12 | 19870851 | 0.5764 | 0.1482 | 169605 (0.0085) | 19701246 (0.9915) |
| 13 | 20807328 | 0.5761 | 0.1449 | 154836 (0.0074) | 20652492 (0.9926) |

Distinct values over dev: src_user 62681, dst_user 77410, src_computer 13793,
dst_computer 13354.

## 6. Red-team match (dev checks; 628 dev red-team events, dev only)

| | events |
|---|---|
| an auth row with the same time, src_computer and dst_computer exists | 614 |
| (a) red-team user = src_user of such a row | 614 |
| (b) red-team user = dst_user of such a row | 614 |
| both (a) and (b) | 614 |
| (a) only / (b) only | 0 / 0 |
| neither | 14 |

There are 614 matched auth rows under (a), 614 under (b) and 614 under
(a) or (b). Their success values are all `Success` (614). This check was not
run on the test period.

## 7. Lock extension (lock)

The L0 keys of `eval/LANL_TEST_LOCK.json` (c3, redteam_sha256,
test_rows_sha256, hash definition) are unchanged. In the git diff, the only
removed line is the hash-definition line gaining a trailing comma. A new
section `l1_auth_test` contains:
- the SHA-256 of all **44** files under `auth\test\`, hashed as file bytes
  without opening them as Parquet
- `test_rows_total` **811958831**, taken from convert `rows_written_test`
- `test_end_day` **57**

`--verify` recomputes both sections. The file hashes also show that the set of
test files is unchanged. The row total is checked against the conversion
record, not re-derived, because test partitions are not opened after writing.

Loader (`eval/lanl_data.py`): `load_lanl(split, source, columns)` now returns
auth rows as a pyarrow Table for dev_train, val_a and val_b, read only from
`auth\dev`. `"test"` still raises unless FINAL_EVAL=1 and logs ALLOWED or
DENIED. An allowed auth test read first checks the test files against the
lock. Test run, printed output, with the log pointed at a scratch file:
- `test/auth` was denied, and the scratch log got one `DENIED` line.
- Dev auth loads (time column only) returned 133093773 rows for dev_train,
  65699676 for val_a and 40678179 for val_b. Each equals the sum of the dev
  per-day counts in convert.

The allowed path was not run.

## 8. The LA2.7 figure and coverage (coverage)

| | value |
|---|---|
| test days (c3 day 14 to test end day 57, inclusive) | 44 |
| test days with at least one red-team event | 9 |
| **test days with no red-team event (LA2.7)** | **35** |
| test end before day 29 (last red-team day)? | no |
| red-team rows after the test end | 0 |

The test end (57) is on or after the last red-team day (29). So every red-team
row with time >= c3 lies inside the test, and the L0 counts in
`results/lanl_split_la2.json` (9 days) are the test's counts. The script read
no test row; it used only saved records.

## 9. Gates (printed output)

| check | before | after |
|---|---|---|
| `python -m eval.freeze --verify` | freeze MATCHES | freeze MATCHES |
| `python -m eval.lock_test --verify` | test lock MATCHES | test lock MATCHES |
| `python -m eval.lanl_lock --verify` | (L0 section only) | LANL test lock MATCHES |
| RBA `results/test_access.log` | 1 line | 1 line |
| `results/lanl_test_access.log` | 0 bytes | exactly 1 CONVERT line |

## 10. Runtimes

| step | seconds | source |
|---|---|---|
| smoke conversion (5M lines) | 5.4 | smoke |
| full conversion | 1061.0 | convert |
| dev checks | 73.5 | dev checks |

## 11. Unexpected findings

- **The failure value is `Fail`, not "Failure".** The success field holds
  `Success` and `Fail` on every dev day, not "success/failure" as the
  documentation's field description might suggest. It was kept as written.
- **14 of 628 dev red-team events have no auth row with the same time, source
  computer and destination computer.** The documentation says red-team events
  are taken from the authentication data. These 14 were not examined further,
  because this phase only asked for the counts. Which split they fall in, and
  whether a near match exists, can be checked on dev if the detector-mapping
  amendment needs it.
- **Wherever a match exists, the red-team user appears as both the source
  and the destination user, and the row is a Success.** No matched red-team
  row is a failed authentication.
- **No "?" appears in the user, computer, orientation or success fields on
  any dev day.** "?" appears only in auth_type (about 57-58% of rows) and
  logon_type (about 13-16%). Any missing values in the other fields must be
  written in some other form; that question belongs to the detector-mapping
  amendment.
- **Estimates against the real run.** Time was 1061.0 s against 1223 s
  estimated, and output 7345818123 bytes against 7092880497 estimated. Peak
  working set was 2144256000 bytes, higher than the smoke peak (654381056),
  which the estimate did not scale. That is still about 1/8 of the memory
  available before the run.
- **The test period holds most of the data:** 811958831 of 1051430459 rows,
  because it is 44 of the 58 days.
- **The CONVERT line's argv field is a script path.** It records the script
  path (`...\eval\lanl_convert.py`) rather than `-m eval.lanl_convert`, because
  Python rewrites `sys.argv[0]` under `-m`.

Phase L1 stops here. No detector mapping, no metric, and no further reading
of test partitions.
