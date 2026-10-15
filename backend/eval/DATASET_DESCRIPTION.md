# RBA dataset description

## Is Account Takeover counts (whole file, per month)

**Timing.** These counts were made on 2026-10-15, **after the May 2020 test
month had already been scored** (once). They are a description of
the dataset, outside the evaluation. They were not used to choose, tune or
re-run anything, and no score or metric was computed. The test-month figure
below must not be read as part of the pre-declared protocol.

**Method.** The raw CSV (`C:\Users\Dell\Downloads\rbadataset\rba-dataset.csv`,
9,052,907,531 bytes, SHA-256
`001f3589595821519b53428aee656b4458e43d8f5b4b9beb6ec2bed8f2209067`) was
streamed directly with `pyarrow.csv.open_csv` (pyarrow 26.0.0), reading only
`Login Timestamp`, `Login Successful`, `Is Attack IP` and
`Is Account Takeover`, with booleans parsed strictly (`True`/`False` only).
The evaluation loaders (`eval/datasets.py`) and the Parquet copies were not
used. Month = the `YYYY-MM` prefix of `Login Timestamp` as written in the CSV.
Raw output: `results/rba_ato_counts.json`.

| Month | Rows | ATO = True | of which Login Successful | of which Is Attack IP |
|---|---:|---:|---:|---:|
| 2020-02 | 2,004,450 | 22 | 22 | 13 |
| 2020-03 | 2,214,823 | 11 | 11 | 5 |
| 2020-04 | 2,173,311 | 11 | 11 | 7 |
| 2020-05 (test month) | 2,158,083 | 15 | 15 | 7 |
| 2020-06 | 2,185,601 | 17 | 16 | 10 |
| 2020-07 | 2,221,046 | 10 | 10 | 6 |
| 2020-08 | 2,171,500 | 17 | 17 | 11 |
| 2020-09 | 2,162,510 | 16 | 16 | 6 |
| 2020-10 | 2,313,404 | 14 | 14 | 6 |
| 2020-11 | 3,090,246 | 8 | 8 | 6 |
| 2020-12 | 3,270,165 | 0 | 0 | 0 |
| 2021-01 | 3,100,885 | 0 | 0 | 0 |
| 2021-02 | 2,203,240 | 0 | 0 | 0 |
| **Total** | **31,269,264** | **141** | **140** | **77** |

No null values in `Is Account Takeover`.

**Checks against earlier figures.** Row totals per month and overall match
`results/rba_conversion_stats.json` and the Phase 2 data report. The
development months (2020-02 to 2020-04) sum to 44 ATO rows, the "44 ATO
events" of `audit_scratch/PHASE2_DATA_REPORT.md:79` and
`audit_scratch/PHASE2_REPORT.md:22`, which cover development data only
(2020-02-03 to 2020-04-30, all rows, no filter; dev_train 31 + dev_val 13,
`PHASE2_DATA_REPORT.md:29-32`).

**Observation.** No row is labelled as an account takeover from December 2020
to the end of the file (2021-02).
