# LANL dataset files (phase L0, step 0)

Dataset: LANL "Comprehensive, Multi-Source Cyber-Security Events".
Local directory: `C:\Users\Dell\datasets\lanl\`.
Values below are copied from `results/lanl_inspect.json`
(`python -m eval.lanl_inspect`).

| file | bytes | SHA-256 (compressed file) |
|---|---|---|
| auth.txt.gz | 7626505158 | 9c6b0cc261b0edd19324f6fd1839743224938a7f644ed202ca70bd70a89bf672 |
| redteam.txt.gz | 4846 | 606635837c684ad11e464075ecf97bc5df325ff7d7f64614d2d8c8af18051669 |

Gzip validity:
- redteam.txt.gz: decompressed in full (gzip CRC and length checked at EOF), 22986 bytes.
- auth.txt.gz: only the first line was decompressed; it decodes as UTF-8. Nothing
  else in the file was decompressed.

Source URL:
- redteam.txt.gz: recorded in the file's Windows Zone.Identifier stream.
  ReferrerUrl `https://csr.lanl.gov/data/cyber1/`; HostUrl
  `https://csr.lanl.gov/data-fence/<signed token redacted>/cyber1/redteam.txt.gz`.
- auth.txt.gz: source URL: not recorded.
