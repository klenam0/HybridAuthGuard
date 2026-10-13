# backend/tests/test_datasets.py
"""
Leakage guard for the locked test split (eval/datasets.py, eval/PROTOCOL.md).

load("test") must raise unless FINAL_EVAL=1, must not read the file when it
refuses, and must log every call, refused or allowed. The test points the
module at a temporary file and log, so the real locked file is never opened.

Run from backend/:  python -m unittest tests.test_datasets -v
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

import pandas as pd

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from eval import datasets  # noqa: E402


class TestLockedTestSplit(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.tmp.name, "test.parquet")
        self.log_file = os.path.join(self.tmp.name, "access.log")
        pd.DataFrame({
            datasets.TS: pd.to_datetime(["2020-05-01 00:00:01", "2020-05-31 23:59:59",
                                         "2020-06-01 00:00:00"]),
            "User ID": [1, 2, 3],
        }).to_parquet(self.test_file)
        self.patches = [
            mock.patch.object(datasets, "TEST_FILE", self.test_file),
            mock.patch.object(datasets, "ACCESS_LOG", self.log_file),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _log_lines(self):
        if not os.path.exists(self.log_file):
            return []
        with open(self.log_file, encoding="utf-8") as f:
            return f.read().splitlines()

    def test_refused_without_final_eval(self):
        for value in (None, "0", "true", "yes", " 1"):
            env = {k: v for k, v in os.environ.items() if k != "FINAL_EVAL"}
            if value is not None:
                env["FINAL_EVAL"] = value
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(datasets.pq, "read_table") as read, \
                    self.assertLogs(datasets.log, "WARNING"):
                with self.assertRaises(datasets.TestSetLocked):
                    datasets.load("test")
                read.assert_not_called()
        lines = self._log_lines()
        self.assertEqual(len(lines), 5)
        self.assertTrue(all("\tREFUSED\t" in ln for ln in lines))

    def test_allowed_with_final_eval_and_logged(self):
        with mock.patch.dict(os.environ, {"FINAL_EVAL": "1"}), \
                self.assertLogs(datasets.log, "WARNING"):
            df = datasets.load("test", columns=["User ID"])
        self.assertEqual(df["User ID"].tolist(), [1, 2])   # June row excluded
        lines = self._log_lines()
        self.assertEqual(len(lines), 1)
        self.assertIn("\tALLOWED\t", lines[0])

    def test_dev_splits_do_not_log(self):
        with mock.patch.object(datasets, "_read", return_value=pd.DataFrame()):
            datasets.load("dev_train")
            datasets.load("dev_val")
        self.assertEqual(self._log_lines(), [])

    def test_unknown_split(self):
        with self.assertRaises(ValueError):
            datasets.load("eval")

    def test_boundaries(self):
        self.assertEqual(datasets.DEV_TRAIN_END, pd.Timestamp("2020-03-30"))
        self.assertEqual(datasets.TEST_START, pd.Timestamp("2020-05-01"))
        self.assertEqual(datasets.DEV_START.day_name(), "Monday")


if __name__ == "__main__":
    unittest.main()
