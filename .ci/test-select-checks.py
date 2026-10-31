#!/usr/bin/env python3
"""Exercise CI job selection using evaluated or representative matrix data."""

import importlib.util
import json
import os
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("checks", Path(__file__).with_name("select-checks.py"))
assert spec is not None and spec.loader is not None
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        matrix_file = os.environ.get("ATTIC_MATRIX_FILE")
        if matrix_file:
            try:
                with open(matrix_file) as source:
                    self.matrix = json.load(source)
            except (OSError, ValueError) as error:
                self.fail(f"Cannot load evaluated matrix: {error}")
        else:
            names = [
                "basic-sqlite-local", "basic-sqlite-garage",
                "basic-postgres-local", "basic-postgres-garage", "lix",
                "access-update-performance",
            ]
            self.matrix = {"include": [
                {"name": prefix + name, "attr": prefix + name, "os": ["ubuntu-24.04"]}
                for prefix in ("", "stable-") for name in names
            ]}

    def test_routine(self):
        matrix, rust = checks.select(self.matrix)
        self.assertEqual({entry["name"] for entry in matrix["include"]}, checks.ROUTINE)
        self.assertEqual(len(rust["include"]), 3)
        self.assertEqual(sum(entry["os"] == "ubuntu-latest" and entry["nix"] == "default"
                             for entry in rust["include"]), 1)
        for entry in matrix["include"]:
            self.assertIn(entry, self.matrix["include"])

    def test_full_excludes_benchmarks(self):
        matrix, rust = checks.select(self.matrix, full=True)
        self.assertEqual(len(matrix["include"]), 9)
        self.assertNotIn("stable-lix", {entry["name"] for entry in matrix["include"]})
        self.assertEqual(len(rust["include"]), 10)
        self.assertFalse(checks.BENCHMARKS & {entry["name"] for entry in matrix["include"]})

    def test_benchmarks_require_opt_in(self):
        matrix, _ = checks.select(self.matrix, benchmarks=True)
        self.assertEqual({entry["name"] for entry in matrix["include"]},
                         checks.ROUTINE | checks.BENCHMARKS)
        matrix, _ = checks.select(self.matrix, full=True, benchmarks=True)
        self.assertEqual(matrix, {"include": [
            entry for entry in self.matrix["include"] if entry["name"] != "stable-lix"
        ]})

    def test_missing_required_check_fails(self):
        with self.assertRaisesRegex(ValueError, "Missing routine checks"):
            checks.select({"include": []})


if __name__ == "__main__":
    unittest.main()
