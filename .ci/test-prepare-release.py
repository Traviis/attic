#!/usr/bin/env python3
"""Exercise version preparation against disposable copies and Cargo metadata."""

import datetime
import importlib.util
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "prepare_release", ROOT / ".ci/prepare-release.py"
)
assert SPEC is not None and SPEC.loader is not None
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("Cargo.toml", "Cargo.lock", "crane.nix", *RELEASE.MANIFESTS):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for directory in ("attic", "client", "server", "token"):
            shutil.copytree(ROOT / directory / "src", self.root / directory / "src")

    def test_prepares_all_packages_and_cargo_accepts_lockfile(self):
        version = RELEASE.prepare(self.root, today=datetime.date(2026, 10, 1))
        self.assertEqual(version, "2026.10.0")
        for manifest in RELEASE.MANIFESTS:
            data = tomllib.loads((self.root / manifest).read_text())
            self.assertEqual(data["package"]["version"], version)
        lock = tomllib.loads((self.root / "Cargo.lock").read_text())
        self.assertEqual(
            {
                p["version"]
                for p in lock["package"]
                if p["name"] in {"attic", "attic-client", "attic-server", "attic-token"}
            },
            {version},
        )
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--no-deps",
                "--format-version",
                "1",
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            RELEASE.prepare(self.root, today=datetime.date(2026, 10, 2)), "2026.10.1"
        )
        self.assertEqual(
            RELEASE.prepare(self.root, today=datetime.date(2026, 11, 1)), "2026.11.0"
        )

    def test_invalid_or_inconsistent_input_changes_no_files(self):
        for version in ("2026.13.0", "2026.01.0", "2026.1.01", "0.1.0", "2026.1.0\n"):
            before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
            with self.assertRaises(ValueError):
                RELEASE.prepare(self.root, version)
            self.assertEqual(before, {p: p.read_bytes() for p in before})
        (self.root / "crane.nix").write_text('version = "99.0.0";')
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with self.assertRaises(ValueError):
            RELEASE.prepare(self.root, "2026.10.0")
        self.assertEqual(before, {p: p.read_bytes() for p in before})


if __name__ == "__main__":
    unittest.main()
