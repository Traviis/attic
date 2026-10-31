#!/usr/bin/env python3
"""Select routine or full compatibility jobs from the evaluated flake matrix."""

import json
import os
import sys
from pathlib import Path

ROUTINE = {"basic-sqlite-local", "basic-postgres-garage", "lix"}
BENCHMARKS = {"access-update-performance", "stable-access-update-performance"}


def select(matrix, full=False, benchmarks=False):
    available = {entry["name"] for entry in matrix["include"]}
    missing = ROUTINE - available
    if missing:
        raise ValueError(f"Missing routine checks: {sorted(missing)}")
    checks = [
        entry for entry in matrix["include"]
        if entry["name"] != "stable-lix"
        and ((entry["name"] in BENCHMARKS and benchmarks)
             or (entry["name"] not in BENCHMARKS and (full or entry["name"] in ROUTINE)))
    ]
    rust = [
        {"os": "ubuntu-latest", "nix": "default"},
        {"os": "macos-latest", "nix": "default"},
        {"os": "ubuntu-latest", "nix": "2.28"},
    ]
    if full:
        rust = [
            {"os": os_name, "nix": version}
            for os_name in ("ubuntu-latest", "macos-latest")
            for version in ("2.28", "2.30", "2.31", "2.34", "default")
        ]
    return {"include": checks}, {"include": rust}


if __name__ == "__main__":
    try:
        matrix, rust = select(
            json.loads(Path(sys.argv[1]).read_text()),
            full=os.environ.get("FULL_QUALIFICATION") == "true",
            benchmarks=os.environ.get("INCLUDE_BENCHMARKS") == "true",
        )
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        sys.exit(f"Cannot select CI checks: {error}")
    print("matrix=" + json.dumps(matrix, separators=(",", ":")))
    print("rust=" + json.dumps(rust, separators=(",", ":")))
