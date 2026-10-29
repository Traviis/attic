#!/usr/bin/env python3
"""Prepare an Attic calendar-versioned release without refreshing dependencies."""

import argparse
import datetime
import re
import tomllib
from pathlib import Path

CALVER = re.compile(r"[1-9][0-9]{3}\.(?:[1-9]|1[0-2])\.(?:0|[1-9][0-9]*)")
MANIFESTS = (
    "attic/Cargo.toml",
    "client/Cargo.toml",
    "server/Cargo.toml",
    "token/Cargo.toml",
)


def prepare(root, requested=None, today=None):
    today = today or datetime.date.today()
    manifests = {root / name: (root / name).read_text() for name in MANIFESTS}
    packages = {
        tomllib.loads(text)["package"]["name"]: tomllib.loads(text)["package"][
            "version"
        ]
        for text in manifests.values()
    }
    versions = set(packages.values())
    if len(versions) != 1:
        raise ValueError("workspace package versions disagree")
    current = versions.pop()
    version = requested
    if version is None:
        month = f"{today.year}.{today.month}"
        patch = int(current.split(".")[2]) + 1 if current.startswith(month + ".") else 0
        version = f"{month}.{patch}"
    if not CALVER.fullmatch(version):
        raise ValueError(
            "version must be YYYY.M.PATCH, with month 1 through 12 and no leading zeroes"
        )
    if tuple(map(int, version.split("."))) <= tuple(map(int, current.split("."))):
        raise ValueError("release version must increase")
    updates = {}
    for path, text in manifests.items():
        pattern = (
            rf'(\[package\]\s*\nname = "[^"]+"\nversion = "){re.escape(current)}(")'
        )
        updates[path], count = re.subn(pattern, rf"\g<1>{version}\2", text, count=1)
        if count != 1:
            raise ValueError(f"{path}: package version missing")
    lock = root / "Cargo.lock"
    text = lock.read_text()
    for package in packages:
        pattern = rf'(\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "){re.escape(current)}(")'
        text, count = re.subn(pattern, rf"\g<1>{version}\2", text)
        if count != 1:
            raise ValueError(f"{lock}: expected one {package} package")
    tomllib.loads(text)
    updates[lock] = text
    nix = root / "crane.nix"
    updates[nix], count = re.subn(
        rf'version = "{re.escape(current)}";',
        f'version = "{version}";',
        nix.read_text(),
    )
    if count != 1:
        raise ValueError("crane.nix: package version disagrees")
    for path, text in updates.items():
        path.write_text(text)
    return version


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parent.parent
    )
    parser.add_argument("--version")
    args = parser.parse_args()
    try:
        print(prepare(args.root, args.version))
    except ValueError as error:
        parser.error(str(error))
