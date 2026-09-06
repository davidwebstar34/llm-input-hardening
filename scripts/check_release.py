"""Validate stable release metadata and optionally extract GitHub release notes."""
from __future__ import annotations

import argparse
from datetime import date
import os
from pathlib import Path
import re
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as exc:
    raise SystemExit("Release metadata checks require Python 3.11 or newer") from exc


STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
RELEASE_HEADING = re.compile(r"^##[ \t]+\[([^]\r\n]+)\]([^\r\n]*)$", re.MULTILINE)
SECTION_HEADING = re.compile(r"^##(?:[ \t]+|$)", re.MULTILINE)
RELEASE_DATE = re.compile(r"[ \t]+[—–-][ \t]+([0-9]{4}-[0-9]{2}-[0-9]{2})[ \t]*")


def _read_toml(root: Path, filename: str) -> dict[str, Any]:
    with (root / filename).open("rb") as handle:
        return tomllib.load(handle)


def _manifest_version(root: Path, filename: str, table: str, name: str) -> str:
    package = _read_toml(root, filename).get(table)
    if not isinstance(package, dict) or package.get("name") != name:
        raise ValueError(f"{filename}: expected [{table}] package {name!r}")
    version = package.get("version")
    if not isinstance(version, str):
        raise ValueError(f"{filename}: package version must be a string")
    return version


def _lock_version(root: Path, filename: str, name: str) -> str:
    packages = _read_toml(root, filename).get("package")
    if not isinstance(packages, list):
        raise ValueError(f"{filename}: missing package entries")
    matches = [package for package in packages
               if isinstance(package, dict) and package.get("name") == name]
    if len(matches) != 1:
        raise ValueError(f"{filename}: expected exactly one package entry for {name!r}")
    version = matches[0].get("version")
    if not isinstance(version, str):
        raise ValueError(f"{filename}: package version must be a string")
    return version


def _release_notes(changelog: str, version: str) -> str:
    matches = [match for match in RELEASE_HEADING.finditer(changelog)
               if match.group(1) == version]
    if len(matches) != 1:
        raise ValueError(f"CHANGELOG.md: expected exactly one [{version}] section")
    heading = matches[0]
    dated = RELEASE_DATE.fullmatch(heading.group(2))
    if dated is None:
        raise ValueError(
            f"CHANGELOG.md: [{version}] must have a YYYY-MM-DD release date, not Unreleased"
        )
    try:
        date.fromisoformat(dated.group(1))
    except ValueError as exc:
        raise ValueError(f"CHANGELOG.md: invalid release date {dated.group(1)!r}") from exc
    next_heading = SECTION_HEADING.search(changelog, heading.end())
    end = next_heading.start() if next_heading else len(changelog)
    notes = changelog[heading.end():end].strip()
    if not notes:
        raise ValueError(f"CHANGELOG.md: [{version}] release notes are empty")
    return notes + "\n"


def check_release(root: Path, tag: str, github_ref: str | None = None) -> str:
    """Check one stable release and return its notes without the version heading."""
    if STABLE_TAG.fullmatch(tag) is None:
        raise ValueError("Release tag must be exactly vX.Y.Z with no leading zeros or suffix")
    if github_ref is not None and github_ref != f"refs/tags/{tag}":
        raise ValueError(f"GITHUB_REF must equal refs/tags/{tag}, got {github_ref!r}")
    version = tag[1:]
    versions = {
        "pyproject.toml": _manifest_version(root, "pyproject.toml", "project", "llm-input-hardening"),
        "Cargo.toml": _manifest_version(root, "Cargo.toml", "package", "llm_input_hardening"),
        "uv.lock": _lock_version(root, "uv.lock", "llm-input-hardening"),
        "Cargo.lock": _lock_version(root, "Cargo.lock", "llm_input_hardening"),
    }
    for filename, actual in versions.items():
        if actual != version:
            raise ValueError(f"{filename}: version {actual!r} does not match release {version!r}")
    return _release_notes((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Stable release tag, for example v2.0.0")
    parser.add_argument("--notes-out", type=Path, help="Write the validated changelog section body")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        notes = check_release(root, args.tag, os.environ.get("GITHUB_REF"))
        if args.notes_out is not None:
            args.notes_out.write_text(notes, encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Release metadata check failed: {exc}\n")
    print(f"Release metadata matches {args.tag}; dated release notes are ready")


if __name__ == "__main__":
    main()
