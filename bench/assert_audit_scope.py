"""Reject dependency audit exports that accidentally omit supported runtime extras."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def assert_audit_scope(path: Path, required: list[str]) -> set[str]:
    packages = {_normalize(match.group(1)) for line in path.read_text(encoding="utf-8").splitlines()
                if (match := re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^]]+\])?==", line))}
    if not packages:
        raise ValueError("Dependency audit export is empty or has no pinned requirements")
    missing = {_normalize(name) for name in required} - packages
    if missing:
        raise ValueError(f"Dependency audit omitted required runtime extras: {sorted(missing)}")
    return packages


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--require", action="append", required=True)
    args = parser.parse_args()
    try:
        packages = assert_audit_scope(args.requirements, args.require)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Dependency audit scope includes {len(packages)} pinned packages and all required runtime extras")


if __name__ == "__main__":
    main()
