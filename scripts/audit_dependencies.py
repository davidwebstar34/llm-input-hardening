"""Audit every PyPI name/version in uv.lock, including foreign-platform tooling.

Run with ``uv run --locked python scripts/audit_dependencies.py`` (Python 3.11+).
Requirements files are audit inventories, not installable environments: markers
are intentionally removed, and alternative versions are audited in separate
batches because pip-audit rejects conflicting pins in a single invocation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


Pin = tuple[str, str]
PYPI_SOURCE = {"registry": "https://pypi.org/simple"}


def required_packages(manifest: dict[str, Any]) -> set[str]:
    """Include every declared runtime extra, dependency group and build tool."""
    project = manifest["project"]
    if {"dependencies", "optional-dependencies"} & set(project.get("dynamic", [])):
        raise ValueError("Dynamic dependencies cannot be checked against the lock audit scope")
    requirements = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)
    groups = manifest.get("dependency-groups", {})
    for entries in groups.values():
        for entry in entries:
            if isinstance(entry, str):
                requirements.append(entry)
            elif not (isinstance(entry, dict) and set(entry) == {"include-group"}
                      and entry["include-group"] in groups):
                raise ValueError(f"Unsupported dependency-group entry: {entry!r}")
    requirements.extend(manifest.get("build-system", {}).get("requires", []))
    names = set()
    for value in requirements:
        requirement = Requirement(value)
        if requirement.url:
            raise ValueError(f"Cannot audit a direct URL dependency against PyPI: {requirement.name}")
        names.add(canonicalize_name(requirement.name))
    return names


def locked_packages(repo: Path) -> list[Pin]:
    """Fail closed on non-PyPI sources, incomplete locks or omitted direct deps."""
    manifest = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((repo / "uv.lock").read_text(encoding="utf-8"))
    if lock.get("version") != 1:
        raise ValueError("Unsupported uv.lock format; expected lock version 1")
    project = manifest["project"]
    project_name = canonicalize_name(project["name"], validate=True)
    pins: set[Pin] = set()
    own_entries = 0
    for package in lock.get("package", []):
        name = canonicalize_name(package["name"], validate=True)
        version = str(Version(package["version"]))
        source = package.get("source")
        if name == project_name:
            own_entries += 1
            if source != {"editable": "."} or version != str(Version(project["version"])):
                raise ValueError("The project lock entry must match this editable project and version")
            continue
        if source != PYPI_SOURCE:
            raise ValueError(f"Cannot audit non-PyPI package source for {name}: {source!r}")
        pin = (name, version)
        if pin in pins:
            raise ValueError(f"Duplicate lock entry: {name}=={version}")
        pins.add(pin)
    if own_entries != 1 or not pins:
        raise ValueError("Lock must contain exactly one project entry and nonempty dependencies")
    missing = required_packages(manifest) - {name for name, _ in pins}
    if missing:
        raise ValueError(f"Lock audit omitted declared runtime/dev/build dependencies: {sorted(missing)}")
    return sorted(pins)


def audit_batches(pins: list[Pin]) -> list[list[Pin]]:
    """Keep every version while avoiding conflicting pins within each batch."""
    versions: dict[str, list[str]] = {}
    for name, version in sorted(pins):
        versions.setdefault(name, []).append(version)
    return [
        [(name, values[index]) for name, values in versions.items() if index < len(values)]
        for index in range(max(map(len, versions.values()), default=0))
    ]


def validate_report(report: dict[str, Any], expected: list[Pin]) -> None:
    """A successful exit alone must never hide skipped or unaudited packages."""
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit returned no dependency inventory")
    observed: set[Pin] = set()
    findings = []
    for dependency in dependencies:
        if "skip_reason" in dependency:
            raise ValueError(f"pip-audit skipped {dependency.get('name')}: {dependency['skip_reason']}")
        pin = (canonicalize_name(dependency["name"], validate=True),
               str(Version(dependency["version"])))
        if pin in observed:
            raise ValueError(f"pip-audit returned a duplicate package: {pin}")
        observed.add(pin)
        vulnerabilities = dependency.get("vulns")
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"pip-audit omitted vulnerability results for {pin}")
        for vulnerability in vulnerabilities:
            findings.append(f"{pin[0]}=={pin[1]}: {vulnerability['id']} "
                            f"(fixed: {', '.join(vulnerability.get('fix_versions', [])) or 'unavailable'})")
    if observed != set(expected):
        raise ValueError(f"pip-audit scope mismatch: missing={sorted(set(expected) - observed)}, "
                         f"unexpected={sorted(observed - set(expected))}")
    if findings:
        raise ValueError("Known dependency vulnerabilities:\n" + "\n".join(findings))


def audit_dependencies(repo: Path, output_dir: Path, *, export_only: bool = False) -> int:
    pins = locked_packages(repo)
    batches = audit_batches(pins)
    output_dir.mkdir(parents=True, exist_ok=True)
    for index, batch in enumerate(batches, start=1):
        requirements = output_dir / f"requirements-{index}.txt"
        requirements.write_text("# Audit inventory; do not install (platform markers removed).\n"
                                + "".join(f"{name}=={version}\n" for name, version in batch),
                                encoding="utf-8")
        if export_only:
            continue
        report_path = output_dir / f"report-{index}.json"
        report_path.unlink(missing_ok=True)
        print(f"Auditing uv.lock batch {index}/{len(batches)} ({len(batch)} pins) against PyPI", flush=True)
        result = subprocess.run([
            sys.executable, "-m", "pip_audit", "--strict", "--no-deps", "--disable-pip",
            "--vulnerability-service", "pypi", "--progress-spinner", "off", "--timeout", "30",
            "--format", "json", "--output", str(report_path), "-r", str(requirements),
        ], check=False, timeout=600)
        if not report_path.is_file():
            raise ValueError(f"pip-audit did not produce a report (exit {result.returncode})")
        validate_report(json.loads(report_path.read_text(encoding="utf-8")), batch)
        if result.returncode:
            raise ValueError(f"pip-audit failed with exit {result.returncode}; see {report_path}")
    if export_only:
        print(f"Exported {len(pins)} locked package versions in {len(batches)} batches; no audit performed.")
    else:
        print(f"Audited all {len(pins)} locked package versions, including every platform, extra and dev/build tool.")
    return len(pins)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, default=Path(".tmp/dependency-audit"))
    parser.add_argument("--export-only", action="store_true", help="Write inventories without claiming an audit")
    args = parser.parse_args()
    try:
        audit_dependencies(args.repo.resolve(), args.output_dir.resolve(), export_only=args.export_only)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"Dependency audit failed: {exc}") from exc


if __name__ == "__main__":
    main()
