from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess

import pytest


pytest.importorskip("tomllib", reason="Release tooling runs on Python 3.11 or newer")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_dependencies.py"
helpers = runpy.run_path(str(SCRIPT))
locked_packages = helpers["locked_packages"]
audit_batches = helpers["audit_batches"]
validate_report = helpers["validate_report"]
audit_dependencies = helpers["audit_dependencies"]


@pytest.fixture
def dependency_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text('''
[project]
name = "sample-project"
version = "1.0.0"
dependencies = ["runtime>=1.0"]
[project.optional-dependencies]
security = ["extra>=2"]
[dependency-groups]
dev = ["pytest>=9", {include-group = "publish"}]
publish = ["twine>=6"]
[build-system]
requires = ["maturin>=1.7,<2"]
''', encoding="utf-8")
    records = [("sample-project", "1.0.0"), ("runtime", "1.0.0"), ("extra", "2.0"),
               ("pytest", "9.0"), ("twine", "6.0"), ("maturin", "1.7"),
               ("cryptography", "46.0.0"), ("cryptography", "47.0.0")]
    lock = "version = 1\n"
    for name, version in records:
        source = '{ editable = "." }' if name == "sample-project" else '{ registry = "https://pypi.org/simple" }'
        lock += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {source}\n'
        if name == "cryptography":
            lock += '''resolution-markers = ["sys_platform == 'win32'"]\n'''
    (tmp_path / "uv.lock").write_text(lock, encoding="utf-8")
    return tmp_path


def report_for(pins: list[tuple[str, str]]) -> dict:
    return {"dependencies": [{"name": name, "version": version, "vulns": []}
                             for name, version in pins], "fixes": []}


def test_universal_audit_includes_foreign_platform_and_every_version(dependency_repo: Path) -> None:
    pins = locked_packages(dependency_repo)
    assert len(pins) == 7
    assert ("cryptography", "46.0.0") in pins
    assert ("cryptography", "47.0.0") in pins
    batches = audit_batches(pins)
    assert len(batches) == 2
    assert sorted(pin for batch in batches for pin in batch) == pins
    assert all(len({name for name, _ in batch}) == len(batch) for batch in batches)


@pytest.mark.parametrize("omitted", ["runtime", "extra", "pytest", "twine", "maturin"])
def test_scope_cannot_drop_runtime_extras_dev_or_build_tools(dependency_repo: Path, omitted: str) -> None:
    path = dependency_repo / "uv.lock"
    sections = path.read_text().split("[[package]]")
    path.write_text("[[package]]".join(section for section in sections
                                    if f'name = "{omitted}"' not in section))
    with pytest.raises(ValueError, match="omitted declared runtime/dev/build"):
        locked_packages(dependency_repo)


@pytest.mark.parametrize("source", ['{registry = "https://private.example/simple"}',
                                  '{git = "https://github.com/example/fork"}',
                                  '{editable = "../local"}', '{}'])
def test_cannot_misrepresent_non_pypi_sources_as_pypi(dependency_repo: Path, source: str) -> None:
    path = dependency_repo / "uv.lock"
    path.write_text(path.read_text().replace('{ registry = "https://pypi.org/simple" }', source, 1))
    with pytest.raises(ValueError, match="non-PyPI package source"):
        locked_packages(dependency_repo)


@pytest.mark.parametrize("mutation", ["duplicate", "missing-root", "old-root", "empty", "schema", "unpinned"])
def test_invalid_lock_cannot_pass(dependency_repo: Path, mutation: str) -> None:
    path = dependency_repo / "uv.lock"
    contents = path.read_text()
    if mutation == "duplicate":
        contents += "\n[[package]]" + contents.split("[[package]]")[-1]
    elif mutation == "missing-root":
        contents = contents.replace('name = "sample-project"', 'name = "different-project"')
    elif mutation == "old-root":
        contents = contents.replace('version = "1.0.0"', 'version = "0.9.0"', 1)
    elif mutation == "empty":
        contents = "version = 1\n"
    elif mutation == "schema":
        contents = contents.replace("version = 1\n", "version = 2\n", 1)
    else:
        contents = contents.replace('version = "47.0.0"', 'version = ">=47"')
    path.write_text(contents)
    with pytest.raises(ValueError):
        locked_packages(dependency_repo)


@pytest.mark.parametrize("mutation", ["missing", "skipped", "wrong-version", "duplicate", "missing-vulns", "vulnerable"])
def test_success_report_must_prove_complete_clean_scope(mutation: str) -> None:
    pins = [("cryptography", "47.0.0"), ("pytest", "9.0.3")]
    report = report_for(pins)
    if mutation == "missing":
        report["dependencies"].pop()
    elif mutation == "skipped":
        report["dependencies"][0] = {"name": "cryptography", "skip_reason": "Not found on PyPI"}
    elif mutation == "wrong-version":
        report["dependencies"][0]["version"] = "99.0.0"
    elif mutation == "duplicate":
        report["dependencies"].append(report["dependencies"][0])
    elif mutation == "missing-vulns":
        report["dependencies"][0].pop("vulns")
    else:
        report["dependencies"][0]["vulns"] = [{"id": "GHSA-example", "fix_versions": ["47.0.1"]}]
    with pytest.raises(ValueError):
        validate_report(report, pins)


def test_clean_report_accepts_normalized_names() -> None:
    validate_report(report_for([("My_Package", "1.0")]), [("my-package", "1.0")])


def test_export_only_is_explicit_and_has_no_platform_markers(
    dependency_repo: Path, capsys: pytest.CaptureFixture,
) -> None:
    output = dependency_repo / "audit"
    assert audit_dependencies(dependency_repo, output, export_only=True) == 7
    assert "no audit performed" in capsys.readouterr().out
    contents = "".join(path.read_text() for path in output.glob("requirements-*.txt"))
    assert "cryptography==46.0.0\n" in contents
    assert "cryptography==47.0.0\n" in contents
    assert "sys_platform" not in contents
    assert not list(output.glob("report-*.json"))


def test_audit_process_failure_cannot_reuse_a_stale_clean_report(
    dependency_repo: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = dependency_repo / "audit"
    output.mkdir()
    (output / "report-1.json").write_text(json.dumps(report_for(locked_packages(dependency_repo))))
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1))
    with pytest.raises(ValueError, match="did not produce a report"):
        audit_dependencies(dependency_repo, output)


def test_real_pip_audit_collector_keeps_all_exported_pins(dependency_repo: Path) -> None:
    # This exercises the upstream requirements parser when pip-audit is installed;
    # no network or package installation is needed to prove collection coverage.
    requirement_source = pytest.importorskip("pip_audit._dependency_source.requirement")
    output = dependency_repo / "audit"
    audit_dependencies(dependency_repo, output, export_only=True)
    observed = set()
    for path in output.glob("requirements-*.txt"):
        source = requirement_source.RequirementSource([path], no_deps=True, disable_pip=True)
        observed.update((item.canonical_name, str(item.version)) for item in source.collect())
    assert observed == set(locked_packages(dependency_repo))
