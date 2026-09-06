from __future__ import annotations

import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest


pytest.importorskip("tomllib", reason="Release tooling runs on Python 3.11 or newer")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_release.py"
check_release = runpy.run_path(str(SCRIPT))["check_release"]


@pytest.fixture
def release_repo(tmp_path: Path) -> Path:
    files = {
        "pyproject.toml": '[project]\nname = "llm-input-hardening"\nversion = "2.0.0"\n',
        "Cargo.toml": '[package]\nname = "llm_input_hardening"\nversion = "2.0.0"\n',
        "uv.lock": '[[package]]\nname = "llm-input-hardening"\nversion = "2.0.0"\n',
        "Cargo.lock": '[[package]]\nname = "llm_input_hardening"\nversion = "2.0.0"\n',
        "CHANGELOG.md": (
            "# Changelog\n\n## [2.1.0] — Unreleased\n\nFuture work.\n\n"
            "## [2.0.0] — 2026-09-06\n\n### Security\n\n- Harden input.\n\n"
            "## [1.3.0]\n\nOld changes.\n"
        ),
    }
    for filename, content in files.items():
        (tmp_path / filename).write_text(content, encoding="utf-8")
    return tmp_path


def test_matching_release_extracts_only_target_notes(release_repo: Path) -> None:
    assert check_release(release_repo, "v2.0.0", "refs/tags/v2.0.0") == (
        "### Security\n\n- Harden input.\n"
    )


@pytest.mark.parametrize("tag", [
    "2.0.0", "v02.0.0", "v2.00.0", "v2.0.01", "v2.0", "v2.0.0rc1",
    "v2.0.0-rc.1", "v2.0.0+build", "v2.0.0\n", " v2.0.0", "v٢.0.0",
])
def test_rejects_noncanonical_or_unstable_tag(release_repo: Path, tag: str) -> None:
    with pytest.raises(ValueError, match="Release tag must be exactly"):
        check_release(release_repo, tag)


@pytest.mark.parametrize("ref", ["", "refs/heads/main", "refs/tags/v1.3.0", "v2.0.0"])
def test_github_ref_must_be_the_same_tag(release_repo: Path, ref: str) -> None:
    with pytest.raises(ValueError, match="GITHUB_REF must equal"):
        check_release(release_repo, "v2.0.0", ref)


@pytest.mark.parametrize("filename", ["pyproject.toml", "Cargo.toml", "uv.lock", "Cargo.lock"])
def test_every_version_must_match(release_repo: Path, filename: str) -> None:
    path = release_repo / filename
    path.write_text(path.read_text().replace('"2.0.0"', '"1.3.0"'), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match release"):
        check_release(release_repo, "v2.0.0")


@pytest.mark.parametrize("filename", ["uv.lock", "Cargo.lock"])
@pytest.mark.parametrize("duplicate", [False, True])
def test_lockfile_requires_unique_own_entry(
    release_repo: Path, filename: str, duplicate: bool,
) -> None:
    path = release_repo / filename
    content = path.read_text()
    path.write_text(content + "\n" + content if duplicate else "version = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="package entr"):
        check_release(release_repo, "v2.0.0")


@pytest.mark.parametrize("heading", [
    "## [2.0.0] — Unreleased", "## [2.0.0]", "## [2.0.0] — 2026-9-6",
    "## [2.0.0] — 2026-02-30", "## [2.0.0] — 2025-02-29",
])
def test_release_requires_valid_iso_date(release_repo: Path, heading: str) -> None:
    path = release_repo / "CHANGELOG.md"
    path.write_text(heading + "\n\nRelease notes.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="release date"):
        check_release(release_repo, "v2.0.0")


@pytest.mark.parametrize("content", [
    "## [1.3.0] — 2026-09-06\n\nOld changes.\n",
    "## [2.0.0] — 2026-09-06\n\nOne.\n\n## [2.0.0] — Unreleased\n\nTwo.\n",
])
def test_release_section_must_exist_once(release_repo: Path, content: str) -> None:
    (release_repo / "CHANGELOG.md").write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        check_release(release_repo, "v2.0.0")


def test_empty_notes_do_not_swallow_following_nonrelease_section(release_repo: Path) -> None:
    (release_repo / "CHANGELOG.md").write_text(
        "## [2.0.0] — 2026-09-06\n\n## Other information\n\nNot release notes.\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="release notes are empty"):
        check_release(release_repo, "v2.0.0")


def test_cli_writes_notes_only_after_successful_validation(release_repo: Path) -> None:
    scripts = release_repo / "scripts"
    scripts.mkdir()
    script = scripts / SCRIPT.name
    shutil.copyfile(SCRIPT, script)
    notes = release_repo / "release-notes.md"
    env = {key: value for key, value in os.environ.items() if key != "GITHUB_REF"}
    command = [sys.executable, str(script), "--tag", "v2.0.0", "--notes-out", str(notes)]
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert notes.read_text() == "### Security\n\n- Harden input.\n"
    notes.unlink()
    result = subprocess.run(
        command, env={**env, "GITHUB_REF": "refs/heads/main"},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 1
    assert "GITHUB_REF must equal" in result.stderr
    assert "Traceback" not in result.stderr
    assert not notes.exists()
