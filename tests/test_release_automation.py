"""Release tooling safety gates; no real registry writes or workflow dispatches."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
from urllib.error import HTTPError

import pytest

pytest.importorskip("tomllib", reason="Release tooling requires Python 3.11+")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release.py"
spec = importlib.util.spec_from_file_location("release_automation", SCRIPT)
assert spec is not None and spec.loader is not None
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    files = {
        "pyproject.toml": '[project]\nname = "llm-input-hardening"\nversion = "2.0.0"\n',
        "Cargo.toml": '[package]\nname = "llm_input_hardening"\nversion = "2.0.0"\n',
        "uv.lock": '[[package]]\nname = "llm-input-hardening"\nversion = "2.0.0"\n',
        "Cargo.lock": '[[package]]\nname = "llm_input_hardening"\nversion = "2.0.0"\n',
        "CHANGELOG.md": '# Changelog\n\n## [2.0.0] — 2026-09-06\n\nOld notes.\n',
    }
    for filename, content in files.items():
        (tmp_path / filename).write_text(content, encoding="utf-8")
    return tmp_path


def test_prepare_preserves_dependencies_and_old_notes(repo: Path) -> None:
    with (repo / "uv.lock").open("a") as stream:
        stream.write('\n[[package]]\nname = "other"\nversion = "2.0.0"\n')
    before = {name: (repo / name).read_bytes() for name in release.RELEASE_FILES}
    rendered = release.prepare_files(repo, "2.0.1", "### Security\n\n- Fix dependency alerts.")
    assert set(rendered) == set(release.RELEASE_FILES)
    assert 'name = "other"\nversion = "2.0.0"' in rendered["uv.lock"]
    assert rendered["CHANGELOG.md"].index("[2.0.1]") < rendered["CHANGELOG.md"].index("[2.0.0]")
    assert rendered["CHANGELOG.md"].endswith("Old notes.\n")
    assert {name: (repo / name).read_bytes() for name in release.RELEASE_FILES} == before


@pytest.mark.parametrize("version", ["2.0.0", "1.9.9"])
def test_new_release_must_increase_version(repo: Path, version: str) -> None:
    with pytest.raises(release.ReleaseError, match="greater than"):
        release.prepare_files(repo, version, "Release notes")


@pytest.mark.parametrize("notes", ["", "  ", "## [2.0.1]\nNotes", "# Release\nNotes"])
def test_notes_cannot_inject_another_changelog_section(repo: Path, notes: str) -> None:
    with pytest.raises(release.ReleaseError, match="Notes must"):
        release.prepare_files(repo, "2.0.1", notes)


def test_mismatched_current_versions_fail_without_edits(repo: Path) -> None:
    path = repo / "Cargo.lock"
    path.write_text(path.read_text(encoding="utf-8").replace('"2.0.0"', '"1.0.0"'), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(release.ReleaseError, match="disagree"):
        release.prepare_files(repo, "2.0.1", "Notes")
    assert path.read_bytes() == before


@pytest.mark.parametrize("version", ["2.01.0", "2.0.0rc1", "-1.0.0", "2.0.0\n", "$(whoami)"])
def test_invalid_versions_rejected(version: str) -> None:
    with pytest.raises(Exception, match="stable X.Y.Z"):
        release.stable_version(version)


class FakeRelease(release.Release):
    def __init__(self, root: Path, version: str = "2.0.0") -> None:
        super().__init__(root, version)
        self.sha = "a" * 40
        self.calls: list[tuple[str, ...]] = []
        self.branch = "main"
        self.dirty = ""
        self.remote = self.sha
        self.tagged: str | None = None
        self.existing: dict[str, list[dict]] = {}
        self.failed_dispatch = False
        self.workflows: list[str] = []
        self.push_origin = f"https://github.com/{release.REPOSITORY}.git"

    def command(self, *args: str, timeout: int = 120) -> str:
        self.calls.append(args)
        if args == ("git", "rev-parse", "--show-toplevel"):
            return str(self.root)
        if args == ("git", "branch", "--show-current"):
            return self.branch
        if args[:3] == ("git", "status", "--porcelain"):
            return self.dirty
        if args[:3] == ("git", "remote", "get-url"):
            return self.push_origin if "--push" in args else f"https://github.com/{release.REPOSITORY}.git"
        if args == ("git", "rev-parse", "HEAD"):
            return self.sha
        if args[:3] == ("git", "rev-parse", "--git-path"):
            return str(self.root / args[3])
        if args[:3] == ("gh", "workflow", "run"):
            if self.failed_dispatch:
                raise release.ReleaseError("connection lost after dispatch")
            return ""
        raise AssertionError(f"Unexpected command: {args}")

    def require_unpublished(self) -> None:
        pass

    def gh_json(self, *args: str):
        assert args[:2] == ("api", f"repos/{release.REPOSITORY}")
        return {"full_name": release.REPOSITORY, "permissions": {"push": True}}

    def remote_refs(self) -> dict[str, str]:
        refs = {"refs/heads/main": self.remote}
        if self.tagged:
            refs[f"refs/tags/{self.tag}"] = self.tagged
        return refs

    def runs(self, workflow: str, branch: str, event: str) -> list[dict]:
        return [row for row in self.existing.get(workflow, []) if row["event"] == event]

    def wait_run(self, workflow: str, branch: str, event: str) -> dict:
        self.workflows.append(workflow)
        return {"databaseId": 42, "event": event}


@pytest.mark.parametrize("field,value,message", [
    ("branch", "feature", "Switch to main"),
    ("dirty", "?? notes.md", "must be clean"),
    ("push_origin", "https://github.com/attacker/fork.git", "one fetch/push URL"),
    ("remote", "b" * 40, "Local HEAD and remote main differ"),
    ("tagged", "a" * 40, "already exists"),
])
def test_preflight_rejects_unsafe_checkout(repo: Path, field: str, value: str, message: str) -> None:
    driver = FakeRelease(repo)
    setattr(driver, field, value)
    with pytest.raises(release.ReleaseError, match=message):
        driver.preflight(False)
    assert not any(args[:2] == ("git", "push") for args in driver.calls)


def test_preflight_rejects_existing_pypi_version(repo: Path, monkeypatch) -> None:
    driver = FakeRelease(repo)
    monkeypatch.setattr(release, "fetch_release", lambda version: {"info": {"version": version}})
    with pytest.raises(release.ReleaseError, match="already exists on PyPI"):
        release.Release.require_unpublished(driver)


def test_pypi_authorization_or_network_errors_are_not_treated_as_absent(repo: Path, monkeypatch) -> None:
    def fetch(version: str):
        raise HTTPError("https://pypi.org", 503, "Unavailable", {}, None)
    monkeypatch.setattr(release, "fetch_release", fetch)
    with pytest.raises(HTTPError):
        release.Release.require_unpublished(FakeRelease(repo))


def test_uncertain_dispatch_is_not_sent_again_on_resume(repo: Path) -> None:
    driver = FakeRelease(repo)
    driver.failed_dispatch = True
    with pytest.raises(release.ReleaseError, match="connection lost"):
        driver.start_or_resume()
    driver.failed_dispatch = False
    with pytest.raises(release.ReleaseError, match="previous dispatch was attempted"):
        driver.start_or_resume()
    dispatches = [args for args in driver.calls if args[:3] == ("gh", "workflow", "run")]
    assert len(dispatches) == 1
    assert f"expected_sha={driver.sha}" in dispatches[0]


def test_completed_release_resume_never_dispatches_or_rebuilds(repo: Path) -> None:
    driver = FakeRelease(repo)
    driver.tagged = driver.sha
    driver.existing["release.yml"] = [{"databaseId": 10, "event": "workflow_dispatch"}]
    driver.start_or_resume()
    assert not any(args[:3] == ("gh", "workflow", "run") for args in driver.calls)
    assert driver.workflows == ["ci.yml", "release.yml"]


def test_main_advancing_during_ci_stops_before_tagging(repo: Path) -> None:
    driver = FakeRelease(repo)
    driver.remote = "b" * 40
    with pytest.raises(release.ReleaseError, match="main changed during CI"):
        driver.start_or_resume()
    assert not any(args[:3] == ("gh", "workflow", "run") for args in driver.calls)


def test_failed_workflow_stops_without_rerun(repo: Path, monkeypatch) -> None:
    driver = FakeRelease(repo)
    driver.existing["ci.yml"] = [{"databaseId": 11, "event": "push", "status": "completed",
                                  "conclusion": "failure", "url": "https://github.com/run/11"}]
    with pytest.raises(release.ReleaseError, match="does not rerun"):
        release.Release.wait_run(driver, "ci.yml", "main", "push")
    assert driver.calls == []


def test_dry_run_never_mutates_checkout_or_dispatches(repo: Path, tmp_path: Path, monkeypatch) -> None:
    scripts = repo / "scripts"
    scripts.mkdir()
    monkeypatch.setattr(release, "__file__", str(scripts / "release.py"))
    monkeypatch.setattr(release.Release, "preflight", lambda self, resume: None)
    def unexpected(*args, **kwargs):
        raise AssertionError("Dry-run must not execute mutation commands")
    monkeypatch.setattr(release.Release, "command", unexpected)
    notes = tmp_path / "notes.txt"
    notes.write_text("- Fix dependencies.\n", encoding="utf-8")
    before = {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()}
    assert release.main(["2.0.1", "--notes-file", str(notes), "--dry-run"]) == 0
    assert {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()} == before


def test_wrapper_forwards_arguments_without_evaluating_them(tmp_path: Path) -> None:
    # The old wrapper staged every file and bypassed the CI gate.
    content = (SCRIPT.parent / "release.sh").read_text(encoding="utf-8")
    bash = shutil.which("bash")
    if os.name == "nt":
        # Windows' PATH may resolve bash to WSL, whose Linux image is optional.
        git = shutil.which("git")
        assert git is not None, "Git is required for release tooling tests"
        bash = next(
            (str(parent / "bin" / "bash.exe") for parent in Path(git).parents
             if (parent / "bin" / "bash.exe").is_file()),
            None,
        )
    assert bash is not None, "Bash (Git Bash on Windows) is required"
    subprocess.run([bash, "-n", "release.sh"], cwd=SCRIPT.parent, check=True)
    assert '"$@"' in content
    assert "git add" not in content and "git tag" not in content


def test_resume_cannot_rebuild_a_version_published_without_a_known_run(repo: Path, monkeypatch) -> None:
    driver = FakeRelease(repo)
    monkeypatch.setattr(release, "fetch_release", lambda version: {"info": {"version": version}})
    monkeypatch.setattr(driver, "require_unpublished", lambda: release.Release.require_unpublished(driver))
    with pytest.raises(release.ReleaseError, match="already exists on PyPI"):
        driver.start_or_resume()
    assert not any(args[:3] == ("gh", "workflow", "run") for args in driver.calls)
    assert not (repo / "release-2.0.0.json").exists()


def test_matching_unreleased_notes_move_into_dated_section_without_duplication(repo: Path) -> None:
    path = repo / "CHANGELOG.md"
    path.write_text(path.read_text(encoding="utf-8").replace("# Changelog\n\n", "# Changelog\n\n## [Unreleased]\n\n- Fix alerts.\n\n"), encoding="utf-8")
    result = release.prepare_files(repo, "2.0.1", "- Fix alerts.")["CHANGELOG.md"]
    assert result.count("- Fix alerts.") == 1
    assert "## [Unreleased]\n\n## [2.0.1]" in result
    assert "Old notes." in result


def test_different_unreleased_notes_are_never_discarded(repo: Path) -> None:
    path = repo / "CHANGELOG.md"
    path.write_text(path.read_text(encoding="utf-8").replace("# Changelog\n\n", "# Changelog\n\n## [Unreleased]\n\nOther pending changes.\n\n"), encoding="utf-8")
    with pytest.raises(release.ReleaseError, match="Unreleased notes differ"):
        release.prepare_files(repo, "2.0.1", "- Fix alerts.")
    assert "Other pending changes." in path.read_text(encoding="utf-8")


def test_live_preparation_commits_exactly_release_files_in_a_real_git_repo(repo: Path, monkeypatch) -> None:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo, text=True, encoding="utf-8",
                              capture_output=True, check=True).stdout.strip()
    git("init", "-b", "main")
    git("config", "user.name", "Release Test")
    git("config", "user.email", "test@example.invalid")
    git("add", "--", *release.RELEASE_FILES)
    git("commit", "-m", "Initial fixture")
    original_sha = git("rev-parse", "HEAD")
    scripts = repo / "scripts"
    scripts.mkdir()
    notes = repo.parent / "notes.md"
    notes.write_text("### Security\n\n- Fix alerts.\n", encoding="utf-8")
    monkeypatch.setattr(release, "__file__", str(scripts / "release.py"))
    observed = []

    class LocalRelease(release.Release):
        def preflight(self, resume: bool) -> None:
            assert not resume
            assert git("status", "--porcelain") == ""
            self.sha = original_sha

        def remote_refs(self) -> dict[str, str]:
            return {"refs/heads/main": original_sha}

        def command(self, *args: str, timeout: int = 120) -> str:
            if args[:2] == ("git", "push"):
                observed.append(args)
                return ""
            return super().command(*args, timeout=timeout)

        def start_or_resume(self) -> dict:
            assert self.sha == git("rev-parse", "HEAD")
            assert git("log", "-1", "--format=%s") == "Release 2.0.1"
            return {"databaseId": 42}

        def verify(self, run: dict) -> None:
            observed.append(("verify", str(run["databaseId"])))

    monkeypatch.setattr(release, "Release", LocalRelease)
    assert release.main(["2.0.1", "--notes-file", str(notes)]) == 0
    assert git("status", "--porcelain") == ""
    assert set(git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()) == set(release.RELEASE_FILES)
    assert observed == [("git", "push", "origin", git("rev-parse", "HEAD") + ":refs/heads/main"), ("verify", "42")]
