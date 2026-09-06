"""Prepare a stable release, wait for CI, publish, and verify the result."""
from __future__ import annotations

import argparse
from datetime import date
import difflib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError

# Also support direct execution from outside the checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.check_release import (  # noqa: E402
    RELEASE_HEADING,
    SECTION_HEADING,
    STABLE_TAG,
    _lock_version,
    _manifest_version,
    check_release,
)
from scripts.verify_pypi import fetch_release, local_digests, verify_payload  # noqa: E402

REPOSITORY = "davidwebstar34/llm-input-hardening"
RELEASE_FILES = ("pyproject.toml", "Cargo.toml", "uv.lock", "Cargo.lock", "CHANGELOG.md")
RUN_FIELDS = "databaseId,headSha,headBranch,event,status,conclusion,url"


class ReleaseError(ValueError):
    """A release gate failed; no subsequent publication step may run."""


def stable_version(value: str) -> str:
    version = value.removeprefix("v")
    if STABLE_TAG.fullmatch("v" + version) is None:
        raise argparse.ArgumentTypeError("version must be stable X.Y.Z, without leading zeros")
    return version


def prepare_files(root: Path, version: str, notes: str) -> dict[str, str]:
    """Render and validate every edit in memory before changing the checkout."""
    notes = notes.strip()
    if not notes or re.search(r"^#{1,2}(?:\s|$)", notes, re.MULTILINE):
        raise ReleaseError("Notes must be nonempty; use ### subheadings, without a release heading")
    current = _manifest_version(root, "pyproject.toml", "project", "llm-input-hardening")
    if STABLE_TAG.fullmatch("v" + current) is None:
        raise ReleaseError("The current package version must be a stable X.Y.Z version")
    versions = [
        _manifest_version(root, "Cargo.toml", "package", "llm_input_hardening"),
        _lock_version(root, "uv.lock", "llm-input-hardening"),
        _lock_version(root, "Cargo.lock", "llm_input_hardening"),
    ]
    if any(item != current for item in versions):
        raise ReleaseError("The four current manifest/lockfile versions disagree")
    if tuple(map(int, version.split("."))) <= tuple(map(int, current.split("."))):
        raise ReleaseError(f"New version must be greater than {current}; use --resume for an existing release")
    rendered: dict[str, str] = {}
    for filename, table, name in (
        ("pyproject.toml", "project", None),
        ("Cargo.toml", "package", None),
        ("uv.lock", "package", "llm-input-hardening"),
        ("Cargo.lock", "package", "llm_input_hardening"),
    ):
        content = (root / filename).read_text(encoding="utf-8")
        if name is None:
            pattern = rf'(\[{table}\][^\[]*?^version\s*=\s*)"{re.escape(current)}"'
        else:
            pattern = (
                rf'(\[\[package\]\][^\[]*?^name\s*=\s*"{name}"[^\[]*?'
                rf'^version\s*=\s*)"{re.escape(current)}"'
            )
        updated, count = re.subn(pattern, lambda match: match[1] + f'"{version}"',
                                 content, flags=re.MULTILINE)
        if count != 1:
            raise ReleaseError(f"Cannot identify exactly one version field in {filename}")
        rendered[filename] = updated
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if any(match[1] == version for match in RELEASE_HEADING.finditer(changelog)):
        raise ReleaseError(f"CHANGELOG.md already contains [{version}]; reconcile it before releasing")
    first_section = SECTION_HEADING.search(changelog)
    offset = first_section.start() if first_section else len(changelog)
    unreleased = [match for match in RELEASE_HEADING.finditer(changelog)
                  if match[1].casefold() == "unreleased"]
    if len(unreleased) > 1:
        raise ReleaseError("CHANGELOG.md has duplicate Unreleased sections")
    prefix, suffix = changelog[:offset].rstrip() + "\n\n", changelog[offset:]
    if unreleased:
        heading = unreleased[0]
        following = SECTION_HEADING.search(changelog, heading.end())
        end = following.start() if following else len(changelog)
        pending = changelog[heading.end():end].strip()
        if pending and pending != notes:
            raise ReleaseError("Unreleased notes differ from --notes-file; use those notes or reconcile the changelog first")
        # Move matching pending notes into the dated release, retaining an empty
        # Unreleased heading. Never silently discard other pending changes.
        prefix = changelog[:heading.end()].rstrip() + "\n\n"
        suffix = changelog[end:]
    entry = f"## [{version}] — {date.today().isoformat()}\n\n{notes}\n\n"
    rendered["CHANGELOG.md"] = prefix + entry + suffix
    with tempfile.TemporaryDirectory(prefix="release-metadata-") as directory:
        staging = Path(directory)
        for filename, content in rendered.items():
            (staging / filename).write_text(content, encoding="utf-8")
        check_release(staging, "v" + version)
    return rendered


class Release:
    def __init__(self, root: Path, version: str, timeout: int = 7200) -> None:
        self.root = root
        self.version = version
        self.tag = "v" + version
        self.timeout = timeout
        self.sha = ""

    def command(self, *args: str, timeout: int = 120) -> str:
        print("+ " + shlex.join(args), flush=True)
        result = subprocess.run(args, cwd=self.root, text=True, encoding="utf-8", capture_output=True,
                                timeout=timeout, check=False)
        if result.returncode:
            raise ReleaseError(f"{args[0]} failed ({result.returncode}): "
                               f"{result.stderr.strip() or result.stdout.strip()}")
        return result.stdout.strip()

    def gh_json(self, *args: str) -> Any:
        return json.loads(self.command("gh", *args))

    def remote_refs(self) -> dict[str, str]:
        output = self.command("git", "ls-remote", "origin", "refs/heads/main",
                              f"refs/tags/{self.tag}", f"refs/tags/{self.tag}^{{}}")
        return {line.split()[1]: line.split()[0] for line in output.splitlines()}

    def tag_commit(self, refs: dict[str, str]) -> str | None:
        return refs.get(f"refs/tags/{self.tag}^{{}}", refs.get(f"refs/tags/{self.tag}"))

    def preflight(self, resume: bool) -> None:
        if Path(self.command("git", "rev-parse", "--show-toplevel")).resolve() != self.root:
            raise ReleaseError("Run against the library's own Git repository")
        if self.command("git", "branch", "--show-current") != "main":
            raise ReleaseError("Switch to main before releasing")
        if self.command("git", "status", "--porcelain", "--untracked-files=all"):
            raise ReleaseError("The checkout must be clean, including untracked files; keep notes outside it")
        allowed = {f"https://github.com/{REPOSITORY}.git", f"https://github.com/{REPOSITORY}",
                   f"git@github.com:{REPOSITORY}.git", f"ssh://git@github.com/{REPOSITORY}.git"}
        for option in ((), ("--push",)):
            if self.command("git", "remote", "get-url", *option, "--all", "origin") not in allowed:
                raise ReleaseError(f"origin must have one fetch/push URL for github.com/{REPOSITORY}")
        repository = self.gh_json("api", f"repos/{REPOSITORY}", "--hostname", "github.com")
        if repository.get("full_name") != REPOSITORY or not repository.get("permissions", {}).get("push"):
            raise ReleaseError("GitHub authentication must have push access to the release repository")
        self.sha = self.command("git", "rev-parse", "HEAD")
        refs = self.remote_refs()
        remote_main = refs.get("refs/heads/main")
        if remote_main != self.sha:
            # Resume a commit whose first push failed, but never include unrelated commits.
            if not resume or self.command("git", "rev-parse", "HEAD^") != remote_main:
                raise ReleaseError("Local HEAD and remote main differ; synchronize them before releasing")
            changed = set(self.command("git", "diff-tree", "--no-commit-id", "--name-only",
                                       "-r", "HEAD").splitlines())
            title = self.command("git", "log", "-1", "--format=%s")
            if changed != set(RELEASE_FILES) or title != f"Release {self.version}":
                raise ReleaseError("Only the script's single unpushed release commit can be resumed")
        tagged = self.tag_commit(refs)
        if tagged is not None and (not resume or tagged != self.sha):
            raise ReleaseError(f"{self.tag} already exists or points to another commit; tags are immutable")
        if resume:
            check_release(self.root, self.tag)
        else:
            self.require_unpublished()

    def require_unpublished(self) -> None:
        try:
            fetch_release(self.version)
        except HTTPError as exc:
            if exc.code != 404:
                raise
        else:
            raise ReleaseError(f"{self.version} already exists on PyPI; choose a new version")

    def runs(self, workflow: str, branch: str, event: str) -> list[dict[str, Any]]:
        rows = self.gh_json("run", "list", "--repo", "github.com/" + REPOSITORY, "--workflow", workflow,
                            "--commit", self.sha, "--branch", branch, "--event", event,
                            "--limit", "100", "--json", RUN_FIELDS)
        return sorted((row for row in rows if row["headSha"] == self.sha
                       and row["headBranch"] == branch and row["event"] == event),
                      key=lambda row: row["databaseId"], reverse=True)

    def wait_run(self, workflow: str, branch: str, event: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout
        last_status = None
        run_id = None
        while time.monotonic() < deadline:
            if run_id is None:
                rows = self.runs(workflow, branch, event)
                run = rows[0] if rows else None
            else:
                run = self.gh_json("run", "view", str(run_id), "--repo", "github.com/" + REPOSITORY,
                                   "--json", RUN_FIELDS)
            if run is not None:
                run_id = run["databaseId"]
                status = (run["databaseId"], run["status"], run["conclusion"])
                if status != last_status:
                    print(f"{workflow}: {run['status']} {run['conclusion'] or ''} {run['url']}", flush=True)
                    last_status = status
                if run["status"] == "completed":
                    if run["conclusion"] != "success":
                        raise ReleaseError(f"{workflow} failed: {run['url']}. Inspect it; --resume does not rerun jobs")
                    return run
            time.sleep(15)
        raise ReleaseError(f"Timed out waiting for {workflow}; inspect GitHub Actions, then use --resume. "
                           "If a dispatch never reached GitHub, start it manually only after confirming no run exists")

    def start_or_resume(self) -> dict[str, Any]:
        self.wait_run("ci.yml", "main", "push")
        refs = self.remote_refs()
        if refs.get("refs/heads/main") != self.sha:
            raise ReleaseError("Remote main changed during CI; do not tag a different commit")
        tagged = self.tag_commit(refs)
        if tagged is not None and tagged != self.sha:
            raise ReleaseError("The release tag points to another commit")
        # Persist intent BEFORE dispatch. An interrupted/uncertain request is never sent twice.
        state_path = Path(self.command("git", "rev-parse", "--git-path", f"release-{self.version}.json"))
        if not state_path.is_absolute():
            state_path = self.root / state_path
        state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
        if state and state.get("sha") != self.sha:
            raise ReleaseError("Saved release state belongs to another commit")
        tag_runs = self.runs("tag-release.yml", "main", "workflow_dispatch")
        release_runs = self.runs("release.yml", self.tag, "workflow_dispatch")
        if not release_runs:
            release_runs = self.runs("release.yml", self.tag, "push")
        if not tag_runs and not release_runs and state.get("dispatch_started"):
            raise ReleaseError(
                "A previous dispatch was attempted but no run is visible. Check GitHub Actions, then "
                "resume once the run appears. If you confirm the request never reached GitHub, manually "
                f"start Tag and start release on main with version={self.version} and "
                f"expected_sha={self.sha}, then resume. Do not delete the dispatch record"
            )
        if not tag_runs and not release_runs and tagged is None:
            self.require_unpublished()
            state_path.write_text(json.dumps({"sha": self.sha, "dispatch_started": True}) + "\n",
                                  encoding="utf-8")
            self.command("gh", "workflow", "run", "tag-release.yml", "--repo", "github.com/" + REPOSITORY,
                         "--ref", "main", "-f", f"version={self.version}",
                         "-f", f"expected_sha={self.sha}")
        elif tagged is not None and not tag_runs and not release_runs:
            raise ReleaseError("Tag exists without a visible release run; inspect Actions before manually dispatching")
        if not release_runs:
            self.wait_run("tag-release.yml", "main", "workflow_dispatch")
        event = release_runs[0]["event"] if release_runs else "workflow_dispatch"
        return self.wait_run("release.yml", self.tag, event)

    def verify(self, run: dict[str, Any]) -> None:
        if self.tag_commit(self.remote_refs()) != self.sha:
            raise ReleaseError("Remote tag no longer matches the tested commit")
        release = self.gh_json("release", "view", self.tag, "--repo", "github.com/" + REPOSITORY,
                               "--json", "tagName,isDraft,isPrerelease,url")
        if release["tagName"] != self.tag or release["isDraft"] or release["isPrerelease"]:
            raise ReleaseError("GitHub must have a published stable release for this exact tag")
        with tempfile.TemporaryDirectory(prefix=f"release-{self.version}-") as directory:
            builds, assets = Path(directory) / "builds", Path(directory) / "assets"
            self.command("gh", "run", "download", str(run["databaseId"]), "--repo", "github.com/" + REPOSITORY,
                         "--pattern", "dist-*", "--dir", str(builds), timeout=600)
            expected = local_digests(builds, self.version)
            verify_payload(fetch_release(self.version), self.version, expected)
            self.command("gh", "release", "download", self.tag, "--repo", "github.com/" + REPOSITORY,
                         "--dir", str(assets), timeout=600)
            if local_digests(assets, self.version) != expected:
                raise ReleaseError("GitHub release distributions differ from CI artifacts")
        # Explicit non-forced fetch refuses to replace a conflicting local tag.
        self.command("git", "fetch", "--no-tags", "origin", f"refs/tags/{self.tag}:refs/tags/{self.tag}")
        if self.command("git", "rev-parse", f"{self.tag}^{{commit}}") != self.sha:
            raise ReleaseError("Local tag does not match the released commit")
        print(f"Verified {self.version}: CI artifacts, PyPI and GitHub files/SHA256 match.\n"
              f"{release['url']}\nhttps://pypi.org/project/llm-input-hardening/{self.version}/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", type=stable_version)
    parser.add_argument("--notes-file", type=Path, help="Markdown release notes; keep this file outside the checkout")
    parser.add_argument("--dry-run", action="store_true", help="Read-only preflight and proposed diff; no commits or publication")
    parser.add_argument("--resume", action="store_true", help="Continue a prepared release; never rerun failed publication jobs")
    parser.add_argument("--timeout", type=int, default=7200, help="Maximum seconds to wait per workflow (default: 7200)")
    args = parser.parse_args(argv)
    if args.resume == (args.notes_file is not None):
        parser.error("supply --notes-file for a new release, or --resume without --notes-file")
    if not 60 <= args.timeout <= 86400:
        parser.error("--timeout must be between 60 and 86400 seconds")
    root = Path(__file__).resolve().parents[1]
    driver = Release(root, args.version, args.timeout)
    try:
        driver.preflight(args.resume)
        rendered = None if args.resume else prepare_files(root, args.version, args.notes_file.read_text(encoding="utf-8"))
        if args.dry_run:
            for filename, content in (rendered or {}).items():
                print("".join(difflib.unified_diff((root / filename).read_text(encoding="utf-8").splitlines(True),
                                                  content.splitlines(True), fromfile=filename, tofile=filename)))
            print("Dry run: would commit/push release metadata, wait for exact-main CI, "
                  "tag/publish through Actions, verify both registries, and fetch the tag.")
            return 0
        if rendered is not None:
            for filename, content in rendered.items():
                (root / filename).write_text(content, encoding="utf-8")
            driver.command("git", "diff", "--check")
            driver.command("git", "add", "--", *RELEASE_FILES)
            staged = set(driver.command("git", "diff", "--cached", "--name-only").splitlines())
            if staged != set(RELEASE_FILES):
                raise ReleaseError("The index contains unexpected files; inspect the staged changes")
            driver.command("git", "commit", "-m", f"Release {args.version}")
            driver.sha = driver.command("git", "rev-parse", "HEAD")
            committed = set(driver.command("git", "diff-tree", "--no-commit-id", "--name-only",
                                           "-r", "HEAD").splitlines())
            if committed != set(RELEASE_FILES):
                raise ReleaseError("The release commit contains unexpected files; inspect hooks before pushing")
        if driver.command("git", "status", "--porcelain", "--untracked-files=all"):
            raise ReleaseError("The checkout changed during release preparation; inspect it before pushing")
        check_release(root, driver.tag)
        if driver.remote_refs().get("refs/heads/main") != driver.sha:
            driver.command("git", "push", "origin", f"{driver.sha}:refs/heads/main")
        driver.verify(driver.start_or_resume())
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        print(f"Release stopped: {exc or 'interrupted'}. No tag is moved and no failed run is retried.\n"
              f"After inspecting the failure, continue a clean prepared commit with:\n"
              f"  uv run --no-project python scripts/release.py {args.version} --resume", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
