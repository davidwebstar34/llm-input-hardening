# Releasing to PyPI and GitHub

Use the release driver from this library's Git checkout. It updates all four
version fields, adds dated release notes, commits only those five files, pushes
`main`, waits for CI on that exact commit, and runs the existing publication
workflows. It finishes by checking the PyPI and GitHub distribution filenames and
SHA256 hashes against CI's artifacts, then fetching the release tag locally.

## One-command releases

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and
[GitHub CLI](https://cli.github.com/), and authenticate with `gh auth login`.
Git must also have permission to push `origin`. The driver requires Python 3.11
or newer; the commands below select Python 3.12. Network access to GitHub and
PyPI is required. A browser login alone does not authenticate Git or `gh`.

Finish and commit implementation changes, dependency updates and documentation
before starting. Switch to `main` and synchronize it with `origin/main`. The
checkout must be clean, including untracked files. Write the new release's
Markdown notes outside the checkout, for example `/tmp/llm-hardening-notes.md`:

```markdown
### Security

- Describe the fixes included in this release.

### Improvements

- Describe changes users need to know about.
```

Supply the next unused stable version and review the dry run first:

```bash
uv run --python 3.12 --no-project python scripts/release.py 3.0.1 \
  --notes-file /tmp/llm-hardening-notes.md --dry-run

uv run --python 3.12 --no-project python scripts/release.py 3.0.1 \
  --notes-file /tmp/llm-hardening-notes.md
```

Replace `3.0.1` with the version you intend to publish. These are examples, not
an instruction to republish 3.0.0. Notes contain the section body only, with
optional `###` subheadings. The driver supplies the version heading and today's
local date; it preserves historical changelog entries. If `CHANGELOG.md` has
nonempty `Unreleased` notes, use that exact section body as the notes file. The
driver moves matching notes into the dated section and keeps an empty
`Unreleased` heading. Differing notes stop preparation so pending changes cannot
be silently discarded. The version must increase
and match `X.Y.Z`, without prerelease suffixes or leading zeros.

`--dry-run` performs read-only network checks and prints the proposed diff. It
does not edit the checkout, stage files, commit, push, tag, or dispatch workflows.
The live command publishes without another prompt. `scripts/release.sh` forwards
the same arguments to the Python driver for compatibility.

## What the command checks

1. The checkout is this library's own repository, on clean `main`; fetch and push
   URLs both identify `davidwebstar34/llm-input-hardening`, GitHub authentication
   has push access, and local HEAD matches the live remote `main`.
2. The version is unused on PyPI and GitHub, all current manifest/lockfile
   versions agree, and the new changelog section is unique and nonempty.
3. Only `pyproject.toml`, `Cargo.toml`, `uv.lock`, `Cargo.lock` and `CHANGELOG.md`
   enter the `Release X.Y.Z` commit. Dependency versions are preserved.
4. The latest `main` push CI for the exact release SHA succeeds. The tag workflow
   also receives that expected SHA, refusing to tag if `main` advanced.
5. **Tag and start release** creates an annotated tag and dispatches **Release**.
   Release repeats tests and fresh dependency audits, builds platform wheels and
   an sdist, uploads through PyPI Trusted Publishing, verifies uploaded hashes,
   tests clean installs on Linux/macOS/Windows, and creates the GitHub Release.
6. The driver downloads that successful run's distribution artifacts and the
   GitHub release assets, compares both registries with the CI hashes, checks the
   tag's commit, and fetches the tag without replacing any existing local tag.

The driver does not automatically fix dependency alerts, change trusted
publishers or environment approvals, yank old packages, or deploy separately
hosted documentation. Complete these maintenance tasks deliberately before a
release when they apply. CI and release failures remain blocking.

## Recovering an interrupted release

Once the release metadata is committed, continue with:

```bash
uv run --python 3.12 --no-project python scripts/release.py 3.0.1 --resume
```

Keep the checkout on the same clean release commit. Resume can push the script's
single release commit if its initial push failed; it rejects unrelated unpushed
commits or a different remote `main`. If interrupted before the metadata commit,
inspect the five files, finish that exact `Release X.Y.Z` commit, and then resume.
It never stages unrelated work to repair an interrupted preparation.

The driver records dispatch intent in `.git/release-X.Y.Z.json` before sending
it. If the response is lost, resume follows the existing run instead of
sending a second publication request. If no run is visible, it stops with
recovery instructions; inspect GitHub Actions and the original error. Only when you establish that the request never reached
GitHub should you manually start **Tag and start release** on the same `main`
commit, with the same version and expected SHA, then resume. Keep the state file;
it prevents accidental duplicate dispatches.

A failed workflow stops the driver. Resume follows existing runs and does not
rerun failed jobs or rebuild an already published version. Inspect the failing
job first. For a transient failure after upload, preserve the same tag and build
artifacts; use GitHub's **Re-run failed jobs** only after confirming it will reuse
the successful build jobs. A code or dependency change requires a new version.
Never move a published tag or try to replace PyPI files under the same version.

Each workflow has a two-hour wait limit; `--timeout SECONDS` changes it within
60–86400 seconds. Waiting times out without canceling remote work. A later
`--resume` continues tracking it. Final verification requires GitHub's build
artifacts to remain within their retention period.

## Publishing access

Configure PyPI's GitHub Trusted Publisher with:

| Setting | Value |
| --- | --- |
| Owner | `davidwebstar34` |
| Repository | `llm-input-hardening` |
| Workflow filename | `release.yml` |
| Environment | `pypi`, or `(Any)` when no restriction is configured |

The publisher verified for 2.0.0 uses `(Any)`, which accepts the workflow's
`pypi` environment. No PyPI token belongs in this repository. Complete any
configured GitHub `pypi` environment review when requested by the publish job.
See [PyPI's setup guide](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).

If GitHub CLI or shell network access is unavailable, restore that access before
using the driver. The same existing workflows can be run from GitHub's Actions
page after manually preparing, reviewing and pushing the five release files.
**Tag and start release** requires successful `main` CI for its exact commit;
**Release** owns publication and verification. A green upload step alone is not
a completed release.

## Public-history baseline (3.0.0)

The public repository starts at a single parentless `Release 3.0.0` commit.
Earlier repository history, tags, releases and pull requests stay in a separate
private archive. Older PyPI releases are not deleted or relicensed.

The initial snapshot is prepared with matching manifests, lockfiles and dated
notes before pushing. CI must pass for that exact root commit; the existing
`tag-release.yml` workflow then tags and publishes it. Subsequent releases use
the normal driver above and retain public history from this baseline onward.

Verify the PyPI Trusted Publisher owner, repository name and workflow before
publication, and preserve the `pypi` deployment environment. The configured
publisher authorizes `davidwebstar34/llm-input-hardening` and `release.yml`; the
owner and these names remain the same across the public-history migration.
