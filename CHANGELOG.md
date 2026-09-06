# Changelog

The public repository history starts with version 3.0.0. Earlier development
history is preserved privately; older PyPI distributions remain unchanged.

## [Unreleased]

## [3.0.0] — 2026-09-06

### Security

- Inspect HTML references, Unicode escapes and percent-encoded UTF-8 for risky
  Unicode by default, including defined nested and mixed encodings.
- Reuse the Rust core's policy-specific scalar classification and inspect both
  original input and sanitized output. Returned text is never entity-decoded.
- Quarantine encoded risky Unicode (`IH033`) and exhausted inspection budgets
  (`IH034`). Keep bounded evidence with explicit source and character offsets.
- Retain per-field evidence in JSON reports and apply the signals through the
  existing CLI, enforcement and middleware paths.

### Breaking changes

- Remove the optional ftfy integration, `use_ftfy`, `--use-ftfy`, the `[ftfy]`
  extra and repair-specific report fields. Remove ftfy and wcwidth dependencies.
- License version 3 under Apache-2.0, preserving earlier MIT and Unicode notices.
- Start the public Git repository with one root commit for v3.0.0.

See [migration and release notes](docs/releases/3.0.0.md) and the
[encoded inspection contract](docs/security/encoded-unicode.md).
