# Dependency status

Version 3.0.0 removes the ftfy integration and its wcwidth dependency. The base
Python package has no Python runtime dependencies; the remaining optional extra
is `confusable-homoglyphs>=3.3.1` through `[security]`.

The Rust/Python binding uses PyO3 0.29.2. Cargo.lock and uv.lock pin build,
development and runtime dependencies. CI audits the Rust graph, the optional
Python runtime dependency and every locked Python version across platforms.

On 2026-09-06 the local Python audit covered all 67 locked package versions and
reported no known vulnerabilities. Publication repeats fresh audits; a past
successful audit is not a permanent assurance about dependency safety.

The dependency export must include `confusable-homoglyphs`; the audit scope
check fails if the export is empty or omits it. See the CI and release workflows
and `scripts/audit_dependencies.py` for the enforced gates.
