# Contributing

## Development setup

```bash
uv sync --all-extras
uv run maturin develop --release
uv run pytest -q
```

Useful local commands:

- `uv run ruff check .`
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `make bakeoff-smoke`
- `make bakeoff-full`

## Repository layout

- `src/`: Rust core sanitizer and report types
- `python/llm_input_hardening/`: Python API, CLI, middleware, telemetry, and integrations
- `tests/`: release-facing contract and regression coverage
- `bench/`: optional performance and evaluation tooling
- `docs/`: repository notes kept out of the default build path

## Working on the Rust/Python boundary

Policy presets are defined once in [`python/llm_input_hardening/policy_registry.json`](python/llm_input_hardening/policy_registry.json).

If you change preset behavior:

1. Update the shared registry.
2. Rebuild the extension with `uv run maturin develop --release`.
3. Run `uv run pytest -q`.

Keep canonical sanitization behavior in Rust when possible. Python should mostly orchestrate, enrich signals, and expose integrations.

## Tests

Run the full suite before opening a PR:

```bash
uv run pytest -q
```

When touching packaging or release behavior, also build the package and smoke-test an installed artifact:

```bash
uv run maturin build --release --out dist
```

For the tagged release push sequence, use:

```bash
scripts/release.sh 3.0.1
```

The script updates the version in `pyproject.toml`, `Cargo.toml`, `uv.lock`, and `Cargo.lock` before it creates the release commit and tag.

## Unicode and corpus hygiene

Invisible and confusable characters are part of the project’s threat model. When submitting tricky cases:

- Prefer escaped literals in tests when readability would otherwise suffer.
- Add a regression test with each sanitizer rule change.
- Explain the attack shape in the test name or surrounding comment.
- Avoid pasting ambiguous text into docs without an explicit explanation of what is hidden.

## README and benchmarks

The root `README.md` is the primary reference for install, usage, and evaluation commands.

`bench/` contains optional evaluation tooling. Use `make bakeoff-smoke` for a fast local check and `make bakeoff-full` only when you need the heavyweight comparison run.

Contributions are licensed under Apache-2.0. Preserve notices for third-party
material; see `NOTICE` and `licenses/`.
