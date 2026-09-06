# Contributing

The contributor workflow lives in the repository root:

- [Contributing guide](https://github.com/davidwebstar34/llm-input-hardening/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/davidwebstar34/llm-input-hardening/blob/main/SECURITY.md)
- [Scope](https://github.com/davidwebstar34/llm-input-hardening/blob/main/SCOPE.md)

In short:

```bash
uv sync --all-extras
uv run maturin develop --release
uv run python -m pytest -q
```
