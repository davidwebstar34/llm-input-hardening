# Installation

Install the base package:

```bash
pip install llm-input-hardening
```

Optional extras:

- `security`: `confusable_homoglyphs` backend for stronger confusable detection

Examples:

```bash
pip install "llm-input-hardening[security]"
```

## From source

```bash
uv sync --all-extras
uv run maturin develop --release
```
