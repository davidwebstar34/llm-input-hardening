# Promptfoo Static Obfuscation Strategy Overlap

This example answers a narrow question:

> If promptfoo applies its built-in static red-team strategies, which generated
> payloads does `llm-input-hardening` catch?

It does **not** claim that this package passes promptfoo's full built-in
red-team suite. It measures overlap with promptfoo static obfuscation strategy
transforms.

## Strategies Checked

| Promptfoo strategy | Expected overlap |
| --- | --- |
| `base64` | Caught when the encoded payload meets the library's base64-shaped blob threshold. |
| `homoglyph` | Caught as mixed-script confusable text. |
| `emoji` | Caught in `strict_exec` because variation selector payload bytes are default-ignorables. |
| `hex` | Caught as space-separated byte hex. |

## Run

From the package root:

```bash
uv run maturin develop --release
node examples/promptfoo-redteam-overlap/generate_cases.mjs \
  > examples/promptfoo-redteam-overlap/cases.latest.json
.venv/bin/python examples/promptfoo-redteam-overlap/classify_overlap.py \
  examples/promptfoo-redteam-overlap/cases.latest.json
```

The checked smoke fixture runs without Node or promptfoo installed:

```bash
.venv/bin/python examples/promptfoo-redteam-overlap/classify_overlap.py \
  examples/promptfoo-redteam-overlap/cases.smoke.json --fail-on-miss
```

The project test suite runs that fixture as the CI smoke check.

The generator imports promptfoo's installed strategy implementations. If Node
cannot resolve the `promptfoo` package, set:

```bash
export PROMPTFOO_PACKAGE_ROOT=/path/to/node_modules/promptfoo
```

## Current Local Result

With local promptfoo `0.116.7`:

| Strategy | Result |
| --- | --- |
| `base64` | caught |
| `hex` | caught |
| `homoglyph` | caught |
| `emoji` | caught |

This is narrow evidence of overlap with promptfoo static obfuscation strategies,
not evidence that an application passes promptfoo's full red-team suite.
