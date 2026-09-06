# CLI

The project includes a CLI with three commands:

- `sanitize`: sanitize text and print JSON (`sanitized_text`, `report`, `timing_ms`)
- `inspect`: sanitize and print JSON plus a small summary
- `decide`: sanitize + enforcement decision (`allow`/`quarantine`/`reject`)

`inspect` and `decide` also accept `--compact` for demo-friendly JSON with
`changed`, positive `removed`/`flagged` counts, stable `reason_codes`, and an
optional decision action.

## Examples

```bash
uv run llm-input-hardening sanitize --text "abc\u202Edef"
uv run llm-input-hardening inspect --text "hello"
uv run llm-input-hardening inspect --compact --text "abc\u202Edef"
uv run llm-input-hardening decide --text "раypal"
uv run llm-input-hardening decide --compact --text "раypal"
uv run llm-input-hardening sanitize --no-tidy-whitespace --text "a  b"
```

## Whitespace overrides

Policy defaults usually decide whether whitespace is tidied. The CLI can force
that tri-state either way:

- `--tidy-whitespace`: force tidying on
- `--no-tidy-whitespace`: force tidying off

The flags are mutually exclusive.

## Exit codes

`sanitize` and `inspect` return `0` when parsing succeeds.

`decide` returns:

- `0`: allow
- `2`: quarantine
- `3`: reject

Argument parsing errors use argparse's standard `2`.
