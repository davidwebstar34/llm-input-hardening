# Python API

Auto-generated from docstrings via `mkdocstrings`.

## Package

::: llm_input_hardening

## Final assembled content

`sanitize_assembled(parts, separator="", max_parts=10_000,
max_input_chars=1_000_000, sanitize_policy="balanced_chat", ...)` returns
`(clean, report, decision)`, like `sanitize_and_decide`. It joins raw fragments
and inspects the resulting content once. Other sanitization and field-validation
options are forwarded. `stats.assembly_parts` records the number of fragments.
Limits include empty fragments and separator characters and apply before joining.

Use it at the final content boundary when your application concatenates fields.
Sanitizing each field independently is insufficient for cross-boundary signals.
The caller chooses which content shares a trust boundary; role metadata and
trusted instructions remain separate. See the [hardening contract](../security/hardening-contract.md).

## Configuration snapshots

`signal_thresholds()` returns an immutable mapping of compiled-policy thresholds.
Changing thresholds requires updating the registry and rebuilding. Reason-code
and default enforcement registries are immutable too. Custom `EnforcementPolicy`
instances snapshot signal collections, so mutating the original set cannot
change a previously constructed policy.

## JSON resource limits and spans

`sanitize_json` accepts `max_depth=1000`, `max_nodes=100_000`,
`max_total_chars=4_194_304`, `max_path_reports=10_000`, and
`max_report_chars=4_194_304`. Nodes include mapping keys. Total characters bound
both original and sanitized string totals; report characters bound the serialized
per-path reports, including span details. Limits are nonnegative integers and
exceeding one raises `ValueError` before a result is returned. The input is never
modified. Individual strings retain the text sanitizer's own limits.

`return_spans=True` retains each string's spans on its `json_path_reports` entry.
Encoded Unicode evidence is retained in each entry's `encoded_unicode_samples`,
with character offsets and an explicit input/sanitized source.
The aggregate report's `spans` is empty; offsets are local to each key or value.

## Token measurement

`meter(..., strict_tokenizer=True)` raises `ValueError` when the selected tokenizer
is unavailable, a model is unknown, or encoding fails. Without strict mode, the
fallback estimates one token per UTF-8 byte and marks the result `estimated=True`.
That estimate is deliberately conservative, but is not a model-specific guarantee.
Literal token-like text is counted as ordinary input when using tiktoken.

`limit_tokens` only calculates available capacity and percentage used. It does not
truncate or reject text. Enforce application budgets separately, using the correct
tokenizer on the complete request, including message framing and tool definitions.

See [integration configuration](../integrations.md) for ASGI protected paths,
wildcard selectors, uninspected-request behavior, and quarantine routing.
