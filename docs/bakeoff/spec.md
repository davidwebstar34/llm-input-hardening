# Bake-off Spec

This page is the formal contract for `bench/run_bakeoff.py`.

Result schema 4 declares each adapter's supported labels, excludes unsupported
labels and postconditions from its denominators, and renders unsupported labels
as N/A. Pairwise common-label summaries score both engines on identical label
subsets. This is a capability comparison, not an overall security ranking.

The separate enforcement corpus (`bench/enforcement_corpus.json`) declares
expected decisions for every policy. Its benign quarantine/reject rates include
expected conservative decisions on legitimate suspicious-shaped content;
unexpected decisions are reported separately and fail bakeoff assertions.
Signal presence, malicious intent, and the desired application decision are
distinct labels. Do not relabel benign hashes or multilingual prose as attacks
to improve an enforcement metric.

`kind="benign"` does not require an empty `must_detect`: native Greek/Cyrillic
words and emoji can legitimately carry observable confusable/default-ignorable
signals while remaining unchanged and allowed by chat enforcement.

## Scope and non-goals

- Scope: deterministic text-integrity behavior and reproducible measurement.
- Non-goal: prompt injection prevention as a standalone semantic defense.

## Corpus Contract

Path: `bench/obfuscation_corpus/cases.json`

Each case must include:

```json
{
  "name": "case_id",
  "kind": "attack | benign",
  "policy": "balanced_chat | strict_exec | preserve | code_mode",
  "text": "raw input text",
  "expected": {
    "must_detect": ["label_a", "label_b"],
    "expected_action": "remove | flag_only | preserve",
    "postconditions": {
      "must_not_contain_codepoints": [
        "bidi_control",
        "junk_invisible",
        "default_ignorable",
        "control_or_format",
        "line_separator"
      ]
    }
  }
}
```

## Labels

- `bidi_control`
- `junk_invisible`
- `default_ignorable`
- `control_or_format`
- `line_separator`
- `normalization_amplified`
- `base64ish_blob`
- `hex_blob`
- `encoded_blob`
- `high_entropy`
- `high_combining_ratio`
- `confusable_mixed_script`
- `whole_script_confusable`
- `confusable_styled`

Detailed per-label definitions: [labels.md](labels.md).

## Engine Summary Contract

Each engine result includes:

- detection quality:
  - `micro_precision`
  - `micro_recall`
  - `macro_precision_excluding_zero_support`
  - `macro_recall_excluding_zero_support`
- postcondition quality:
  - `postcondition_pass_rate`
- preservation quality:
  - `benign_changed_rate`
- confidence intervals:
  - `micro_precision_ci.wilson_lo`
  - `micro_precision_ci.wilson_hi`
  - `micro_recall_ci.wilson_lo`
  - `micro_recall_ci.wilson_hi`
  - `postcondition_pass_rate_ci.wilson_lo`
  - `postcondition_pass_rate_ci.wilson_hi`
- stability signals:
  - `token_delta`
  - `invariance`

NFKC is used as a diagnostic shadow path for invariance/token-stability analysis. It is not a blanket transform mandate for runtime policy behavior.

## Token stability backend

- Default token counter: lightweight heuristic chunk estimator.
- Optional backend: `tiktoken` via `--tokenizer tiktoken` and optional `--tokenizer-model`.
- Rationale:
  - heuristic default keeps bake-off lightweight and portable.
  - real tokenizer mode improves fidelity for model-specific token budgets.

Zero-support labels must render as `N/A` in markdown and must be excluded from macro averages.

## Postcondition Rules

- `expected_action=remove`:
  - output must change
  - required `must_not_contain_codepoints` groups must be absent
- `expected_action=flag_only`:
  - all `must_detect` labels must be present
- `expected_action=preserve`:
  - output must not change

CI gate (`bench/assert_bakeoff.py`) must fail when required postcondition floors are not met.

## Corpus governance

- Corpus support floors are enforced from `bench/bakeoff_thresholds.json`.
- Critical labels cannot have zero support.
- Major label families must include benign counterexample coverage per threshold policy.
- Corpus schema and support can be checked with `bench/lint_corpus.py`.
- JSON schema validation is provided by:
  - `bench/schema/corpus.schema.json`
  - `bench/schema/bakeoff_results.schema.json`
  - `bench/schema/thresholds.schema.json`
  - CLI: `bench/validate_json.py`
- Governance policy and release checklist live in [governance.md](governance.md).

## Environment Metadata

Top-level JSON includes `env` with:

- git SHA
- Python version and executable
- OS/platform/machine/CPU metadata
- dependency versions:
  - `llm-input-hardening`
  - `llm-guard`
  - `confusable-homoglyphs`
