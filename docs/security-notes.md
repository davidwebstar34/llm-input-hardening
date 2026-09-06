# Security notes

## Threat model (what we’re defending against)

This library targets *text-shaping and ambiguity attacks* against LLM applications, including:

- **Unicode obfuscation**: bidi controls and “invisible” codepoints that can hide or reorder text visually.
- **Prompt boundary corruption**: control characters and newline quirks that break assumptions in prompt templates.
- **Encoded payload smuggling**: high-entropy or base64-ish blobs that are unlikely to be normal language and may carry hidden instructions/data.
- **Indirect prompt injection** (supporting control): retrieved documents can contain the same ambiguity tricks as user text.

It does **not** attempt to solve the semantic problem of “will the model follow malicious instructions”.

## What this library does well

- Removes hidden/ambiguous characters that can:
  - hide instructions visually (bidi controls)
  - alter tokenization invisibly (zero-width junk)
  - cause prompt template escapes via control characters
- Normalizes Unicode to reduce confusable or compatibility bypasses
- Emits flags for suspicious payloads to support blocking/monitoring

## What this library does NOT do

- It does not “solve” prompt injection.
- It does not ensure the model follows your system/developer instructions.
- It does not sandbox tools.
- It does not prevent indirect prompt injection unless you sanitize retrieved text too.

## Recommended defense-in-depth

- Strong system prompts + least privilege tool access
- Allowlist-based tool routing
- Retrieval filtering + citations
- Output validation (schemas, allowlists)
- Logging/monitoring of flags for abuse detection
- Human review for high-impact actions

## Recommended production patterns

- Sanitize **all inbound strings**, not just the “prompt” field:
  - user messages
  - retrieved documents (RAG)
  - tool/function-call string arguments
- Treat `flagged_counts` and `removed_counts` as observability signals:
  - log + aggregate by route / tenant / IP
  - alert on spikes
  - optionally reject/step-up auth on suspicious patterns
- Use `strict` (NFKC) only when you can tolerate text distortion; prefer `balanced` for normal chat UX.
- For spoof-prone workflows (identity, payments, admin actions), enable `confusables_backend="confusable_homoglyphs"` and enforce `allow/quarantine/reject` decisions.

## Confusable classification notes

- Confusable analysis is best-effort and reports a UTS #39-aligned `confusables_restriction_level`.
- Mixed-script detection is exposed as telemetry (`confusables_mixed_script`, `mixed_script_words`).
- The built-in heuristic uses static script ranges and covers Latin, Cyrillic,
  Greek, Cherokee, Armenian, and Coptic lookalike mixes. CJK script mixes remain
  excluded to avoid normal Japanese/Chinese/Korean false positives.
- Styled/compatibility Latin forms and compatibility digits such as mathematical
  bold, circled, fullwidth, and small-cap forms are reported separately as
  `confusable_styled`.
- Tokens whose non-Latin letters collapse to ASCII Latin are always reported as
  `whole_script_confusable`. Default chat enforcement permits candidates in
  native prose only when the input uses one non-Latin script and contains at
  least three nonconfusable words of three characters, outnumbering candidates.
  This is a severity heuristic, not an intent guarantee. Strict policies reject
  the observation in every context; adding short padding cannot erase it.
  Detection requires at least three actual letters; digits and connector
  punctuation continue an identifier but do not meet that minimum themselves.
- When text looks confusable, a Latin **skeleton** (NFKC + a curated
  Cyrillic/Greek/Cherokee/Armenian/Coptic→Latin homoglyph fold) is computed and surfaced as
  `stats["confusables_skeleton"]` (with `confusables_skeleton_stored: true`). Two
  homoglyph spoofs of each other collapse to the same skeleton, so you can compare
  it against a trusted term to detect impersonation. Benign, non-confusable text
  carries no skeleton. Skeletons are omitted if either source or generated
  skeleton exceeds 4,096 characters; no truncated skeleton is used as identity.
- Arabic-Indic and other native decimal digits are preserved and not treated as
  styled forms; blanket flagging would turn ordinary multilingual prices into
  false positives. Compatibility digits such as fullwidth `１００` are flagged.

## Normalization resource bound

Normalization is streamed into a bounded buffer. If NFC/NFKC output would
exceed `max(128, input_chars * 8)`, the report records
`normalization_amplified` (`IH013_NORMALIZATION_EXPANSION_LIMIT`), sets
`stats.normalization_truncated`, and default enforcement rejects the lossy
result. This prevents a short compatibility-form input from expanding without a
bound in text, JSON, or middleware call paths.

The Python text API also limits input to 1,000,000 characters by default,
configurable with `max_input_chars`. Requested spans fail above 10,000 events.
`sanitize_json` applies separate traversal, text and report budgets. These limits
raise errors; applications must not catch them and forward unsanitized input.

Canonical ordering and skeleton normalization use bounded native processing, including long
out-of-order mark sequences. Mark classification uses the complete Unicode
General_Category=Mark data provided by the native normalization dependency.
Reports expose the normalization, mark and variation data versions.

Confusable word analysis treats marks, default-ignorables and format characters
as decorations in its detection view, and keeps identifier digits and connector
punctuation within the same token. This view does not strip those characters
from returned multilingual text. All confusable backends use that boundary.

Chat variation-selector checks use pinned standardized/emoji pairs, complete
Mongolian selector coverage, and an explicit Han-context policy for extended
ideographic selectors. Unsupported contexts produce `invalid_variation_selector`
(`IH015`) and quarantine by default. Preserved joiners cannot reset the selector
cap. Valid variation choices remain a potential information channel; preserving
legitimate variants cannot promise to eliminate all steganography.

See the [hardening contract](security/hardening-contract.md) for cross-stage
invariants, assembly boundaries and the regression strategy, and the
[dependency audit status](security/dependency-status.md) for the remaining
release blocker.

Execution-adjacent callers must validate the returned field. NFKC can turn
`．．／admin` into `../admin`; normalization does not authorize paths. Use an
application validator after sanitization and `reject_on_change=True` where
silent transformation is unacceptable. See [field policies](policies/presets.md).

## Determinism boundary (honest version)

The sanitizer is deterministic **per build**, not eternally. The same input, code,
and policy produce the same output — but three data dependencies can shift that
output when they change underneath you:

1. **Unicode version.** Normalization (NFC/NFKC) and the default-ignorable /
   combining / bidi tables are defined by the Unicode Character Database compiled
   into the build. Unicode ships new characters and property corrections most
   years, so a rule that is complete today can develop a hole — or a normalized
   form can change — after a `unicode-normalization` upgrade.
2. **`confusable_homoglyphs` data.** The optional confusables backend carries its
   own confusables table; its verdicts track that package's version.
3. **Python HTML5 entity data.** Encoded-candidate observations use the standard
   library entity table; pin Python when reports must be reproducible.

Treat "deterministic" as *reproducible for a pinned toolchain*. If you depend on
byte-stable output across time (for signatures, caching, or golden tests), pin the
Python, `unicode-normalization` and `confusable-homoglyphs` versions and treat a
bump as a behavior change to re-baseline.

## Bidi handling: overrides vs. marks

Directional **overrides, embeddings, and isolates** (U+202A–202E, U+2066–2069) are
removed under every policy and reject by default (`bidi_control`,
`IH001_BIDI_CONTROL`) — they can force a visual order that disagrees with logical
order (Trojan Source). The plain directional **marks** (LRM/RLM/ALM: U+200E,
U+200F, U+061C) are ordinary content in Arabic/Hebrew; they are a distinct,
softer `bidi_mark` signal (`IH007_BIDI_MARK`) — preserved and flagged under chat
policies, removed only under strict ones. Note the deliberate judgment call:
isolates are grouped with the overrides because they are reorder-capable, even
though they are increasingly used for benign embedding; strict policies are the
place to canonicalize them away.
