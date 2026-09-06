# How it works

This page describes the **algorithmic pipeline**, **invariants**, and **threat rationale** for the sanitizer shipped in this repo.

---

## Design goals

1. **Deterministic**: same input + policy → same output + report.
2. **Streaming-friendly**: linear scan over the text where possible.
3. **Low overhead**: safe to run on every user request.
4. **Explicit scope**: remove stealth Unicode aggressively, while leaving semantic text interpretation out of scope.
5. **Actionable reporting**: every change is counted; suspicious patterns are flagged.

---

## Pipeline

![llm-input-hardening text integrity pipeline](assets/input-hardening-flow.svg)

### 1) Bound input and inspect encoded candidates

Input is bounded before processing. Python inspects both the original input and
sanitized output for [encoded risky Unicode](security/encoded-unicode.md).
Candidate decoding is bounded and never changes returned text. Risk observations
and exhausted inspection limits quarantine by default.

### 2) Newline normalization

Normalize Windows newlines so templating and downstream rules are stable:

- `\r\n` → `\n` (by removing `\r`)
- `\r` → removed

**Invariant**: output contains no `\r`.

### 3) Unicode normalization (policy-controlled)

- `NFC`: canonical composition (default safe).
- `NFKC`: compatibility composition (stricter; can fold “lookalike” characters).
- Output is streamed into `max(128, input_chars * 8)`; exceeding the bound
  emits `normalization_amplified` and rejects by default.

**Why it matters**: attackers can use compatibility characters, full-width variants, and odd combining sequences to bypass filters or create ambiguous prompts.

### 4) Character filtering

Perform a single pass over Unicode scalar values:

Remove (policy-controlled):
- **Bidi controls** (visual spoofing / hiding)
- **Junk invisibles** (ZWSP/BOM/WORD JOINER; explicit library list)
- **Control / format characters** except allowed controls (`\n`, `\t`)
- **Default-Ignorable code points** (including joiners, variation selectors, and tags)

Preserve (by default):
- common whitespace (space, newline, tab)

**Invariant**: output contains no dangerous bidi overrides, listed junk
invisibles, tag-character payloads, or disallowed controls. Chat policies still
preserve legitimate joiners and a single variation selector where appropriate.

### 5) Optional whitespace tidying

When enabled:
- collapse repeated spaces
- trim leading/trailing whitespace
- trim spaces around newlines
- strip trailing newlines

This is useful when you inject user input into prompt templates and want stable formatting.

After removal/tidying, normalize again under the original expansion budget.
This ensures the returned text is NFC/NFKC and remains unchanged on a second
sanitization. Selector caps follow surviving output adjacency. Span coordinates
continue to refer to the initial normalized scan.

### 6) Flags / signals (heuristics)

Flags do **not** necessarily modify output. They are signals for application-level handling:

Examples:
- `base64ish_blob`: contiguous or whitespace-wrapped base64-like regions
- `high_entropy`: high Shannon entropy in the first 2,000 characters
- `high_combining_ratio`: unusually high combining-mark ratio
- `excessive_combining_stack`: pathological mark stacks; this drives default
  quarantine while the ratio remains observational for multilingual safety
- `invalid_variation_selector`: a selector has unsupported base context;
  default enforcement quarantines this observation
- `hex_blob`: long contiguous hex-looking payload or promptfoo-style space-separated byte hex
- `confusable_mixed_script`: optional mixed-script homoglyph signal via `confusable_homoglyphs`
- `whole_script_confusable`: a single non-Latin script word folds entirely to ASCII Latin
- `confusable_styled`: styled letters and compatibility digits

### 7) Report generation

A structured report is returned containing:
- `changed`
- `removed_counts`
- `flagged_counts`
- optionally spans so you can highlight exactly what was removed and where.
- `stats` with additional measurements (e.g., entropy and combining ratio).
- `compact_report()` when you need a small JSON summary for demos, logs, or release evidence.

See [Report schema](report-schema.md).

---

## Complexity and performance notes

- Unicode normalization and filtering are **O(n)** in the number of characters.
- Whitespace tidying is **O(n)**.
- Entropy is computed over only the first 2,000 characters (bounded).
- The implementation includes an ASCII fast-path when it can prove no changes are needed.

This is intended to be cheap enough to run on every request, not just at “ingress”.

---

## Language-safety notes

- Chat policies preserve ZWJ/ZWNJ and one contextual variation selector; strict
  policies remove them. Chat preserves only the three RGI subdivision flags;
  strict policies remove every tag character.
- Combining marks are preserved. Ratios remain visible; default enforcement
  reacts to pathological stacks, not the ratio alone.
- **NFKC can distort text** (it is a compatibility normalization). Use `strict` when you can tolerate folding in exchange for stronger canonicalization.

---

## Recommended application patterns

- Always run sanitization on **untrusted user input** before it reaches the model.
- Treat `flagged_counts` as a decision signal:
  - log it
  - rate-limit
  - require CAPTCHA / auth step
  - reject or route to review
- Use `sanitize_and_decide()` when you want a built-in `allow` / `quarantine` / `reject` decision layer.
- Keep “strict” mode for high-risk contexts (tool execution, code generation, sensitive data).

## Determinism guarantees

For a given version of this library:
- the sanitizer is deterministic (no randomness)
- the output depends only on `(text, policy, normalization override, tidy override)`
- reports are reproducible with pinned Python and dependency versions
