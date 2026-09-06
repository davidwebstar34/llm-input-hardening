# Encoded Unicode inspection

Version 3 inspects encoded candidates by default, with no optional dependency.
It adds observations; it never replaces the returned text with a decoded view.
For example, `< abc&#x202E;def` stays unchanged but produces
`encoded_risky_unicode` (`IH033_ENCODED_RISKY_UNICODE`) and a default quarantine.
An ordinary `Tom &amp; Jerry` does not produce this signal.

## Supported candidates

- HTML numeric references (decimal or hexadecimal, including leading zeros and
  omitted semicolons) and named references supported by Python's HTML5 table.
  Inspection is independent of whether the input contains `<`.
- Literal `\uXXXX` and `\UXXXXXXXX` escapes, including paired UTF-16 surrogates.
- Percent-encoded UTF-8 byte runs. Valid sequences remain inspectable alongside
  malformed bytes. Incomplete bytes stay encoded between inspection rounds so
  another encoding can supply a missing prefix.
- Nested or mixed instances of these formats, within the bounds below.

Risk classification reuses the Rust core's policy and Unicode tables: bidi
controls, junk invisibles, disallowed controls, line separators, tag characters,
and policy-removed default ignorables. Unpaired surrogate escapes are also
reported. Numeric HTML references are checked for their target scalar even when
an HTML5 parser would drop or remap it. Ordinary line breaks and tabs are not
encoded-risk signals. Chat-preserved directional marks, joiners and variation
selectors do not trigger this scalar-level detector; strict policies flag their
encoded forms. Encoded tag characters are observational even when a complete
decoded tag sequence might be a legitimate flag.

Both the input and, if different, the sanitized output are inspected. This
catches escapes assembled by normalization or invisible-character removal.
The flag count is the maximum count across these two views, avoiding duplicate
counts for the same input. It counts risky scalars in decoded candidates, not
malicious instructions or uniquely identified attacks.

## Bounded work and evidence

Each inspected view permits at most three decoding layers, 4,096 candidate
matches and 65,536 candidate characters across those layers. A fourth-layer
probe checks whether further supported decoding is needed. Exceeding a budget
produces `encoded_unicode_inspection_limit`
(`IH034_ENCODED_UNICODE_INSPECTION_LIMIT`); default enforcement quarantines it.
It is an incomplete inspection, not a clean result. These bounds are fixed for
this release; the existing input-size bound also applies.

Reports contain:

- `stats.encoded_unicode_candidates` and `encoded_unicode_candidate_chars`:
  work consumed, summed across inspected views.
- `stats.encoded_unicode_decode_depth`: greatest decoded depth reached.
- `stats.encoded_unicode_limit`: `null`, `candidates`, `candidate_chars`, or
  `decode_depth` (the first exhausted budget across inspected views).
- `stats.encoded_unicode_samples`: at most eight samples total. Each has
  `start`, `end`, `source`, `encodings`, `decode_depth`, `codepoints` and `reasons`.
  Codepoint lists are capped at eight; counts continue within the work budget.

Sample offsets are **Python character indices**, end-exclusive, into the
original `input` or returned `sanitized` string identified by `source`. They are
separate from the core's normalized UTF-8 byte spans. Nested samples point to
the original encoded range, not a temporary decoded string. Samples contain no
raw input text. JSON path reports retain samples and limit status per field,
subject to the existing JSON report-size budget.

## Enforcement and integration

Both signals quarantine under every default enforcement preset. Callers can
change severity using `EnforcementPolicy.reject_flags` and `quarantine_flags`.
Removing a signal from quarantine allows that observation unless another rule
blocks it; it does not change the inspection or make downstream decoding safe.
Documentation and code samples can legitimately contain dangerous escapes.

Parse the actual transport/document format first, then harden the resulting
text. If a later component decodes or transforms text, inspect the resulting
representation again before using it. A parsed JSON `"\u202e"` already contains
a bidi control; a JSON string containing a literal backslash escape is a
different input. Do not repeatedly decode production text until it looks clean.

This is a finite detector, not a universal decoder or an HTML sanitizer. It does
not emulate arbitrary parser order, URL/form semantics, JavaScript escapes,
base64 decoding, compression, custom encodings, or model interpretation of an
encoded instruction. The Python API owns candidate inspection; direct Rust
`sanitize_inner` users receive core Unicode checks, not this Python signal.

See [CWE-180](https://cwe.mitre.org/data/definitions/180.html) and
[CWE-174](https://cwe.mitre.org/data/definitions/174.html) for validation order and
double-decoding hazards.
