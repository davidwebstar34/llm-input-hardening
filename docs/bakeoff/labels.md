# Bake-off Labels

This page defines each bake-off label as a test contract.

## `bidi_control`

- Trigger: text contains bidi embedding/override/isolate controls used to reorder visual rendering.
- Typical code points: `U+202A..U+202E`, `U+2066..U+2069`, `U+200E`, `U+200F`, `U+061C`.
- Expected action:
  - `balanced_chat`: remove dangerous bidi controls.
  - `strict_exec`: remove dangerous bidi controls.
  - `preserve`: remove dangerous bidi controls.
- Postcondition:
  - if case expects removal, output must not contain bidi controls.
- Reference: [UAX #9](https://www.unicode.org/reports/tr9/).

## `junk_invisible`

- Trigger: known stealth characters with little legitimate free-text value in most prompts.
- Typical code points: `U+200B` (ZWSP), `U+2060` (WORD JOINER), `U+FEFF` (BOM in-text).
- Expected action:
  - remove for all policies.
- Postcondition:
  - output must not contain the configured junk invisibles.
- References:
  - [UAX #9](https://www.unicode.org/reports/tr9/) (interaction with bidi rendering).
  - [UTS #39](https://www.unicode.org/reports/tr39/) (security context for invisible/ambiguous text).

## `default_ignorable`

- Trigger: Default_Ignorable code points preserved for compatibility/shaping but dangerous in high-risk text channels.
- Typical ranges:
  - ZWJ/ZWNJ
  - variation selectors (`U+FE00..U+FE0F`, `U+E0100..U+E01EF`)
  - tag characters (`U+E0000..U+E007F`, `U+E0080..U+E00FF`)
- Expected action:
  - `strict_exec`: remove.
  - `balanced_chat` / `preserve`: may retain selected characters.
- Postcondition:
  - for strict removal cases, output must not contain configured default-ignorables.
- References:
  - [UTS #39](https://www.unicode.org/reports/tr39/)
  - [UAX #15](https://www.unicode.org/reports/tr15/)

## `control_or_format`

- Trigger: disallowed control/format characters outside permitted whitespace controls.
- Expected action:
  - remove for all policies.
- Postcondition:
  - output must not contain disallowed control/format code points.
- References:
  - [UAX #9](https://www.unicode.org/reports/tr9/)
  - [UTS #39](https://www.unicode.org/reports/tr39/)

## `line_separator`

- Trigger: Unicode line/paragraph separators that behave like structural newlines but are not ASCII control characters.
- Typical code points: `U+2028` (LINE SEPARATOR), `U+2029` (PARAGRAPH SEPARATOR).
- Expected action:
  - remove for all policies.
- Postcondition:
  - output must not contain Unicode line/paragraph separators.
- Rationale:
  - these can create prompt/log/template boundary changes while avoiding checks that look only for `\n` or `\r`.

## `base64ish_blob`

- Trigger: payload pattern likely encoded data (long base64-like token).
- Expected action:
  - flag-only (detection signal); not necessarily transformed.
- Postcondition:
  - required label must be detected when case expects this label.

## `hex_blob`

- Trigger: long, even-length hex-only token or space-separated byte-hex sequence likely representing encoded/binary payload.
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.

## `encoded_blob`

- Trigger: non-base64/non-hex encoded-looking payload shape, currently ascii85/base85-looking runs or long space-separated binary-byte strings.
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.

## `high_entropy`

- Trigger: entropy window exceeds configured threshold, indicating non-natural text payload.
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.

## `high_combining_ratio`

- Trigger: combining-mark ratio exceeds threshold. This is observational: ordinary vocalized/pointed languages can have high ratios, so the ratio alone does not quarantine.
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.

## `excessive_combining_stack`

- Trigger: a single base carries an excessive consecutive combining-mark stack.
- Expected action: flag-only; default enforcement quarantines.
- Corpus controls cover ten combining ranges and mark-rich benign language samples in the separate enforcement corpus.

## `confusable_mixed_script`

- Trigger: mixed-script confusable signal (heuristic and/or backend-assisted detection).
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.
- References:
  - [UTS #39](https://www.unicode.org/reports/tr39/) (mixed-script/confusables/skeleton concepts).
  - [UAX #15](https://www.unicode.org/reports/tr15/) (normalization caveats that affect confusable analysis).

## `whole_script_confusable`

- Trigger: a non-Latin word maps entirely to an ASCII-Latin skeleton while
  remaining single-script. This observation is retained even in native prose.
  Chat enforcement uses the contextual actionability field to allow benign
  native prose; strict enforcement rejects candidates conservatively.
- Typical examples: all-Cyrillic `раураӏ` and all-Cherokee
  `ᏢᎪᎽᏢᎪᏞ`.
- Expected action: flag-only; enforcement rejects for execution policies and
  quarantines for chat policies.
- Postcondition: required label must be detected.

## `confusable_styled`

- Trigger: styled/compatibility Latin forms or compatibility digits that
  visually spoof ASCII under chat policies.
- Typical examples:
  - mathematical bold/italic Latin
  - circled Latin
  - fullwidth Latin
  - small-cap Latin letters
  - fullwidth, circled, and superscript digits
- Expected action:
  - flag-only.
- Postcondition:
  - required label must be detected.

## `normalization_amplified`

- Trigger: NFC/NFKC output would exceed `max(128, input_chars * 8)`.
- Expected action: remove; normalization is stopped at the limit and default
  enforcement rejects the lossy result.
- Postcondition: output must change and the required label must be detected.
