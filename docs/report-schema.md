# Report schema

This project returns a structured report for every sanitization call.

The schema is **versioned** so applications can safely parse and evolve with the library.

---

## Top-level fields

- `report_version` (int): schema version (currently `1`)
- `policy` (str): effective policy name (e.g. `"balanced"`)
- `normalization` (str): effective normalization (e.g. `"NFC"`, `"NFKC"`)
- `changed` (bool): whether output differs from input
- `removed_counts` (dict[str, int]): counts by removal category
- `flagged_counts` (dict[str, int]): counts by flag type
- `reason_codes` (dict[str, int]): stable reason-code counts derived from removed and flagged signals
- `spans` (list[SpanEvent]): present for every call; populated only when `return_spans=True`
- `stats` (dict[str, Any]): additional measurements (see below)

---

## removed_counts keys

These keys are stable and may be extended over time:

- `carriage_return`: removed `\r` characters
- `line_separator`: removed Unicode line/paragraph separators (`U+2028`, `U+2029`)
- `normalization_amplified`: normalization exceeded the bounded expansion limit
  and was truncated before scanning (counted once per affected call)
- `bidi_control`: removed bidi control codepoints (visual spoofing / hiding)
- `junk_invisible`: removed explicit “junk invisible” codepoints (ZWSP, WORD JOINER, BOM)
- `control_or_format`: removed disallowed `Control`/`Format` characters (except `\n`, `\t`)
- `default_ignorable`: removed Unicode Default-Ignorable code points (joiners, variation selectors, tags, etc.)
- `whitespace_tidy`: characters collapsed by tidying; formatting changes do not
  contribute to the default removal-volume quarantine threshold
- `tag_char`: removed tag characters; only England/Scotland/Wales RGI subdivision
  sequences are preserved by chat policies, and strict policies remove all tags
- `variation_selector_excess`: extra selectors adjacent in surviving output

Keep keys stable. Prefer adding new keys over changing meanings.

---

## flagged_counts keys

Flags are signals; they do not necessarily imply an input should be rejected.

- `encoded_risky_unicode`: risky scalars found in supported encoded candidates
  (`IH033`); maximum count across original/sanitized views; default quarantine
- `encoded_unicode_inspection_limit`: candidate/depth/work budget exhausted
  (`IH034`); default quarantine, even if no risky scalar was reached


- `base64ish_blob`: a contiguous or whitespace-wrapped region has a base64-like shape
- `high_entropy`: Shannon entropy over the first 2,000 characters exceeds a threshold
- `high_combining_ratio`: combining marks exceed a ratio threshold; observational
  only under default enforcement, since legitimate languages can have high ratios
- `excessive_combining_stack`: a stack of at least eight marks, at least three
  stacks of five marks, or five marks combined with the high-ratio signal
- `invalid_variation_selector`: a preserved selector is unsupported for its
  preceding base under the declared variation-context policy (`IH015`);
  default enforcement quarantines this observation
- `hex_blob`: long contiguous hex-like payload shape or space-separated byte-hex sequence
- `encoded_blob`: ascii85/base85-looking payload shape or long space-separated binary-byte sequence
- `mixed_script_word`: at least one word mixes visually-confusable scripts
- `confusable_mixed_script`: mixed-script homoglyph signal from the optional confusable backend
- `whole_script_confusable`: at least one token's non-Latin letters fold to
  ASCII Latin; at least three actual letters are required, while digits and
  connector punctuation can continue the token. Retained in native prose too
- `confusable_styled`: styled/compatibility Latin forms or compatibility digits

---

## stats

Current keys:
- `ascii_fast_path` (bool): present when the fast-path was used
- `normalized_changed` (bool): whether Unicode normalization changed the input
- `post_removal_normalized_changed` (bool): whether final normalization composed
  characters brought together by removal; output still uses the original cap
- `normalization_input_chars` / `normalization_output_chars` (int): scalar counts before and after bounded normalization
- `normalization_output_limit_chars` (int): active normalization output cap
- `normalization_truncated` (bool): whether normalization hit the cap
- `combining_ratio` (float): combining mark ratio (0–1)
- `combining_max_stack` / `combining_suspicious_stacks` (int): largest consecutive
  mark stack and count of stacks with at least five marks; default-ignorables do
  not separate stacks
- `encoded_unicode_samples`: at most eight samples with character offsets,
  explicit `input`/`sanitized` source, encodings, depth, codepoints and reasons
- `encoded_unicode_candidates`, `encoded_unicode_candidate_chars`: work consumed
- `encoded_unicode_decode_depth`: greatest decoded depth reached
- `encoded_unicode_limit`: `null`, `candidates`, `candidate_chars` or `decode_depth`
  (see [encoded inspection](security/encoded-unicode.md) for exact semantics)

- `field_validation_passed` (bool): result of an explicitly supplied validator
- `assembly_parts` (int): raw fragment count when using `sanitize_assembled`
- `base64ish` (bool): base64ish detector result
- `base64ish_wrapped` (bool): the base64-like region includes wrapping whitespace
- `invalid_variation_selector_count` (int): selectors with unsupported base context
- `unicode_normalization_version` / `unicode_mark_version` (str): Unicode data
  version used by native normalization and mark classification
- `variation_data_version` (str): pinned standardized/emoji variation data version
- `ideographic_variation_policy` (str): contextual policy for extended Han
  selectors; this is not a claim of exact IVD sequence registration
- `entropy_2000` (float): Shannon entropy over the first 2,000 characters
- `confusables_backend` (str): backend name when confusable checks are enabled
- `confusables_available` (bool): whether the backend import succeeded
- `confusables_mixed_script` (bool): backend mixed-script signal
- `confusables_dangerous` (bool): backend dangerous/confusable signal
- `confusable_count` (int): backend-reported confusable character count
- `confusables_styled_latin` (bool): styled/compatibility Latin detector result
- `styled_latin_words` (list[str]): sample words containing styled Latin
- `confusables_styled_compatibility` (bool): styled letter or compatibility-digit detector result
- `styled_compatibility_tokens` (list[str]): sample styled/compatibility tokens
- `mixed_script_word_count` (int): number of mixed-script words detected
- `mixed_script_words` (list[str]): sample mixed-script words
- `confusables_whole_script` (bool): whole-script confusable detector result
- `whole_script_word_count` (int): number of whole-script confusable words
- `whole_script_words` (list[str]): sample whole-script confusable words
- `whole_script_confusable_actionable` (bool): false only for candidates within
  established native prose (one non-Latin script, at least three nonconfusable
  words of three characters, outnumbering candidate words). Default chat permits
  those candidates only when this is explicitly false; execution policy
  still rejects them. Custom policies can override that choice.
- `confusables_error` (str): backend error text when detection fails
- `hexish` (bool): hex-like detector result
- `hex_format` (str | null): detected hex shape (`"contiguous"` or `"spaced_bytes"`)
- `encoded_blob` (bool): alt-encoded blob detector result
- `encoded_blob_format` (str | null): detected alt encoding shape (`"ascii85"`, `"base85"`, or `"binary_bytes"`)
- `entropy_window_max` (float): max entropy over sliding windows
- `default_ignorable_removed` (int): total removed by the Python default-ignorable pass
- `default_ignorable_removed_joiner` (int): removed joiners (`ZWNJ`, `ZWJ`)
- `default_ignorable_removed_variation_selector` (int): removed variation selectors
- `default_ignorable_removed_tag` (int): removed Unicode tag characters
- `default_ignorable_removed_other` (int): removed other default-ignorables
- `json_string_key_count` / `json_changed_string_keys` (int): key traversal counts from `sanitize_json()`
- `json_path_reports` (list[dict]): per-string value and key reports; key entries use a `<key>` path suffix and `location: "key"`
- `json_node_count` / `json_total_chars` / `json_output_chars` (int): traversal
  nodes and input/output string character totals, including mapping keys

Word/token samples contain at most eight entries of 160 characters each. The
whole-text confusable skeleton is omitted for inputs or skeletons above 4,096 characters;
`confusables_skeleton_stored` explicitly reports availability. Detection still
examines the full bounded input.

`decide_enforcement(report)` selects the policy matching `report["policy"]` by
default, consistently with `sanitize_and_decide`. Explicit policies still take
precedence. New decision reasons are `IH091_INPUT_TRANSFORMED` for
`reject_on_change=True` and `IH092_FIELD_VALIDATION_FAILED` for a validator
returning false. The stack observation uses `IH014_EXCESSIVE_COMBINING_STACK`.

---

## spans (SpanEvent)

Each span event describes an observed removal or flag at a point in the scan.

Shape:

```json
{
  "kind": "removed",
  "reason": "bidi_control",
  "start": 10,
  "end": 13,
  "detail": "U+202E"
}
```

Rules:
- `kind` is `"removed"` or `"flag"`.
- `reason` matches the keys used in `removed_counts` / `flagged_counts`.
- `detail` contains additional context (usually a `U+XXXX` codepoint).
- `start/end` are **UTF-8 byte indices into the initial normalized scan**, before
  removal or final composition. Final output is normalized again after removal.
  - If `stats.normalized_changed` is false, these byte indices
    also match the original input string.
  - Do not use them as Python character indices or as offsets into the original
    input when normalization changed it.
  - More than 10,000 span events raises `ValueError`; no events are silently
    clipped. Whole-text Python heuristic flags do not claim character spans.
  - JSON spans are stored in each corresponding path report, not in the root
    `spans` list, because different leaves have different coordinate systems.

---

## Example report

```json
{
  "report_version": 1,
  "policy": "balanced",
  "normalization": "NFC",
  "changed": true,
  "removed_counts": {"bidi_control": 1, "junk_invisible": 1},
  "flagged_counts": {"base64ish_blob": 1},
  "reason_codes": {"IH030_BASE64_LIKE_PAYLOAD": 1},
  "spans": [],
  "stats": {"normalized_changed": false, "base64ish": true, "entropy_2000": 4.2, "combining_ratio": 0.0}
}
```
