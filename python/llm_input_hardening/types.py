from __future__ import annotations

from typing import Any, Literal, TypedDict


class SpanEvent(TypedDict):
    """One span event emitted by the sanitizer when `return_spans=True`."""

    kind: Literal["removed", "flag"]
    reason: str
    start: int
    end: int
    detail: str


class EncodedUnicodeSample(TypedDict):
    """Bounded evidence; offsets are character indices in the named source."""

    source: Literal["input", "sanitized"]
    start: int
    end: int
    encodings: list[str]
    decode_depth: int
    codepoints: list[str]
    reasons: list[str]


class SanitizeStats(TypedDict, total=False):
    """Additional measurements included in `SanitizeReport["stats"]`.

    Keys may be added over time; consumers should treat this as best-effort telemetry.
    """

    ascii_fast_path: bool
    normalized_changed: bool
    post_removal_normalized_changed: bool
    normalization_input_chars: int
    normalization_output_chars: int
    normalization_output_limit_chars: int
    normalization_truncated: bool
    encoded_unicode_samples: list[EncodedUnicodeSample]
    encoded_unicode_candidates: int
    encoded_unicode_candidate_chars: int
    encoded_unicode_decode_depth: int
    encoded_unicode_limit: str | None
    field_validation_passed: bool
    reject_on_change: bool
    assembly_parts: int
    invalid_variation_selector_count: int
    unicode_normalization_version: str
    unicode_mark_version: str
    variation_data_version: str
    ideographic_variation_policy: str
    combining_ratio: float
    combining_max_stack: int
    combining_suspicious_stacks: int
    base64ish: bool
    base64ish_wrapped: bool
    entropy_2000: float
    confusables_backend: str
    confusables_available: bool
    confusables_mixed_script: bool
    confusables_dangerous: bool
    confusables_restriction_level: str
    confusables_scripts: list[str]
    confusables_skeleton_stored: bool
    confusables_skeleton: str
    confusable_count: int
    confusables_error: str
    confusables_styled_latin: bool
    styled_latin_words: list[str]
    confusables_styled_compatibility: bool
    styled_compatibility_tokens: list[str]
    mixed_script_word_count: int
    mixed_script_words: list[str]
    confusables_whole_script: bool
    whole_script_confusable_actionable: bool
    whole_script_word_count: int
    whole_script_words: list[str]
    hexish: bool
    hex_format: str | None
    encoded_blob: bool
    encoded_blob_format: str | None
    entropy_window_max: float
    default_ignorable_removed: int
    default_ignorable_removed_joiner: int
    default_ignorable_removed_variation_selector: int
    default_ignorable_removed_tag: int
    default_ignorable_removed_other: int
    default_ignorable_stripped: bool
    json_string_leaf_count: int
    json_changed_string_leaves: int
    json_string_key_count: int
    json_changed_string_keys: int
    json_max_depth: int
    json_node_count: int
    json_total_chars: int
    json_output_chars: int
    json_path_reports: list[dict[str, Any]]


class SanitizeReport(TypedDict):
    """Structured report returned by `sanitize()`."""

    report_version: int
    policy: str
    normalization: str
    changed: bool
    removed_counts: dict[str, int]
    flagged_counts: dict[str, int]
    reason_codes: dict[str, int]
    spans: list[SpanEvent]
    stats: SanitizeStats


class TokenMeter(TypedDict):
    """Token budget information emitted by `meter()`."""

    tokenizer: str
    estimated: bool
    input_tokens: int
    limit_tokens: int | None
    reserved_output_tokens: int
    available_tokens: int | None
    percent_used: float | None


class MeterResult(TypedDict):
    """Return type for `meter()`."""

    sanitize: SanitizeReport
    tokens_before: TokenMeter
    tokens_after: TokenMeter


EnforcementAction = Literal["allow", "quarantine", "reject"]


class EnforcementDecision(TypedDict):
    """Decision emitted by `decide_enforcement()`.

    `reasons` is a deprecated alias of `reason_codes` kept for backward
    compatibility; new consumers should read `reason_codes`.
    """

    action: EnforcementAction
    reason_codes: list[str]
    reasons: list[str]
    triggered_flags: dict[str, int]
    triggered_removed: dict[str, int]
