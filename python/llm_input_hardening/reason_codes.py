from __future__ import annotations

from typing import Mapping
from types import MappingProxyType

# Stable reason-code registry for removed/flagged signals.
# Keep these identifiers backward-compatible across releases.
REASON_CODE_REGISTRY: Mapping[str, str] = MappingProxyType({
    "bidi_control": "IH001_BIDI_CONTROL",
    "bidi_mark": "IH007_BIDI_MARK",
    "default_ignorable": "IH002_DEFAULT_IGNORABLE",
    "junk_invisible": "IH003_JUNK_INVISIBLE",
    "control_or_format": "IH004_CONTROL_OR_FORMAT",
    "carriage_return": "IH005_CARRIAGE_RETURN",
    "whitespace_tidy": "IH006_WHITESPACE_TIDY",
    "tag_char": "IH008_TAG_CHARACTER",
    "variation_selector_excess": "IH009_VARIATION_SELECTOR_ABUSE",
    "high_entropy": "IH010_HIGH_ENTROPY",
    "high_combining_ratio": "IH011_HIGH_COMBINING_RATIO",
    "line_separator": "IH012_LINE_SEPARATOR",
    "normalization_amplified": "IH013_NORMALIZATION_EXPANSION_LIMIT",
    "excessive_combining_stack": "IH014_EXCESSIVE_COMBINING_STACK",
    "invalid_variation_selector": "IH015_INVALID_VARIATION_SELECTOR",
    "confusable_mixed_script": "IH020_CONFUSABLE_MIXED_SCRIPT",
    "mixed_script_word": "IH020_CONFUSABLE_MIXED_SCRIPT",
    "confusable_styled": "IH021_CONFUSABLE_STYLED_LATIN",
    "whole_script_confusable": "IH022_WHOLE_SCRIPT_CONFUSABLE",
    "base64ish_blob": "IH030_BASE64_LIKE_PAYLOAD",
    "hex_blob": "IH031_HEX_LIKE_PAYLOAD",
    "encoded_blob": "IH032_ALT_ENCODED_PAYLOAD",
    "encoded_risky_unicode": "IH033_ENCODED_RISKY_UNICODE",
    "encoded_unicode_inspection_limit": "IH034_ENCODED_UNICODE_INSPECTION_LIMIT",
})

DECISION_REASON_CODES: Mapping[str, str] = MappingProxyType({
    "total_removed_threshold": "IH090_REMOVAL_VOLUME_THRESHOLD",
    "input_transformed": "IH091_INPUT_TRANSFORMED",
    "field_validation_failed": "IH092_FIELD_VALIDATION_FAILED",
})


def reason_code_for_signal(signal: str) -> str | None:
    return REASON_CODE_REGISTRY.get(signal)


def reason_code_counts(
    removed_counts: Mapping[str, int],
    flagged_counts: Mapping[str, int],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for source in (removed_counts, flagged_counts):
        for signal, raw_count in source.items():
            count = int(raw_count)
            if count <= 0:
                continue
            code = reason_code_for_signal(signal)
            if code is None:
                continue
            counts[code] = counts.get(code, 0) + count
    return {code: counts[code] for code in sorted(counts)}
