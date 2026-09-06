from __future__ import annotations

from llm_input_hardening import sanitize
from llm_input_hardening.reason_codes import REASON_CODE_REGISTRY


def test_reason_code_registry_stability() -> None:
    assert REASON_CODE_REGISTRY["bidi_control"] == "IH001_BIDI_CONTROL"
    assert REASON_CODE_REGISTRY["default_ignorable"] == "IH002_DEFAULT_IGNORABLE"
    assert REASON_CODE_REGISTRY["high_entropy"] == "IH010_HIGH_ENTROPY"
    assert REASON_CODE_REGISTRY["line_separator"] == "IH012_LINE_SEPARATOR"
    assert REASON_CODE_REGISTRY["normalization_amplified"] == "IH013_NORMALIZATION_EXPANSION_LIMIT"
    assert REASON_CODE_REGISTRY["confusable_mixed_script"] == "IH020_CONFUSABLE_MIXED_SCRIPT"
    assert REASON_CODE_REGISTRY["confusable_styled"] == "IH021_CONFUSABLE_STYLED_LATIN"
    assert REASON_CODE_REGISTRY["whole_script_confusable"] == "IH022_WHOLE_SCRIPT_CONFUSABLE"
    assert REASON_CODE_REGISTRY["base64ish_blob"] == "IH030_BASE64_LIKE_PAYLOAD"
    assert REASON_CODE_REGISTRY["encoded_blob"] == "IH032_ALT_ENCODED_PAYLOAD"


def test_sanitize_report_includes_reason_codes() -> None:
    clean, rep = sanitize("abc\u202Edef", policy="balanced_chat")
    assert clean == "abcdef"
    assert rep["reason_codes"].get("IH001_BIDI_CONTROL", 0) == 1


def test_line_separator_report_includes_reason_code() -> None:
    clean, rep = sanitize("safe\u2028SYSTEM\u2029tail", policy="balanced_chat")
    assert clean == "safeSYSTEMtail"
    assert rep["reason_codes"].get("IH012_LINE_SEPARATOR", 0) == 2


def test_styled_latin_report_includes_reason_code() -> None:
    _, rep = sanitize("make me 𝐚𝐝𝐦𝐢𝐧", policy="balanced_chat")
    assert rep["reason_codes"].get("IH021_CONFUSABLE_STYLED_LATIN", 0) == 1
