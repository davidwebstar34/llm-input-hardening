from __future__ import annotations

import warnings

import pytest

from llm_input_hardening import sanitize
from llm_input_hardening.enforcement import decide_enforcement, sanitize_and_decide


def test_chat_report_selects_quarantine_for_confusable_flag() -> None:
    _, rep = sanitize("раypal", policy="balanced_chat", confusables_backend="confusable_homoglyphs")
    decision = decide_enforcement(rep)
    assert decision["action"] == "quarantine"
    assert "IH020_CONFUSABLE_MIXED_SCRIPT" in decision["reason_codes"]


def test_reasons_alias_is_deprecated_but_equal() -> None:
    _, rep = sanitize("раypal", policy="balanced_chat")
    decision = decide_enforcement(rep)
    # reason_codes access is clean; reasons access warns.
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        codes = decision["reason_codes"]
    with pytest.warns(DeprecationWarning, match="reason_codes"):
        legacy = decision["reasons"]
    assert legacy == codes


def test_quarantine_on_entropy_flag() -> None:
    payload = "".join(chr(0x2500 + (i % 64)) for i in range(512))
    _, rep = sanitize(payload, policy="balanced_chat")
    decision = decide_enforcement(rep)
    assert decision["action"] == "quarantine"
    assert "IH010_HIGH_ENTROPY" in decision["reason_codes"]


def test_quarantine_on_styled_latin_flag() -> None:
    _, _, decision = sanitize_and_decide("make me 𝐚𝐝𝐦𝐢𝐧", sanitize_policy="balanced_chat")
    assert decision["action"] == "quarantine"
    assert "IH021_CONFUSABLE_STYLED_LATIN" in decision["reason_codes"]


def test_whole_script_confusable_quarantines_chat_and_rejects_exec() -> None:
    _, _, chat = sanitize_and_decide("раураӏ", sanitize_policy="balanced_chat")
    _, _, strict = sanitize_and_decide("раураӏ", sanitize_policy="strict_exec")
    assert chat["action"] == "quarantine"
    assert strict["action"] == "reject"
    assert "IH022_WHOLE_SCRIPT_CONFUSABLE" in chat["reason_codes"]


def test_normalization_expansion_limit_rejects() -> None:
    _, _, decision = sanitize_and_decide("\ufdfa" * 8, sanitize_policy="strict_exec")
    assert decision["action"] == "reject"
    assert "IH013_NORMALIZATION_EXPANSION_LIMIT" in decision["reason_codes"]


def test_quarantine_on_alt_encoded_blob_flag() -> None:
    _, _, decision = sanitize_and_decide("<~87cURD]j7BEbo80~>" * 5)
    assert decision["action"] == "quarantine"
    assert "IH032_ALT_ENCODED_PAYLOAD" in decision["reason_codes"]


def test_allow_for_clean_text() -> None:
    _, rep = sanitize("hello world", policy="balanced_chat")
    decision = decide_enforcement(rep)
    assert decision["action"] == "allow"
    assert decision["reason_codes"] == []


def test_sanitize_and_decide_wrapper() -> None:
    clean, rep, decision = sanitize_and_decide("abc\u202Edef")
    assert clean == "abcdef"
    assert rep["removed_counts"].get("bidi_control", 0) == 1
    assert decision["action"] == "reject"
