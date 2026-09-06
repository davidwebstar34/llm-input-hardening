from __future__ import annotations

from llm_input_hardening import sanitize


def test_legitimate_accented_language_passes() -> None:
    text = "Café naïve fiancé déjà vu."
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 0


def test_zalgo_abuse_triggers_flag() -> None:
    text = ("z\u0338" * 200) + " harmless tail"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1


def test_mixed_legitimate_and_abusive_combining_triggers_flag() -> None:
    text = "Café " + ("e\u0338" * 120)
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1


def test_symbol_and_half_mark_zalgo_ranges_trigger_flag() -> None:
    text = ("x\u20dd" * 80) + ("y\ufe20" * 80)
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1


def test_script_specific_combining_marks_trigger_flag() -> None:
    text = ("א\u05b0" * 120) + " tail"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1
