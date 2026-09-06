from __future__ import annotations

from llm_input_hardening import sanitize


def test_emoji_variation_selector_removed() -> None:
    text = "I ❤️ prompts"
    clean, rep = sanitize(text, policy="strict_exec")
    assert clean == "I ❤ prompts"
    assert rep["removed_counts"].get("default_ignorable", 0) >= 1


def test_emoji_zwj_chain_disrupted() -> None:
    text = "👨‍👩‍👧‍👦"
    clean, rep = sanitize(text, policy="strict_exec")
    assert clean == "👨👩👧👦"
    assert rep["removed_counts"].get("default_ignorable", 0) == 3


def test_emoji_zwj_chain_preserved_in_balanced_chat() -> None:
    text = "👨‍👩‍👧‍👦"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["removed_counts"].get("default_ignorable", 0) == 0
