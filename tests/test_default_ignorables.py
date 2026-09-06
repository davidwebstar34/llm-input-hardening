from __future__ import annotations

from llm_input_hardening import sanitize


def _has_default_ignorable(text: str) -> bool:
    # Test helper for key categories required by scope.
    ranges = (
        (0x200C, 0x200D),  # ZWNJ/ZWJ
        (0xFE00, 0xFE0F),  # VS1..VS16
        (0xE0100, 0xE01EF),  # VS17..VS256
        (0xE0000, 0xE007F),  # tags
    )
    for ch in text:
        cp = ord(ch)
        for start, end in ranges:
            if start <= cp <= end:
                return True
    return False


def test_removes_joiners_variation_selectors_and_tags() -> None:
    text = "A\u200cB\u200dC\u2764\ufe0fD\U000E0041E"
    clean, rep = sanitize(text, policy="strict_exec")
    assert clean == "ABC❤DE"
    # ZWNJ, ZWJ, and VS16 are counted as default_ignorable; the tag character is
    # now counted under the dedicated tag_char signal.
    assert rep["removed_counts"].get("default_ignorable", 0) == 3
    assert rep["removed_counts"].get("tag_char", 0) == 1


def test_mixed_adversarial_sentence_removes_ignorables() -> None:
    text = "SAFE\u200b zone \u202Eevil \u200cpayload\ufe0f"
    clean, rep = sanitize(text, policy="strict_exec")
    assert "\u200b" not in clean
    assert "\u200c" not in clean
    assert "\ufe0f" not in clean
    removed_total = rep["removed_counts"].get("default_ignorable", 0) + rep["removed_counts"].get(
        "junk_invisible", 0
    )
    assert removed_total >= 3


def test_invariant_no_default_ignorable_survives() -> None:
    text = "x\u200cz\u200dq\ufe0f\U000E0042"
    clean, _ = sanitize(text, policy="strict_exec")
    assert not _has_default_ignorable(clean)


def test_balanced_chat_preserves_joiners_and_variation_selectors() -> None:
    text = "A\u200cB\u200dC\u2764\ufe0fD"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["removed_counts"].get("default_ignorable", 0) == 0
