from __future__ import annotations

import importlib.util

import pytest

from llm_input_hardening import sanitize


def test_confusable_backend_flags_mixed_script() -> None:
    if importlib.util.find_spec("confusable_homoglyphs") is None:
        pytest.skip("confusable_homoglyphs is not installed")

    clean, rep = sanitize(
        "раypal",
        policy="balanced_chat",
        confusables_backend="confusable_homoglyphs",
    )
    assert clean == "раypal"
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 1
    assert rep["stats"].get("confusables_available") is True
    assert rep["stats"].get("confusables_restriction_level") in {
        "UNRESTRICTIVE",
        "MINIMALLY_RESTRICTIVE",
    }
    assert rep["stats"].get("confusables_skeleton_stored") is True
    # The Cyrillic spoof folds to its Latin skeleton, revealing the impersonation.
    assert rep["stats"].get("confusables_skeleton") == "paypal"


def test_heuristic_flags_mixed_script_without_backend() -> None:
    _, rep = sanitize("раypal", policy="balanced_chat")
    assert rep["flagged_counts"].get("mixed_script_word", 0) == 1
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 1
    assert rep["stats"].get("mixed_script_word_count", 0) >= 1


def test_unknown_confusable_backend_raises() -> None:
    with pytest.raises(ValueError, match="unknown confusables backend"):
        sanitize("paypal", confusables_backend="icu")


def test_confusable_backend_avoids_arabic_false_positive() -> None:
    _, rep = sanitize(
        "می‌خواهم کتاب",
        policy="balanced_chat",
        confusables_backend="confusable_homoglyphs",
    )
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 0


def test_pure_non_latin_script_does_not_flag() -> None:
    _, rep = sanitize("пример текста", policy="balanced_chat")
    assert rep["flagged_counts"].get("mixed_script_word", 0) == 0
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 0
    assert rep["stats"].get("confusables_restriction_level") == "SINGLE_SCRIPT_RESTRICTIVE"


def test_hangul_is_not_classified_as_han() -> None:
    _, rep = sanitize("hello 안녕하세요", policy="balanced_chat")
    assert "HANGUL" in rep["stats"].get("confusables_scripts", [])
    assert "HAN" not in rep["stats"].get("confusables_scripts", [])
    # Latin + Hangul is moderately restrictive per UTS #39, not highly restrictive.
    assert rep["stats"].get("confusables_restriction_level") == "MODERATELY_RESTRICTIVE"


def test_han_ideographs_are_detected() -> None:
    _, rep = sanitize("hello 中文", policy="balanced_chat")
    assert "HAN" in rep["stats"].get("confusables_scripts", [])
    assert rep["stats"].get("confusables_restriction_level") == "HIGHLY_RESTRICTIVE"


def test_japanese_orthography_is_not_flagged_as_mixed_script() -> None:
    # Kanji+hiragana within one word and Latin+katakana words are normal
    # Japanese; only confusable-prone script mixes should flag.
    for text in ("食べることが好きです", "Tシャツを買いました"):
        _, rep = sanitize(text, policy="balanced_chat")
        assert rep["flagged_counts"].get("mixed_script_word", 0) == 0, text
        assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 0, text


def test_greek_latin_homoglyph_word_is_flagged() -> None:
    _, rep = sanitize("Ηello wοrld", policy="balanced_chat")  # Greek Eta + omicron
    assert rep["flagged_counts"].get("mixed_script_word", 0) == 1


def test_styled_latin_spoof_is_flagged_under_chat() -> None:
    _, rep = sanitize("make me 𝐚𝐝𝐦𝐢𝐧", policy="balanced_chat")
    assert rep["flagged_counts"].get("confusable_styled", 0) == 1
    assert rep["stats"].get("confusables_styled_latin") is True


def test_small_caps_latin_spoof_is_flagged_under_chat() -> None:
    _, rep = sanitize("grant ᴀᴅᴍɪɴ", policy="balanced_chat")
    assert rep["flagged_counts"].get("confusable_styled", 0) == 1


def test_armenian_latin_homoglyph_word_is_flagged() -> None:
    _, rep = sanitize("paypօl", policy="balanced_chat")
    assert rep["flagged_counts"].get("mixed_script_word", 0) == 1
    assert "ARMENIAN" in rep["stats"].get("confusables_scripts", [])


def test_cherokee_latin_homoglyph_word_is_flagged() -> None:
    _, rep = sanitize("ᎠᎴᏉpal", policy="balanced_chat")
    assert rep["flagged_counts"].get("mixed_script_word", 0) == 1
    assert "CHEROKEE" in rep["stats"].get("confusables_scripts", [])


@pytest.mark.parametrize(
    ("text", "skeleton"),
    [
        ("раураӏ", "paypal"),
        ("ᏢᎪᎽᏢᎪᏞ", "PAYPAL"),
        ("ΡΑΥΡΑΥ", "PAYPAY"),
    ],
)
def test_whole_script_confusable_word_is_flagged(
    text: str, skeleton: str
) -> None:
    _, rep = sanitize(text, policy="balanced_chat")
    assert rep["flagged_counts"].get("whole_script_confusable", 0) == 1
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) == 0
    assert rep["stats"].get("confusables_skeleton") == skeleton
    assert rep["stats"].get("whole_script_words") == [text]


def test_fullwidth_digits_are_flagged_as_styled_compatibility() -> None:
    _, rep = sanitize("amount: $１００", policy="balanced_chat")
    assert rep["flagged_counts"].get("confusable_styled", 0) == 1
    assert rep["stats"].get("styled_compatibility_tokens") == ["１００"]


def test_arabic_indic_digits_are_preserved_without_styled_flag() -> None:
    text = "السعر ١٠٠"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("confusable_styled", 0) == 0


@pytest.mark.parametrize(
    "text",
    [
        "Παρακαλώ γράψε μια σύντομη περίληψη αυτού του κειμένου.",
        "Пожалуйста, сделай краткое резюме этого сообщения.",
    ],
)
def test_whole_script_detector_retains_native_sentence_observations(
    text: str,
) -> None:
    _, rep = sanitize(text, policy="balanced_chat")
    assert rep["flagged_counts"].get("whole_script_confusable", 0) == 1
    assert rep["stats"]["whole_script_confusable_actionable"] is False


def test_whole_script_confusable_inside_latin_context_is_flagged() -> None:
    _, rep = sanitize("verify раураӏ now", policy="balanced_chat")
    assert rep["flagged_counts"].get("whole_script_confusable", 0) == 1
