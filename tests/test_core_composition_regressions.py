"""Security properties across interacting normalization/removal rules."""

from __future__ import annotations

import unicodedata

import pytest

from llm_input_hardening import sanitize, sanitize_and_decide


POLICIES = ("preserve", "balanced_chat", "strict_exec", "code_mode")
DISALLOWED_ASCII = tuple(cp for cp in (*range(32), 127) if cp not in (9, 10))


def _flag(name: str) -> str:
    return "\U0001f3f4" + "".join(chr(0xE0000 + ord(ch)) for ch in name) + "\U000e007f"


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("codepoint", DISALLOWED_ASCII)
def test_ascii_controls_are_removed_with_tidying_disabled(policy: str, codepoint: int) -> None:
    text = f"a{chr(codepoint)}b"
    clean, report = sanitize(text, policy=policy, tidy_whitespace=False, return_spans=True)
    assert clean == "ab"
    assert report["stats"]["ascii_fast_path"] is False
    assert report["changed"] is True
    assert len(report["spans"]) == 1
    assert report["spans"][0]["start"] == 1
    assert report["spans"][0]["end"] == 2


@pytest.mark.parametrize("policy", POLICIES)
def test_permitted_ascii_controls_keep_fast_path(policy: str) -> None:
    text = "a\tb\nc"
    clean, report = sanitize(text, policy=policy, tidy_whitespace=False)
    assert clean == text
    assert report["stats"]["ascii_fast_path"] is True


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("name", ("gbeng", "gbsct", "gbwls"))
def test_real_subdivision_flags_are_chat_only(policy: str, name: str) -> None:
    text = _flag(name)
    clean, report = sanitize(text, policy=policy)
    if policy in ("preserve", "balanced_chat"):
        assert clean == text
        assert not report["removed_counts"]
    else:
        assert clean == "\U0001f3f4"
        assert report["removed_counts"]["tag_char"] == 6


@pytest.mark.parametrize("policy", POLICIES)
def test_arbitrary_flag_wrapped_tag_chunks_are_removed_and_actioned(policy: str) -> None:
    text = _flag("ignore") + _flag("all") + _flag("sct") + _flag("gbengx")
    clean, report, decision = sanitize_and_decide(text, sanitize_policy=policy)
    assert clean == "\U0001f3f4" * 4
    assert report["removed_counts"]["tag_char"] == 22
    assert decision["action"] != "allow"


@pytest.mark.parametrize("policy", ("preserve", "balanced_chat"))
@pytest.mark.parametrize("separator", ("\x00", "\r", "\u200b", "\u202e", "\u2060", "\U000e0061"))
def test_selector_cap_uses_surviving_output_adjacency(policy: str, separator: str) -> None:
    text = "a\ufe0f" + (separator + "\U000e0100") * 20
    clean, report = sanitize(text, policy=policy, return_spans=True)
    assert clean == "a\ufe0f"
    assert report["removed_counts"]["variation_selector_excess"] == 20
    selector_spans = [span for span in report["spans"] if span["reason"] == "variation_selector_excess"]
    encoded = text.encode("utf-8")
    assert len(selector_spans) == 20
    for span in selector_spans:
        assert encoded[span["start"] : span["end"]].decode("utf-8") == "\U000e0100"


@pytest.mark.parametrize("policy", POLICIES)
@pytest.mark.parametrize("separator", ("\x00", "\r", "\u200b", "\u202e", "\u2060", "\U000e0061"))
@pytest.mark.parametrize("parts", (("e", "\u0301"), ("\u1100", "\u1161"), ("a\u0315", "\u0300")))
def test_deletion_returns_a_normalized_fixed_point(policy: str, separator: str, parts: tuple[str, str]) -> None:
    text = separator.join(parts)
    clean, report = sanitize(text, policy=policy, return_spans=True)
    norm = "NFKC" if policy == "strict_exec" else "NFC"
    assert unicodedata.normalize(norm, clean) == clean
    assert sanitize(clean, policy=policy)[0] == clean
    scanned_bytes = unicodedata.normalize(norm, text).encode("utf-8")
    assert report["stats"]["post_removal_normalized_changed"] is True
    for span in report["spans"]:
        assert scanned_bytes[span["start"] : span["end"]].decode("utf-8") == separator


@pytest.mark.parametrize(
    "text",
    (
        "नमस्ते दुनिया नमस्ते दुनिया नमस्ते दुनिया नमस्ते दुनिया",
        "שָׁלוֹם עוֹלָם שָׁלוֹם עוֹלָם שָׁלוֹם עוֹלָם שָׁלוֹם עוֹלָם",
        "بِسْمِ اللَّهِ الرَّحْمَٰنِ الرَّحِيمِ بِسْمِ اللَّهِ الرَّحْمَٰنِ الرَّحِيمِ",
    ),
)
def test_mark_rich_languages_remain_allowed(text: str) -> None:
    clean, report, decision = sanitize_and_decide(text)
    assert clean == unicodedata.normalize("NFC", text)
    assert report["flagged_counts"]["high_combining_ratio"] == 1
    assert report["flagged_counts"].get("excessive_combining_stack", 0) == 0
    assert report["stats"]["combining_max_stack"] < 5
    assert decision["action"] == "allow"


@pytest.mark.parametrize("text", ("x" + "\u0338" * 8, ("x" + "\u0338" * 5 + " ") * 3, "x" + "\u0338\u200d" * 8))
def test_pathological_mark_stacks_are_actionable(text: str) -> None:
    _, report, decision = sanitize_and_decide(text)
    assert report["flagged_counts"]["excessive_combining_stack"] == 1
    assert report["stats"]["combining_max_stack"] >= 5
    assert decision["action"] == "quarantine"


@pytest.mark.parametrize("norm", ("NFC", "NFKC"))
def test_normalization_cap_stays_a_fixed_point_with_trailing_marks(norm: str) -> None:
    text = "\ufdfa" * 40 + "e\u200b\u0301" + "\u0338" * 20
    clean, report = sanitize(text, policy="strict_exec", normalization=norm)
    assert unicodedata.normalize(norm, clean) == clean
    assert len(clean) <= max(128, len(text) * 8)
    assert sanitize(clean, policy="strict_exec", normalization=norm)[0] == clean
    assert report["stats"]["normalization_truncated"] is (norm == "NFKC")


def test_span_event_limit_errors_instead_of_clipping_report() -> None:
    _, report = sanitize("\u200b" * 10_000, return_spans=True)
    assert len(report["spans"]) == 10_000
    with pytest.raises(ValueError, match="span event limit exceeded"):
        sanitize("\u200b" * 10_001, return_spans=True)
    assert sanitize("\u200b" * 10_001, return_spans=False)[0] == ""
