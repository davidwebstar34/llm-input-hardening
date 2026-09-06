"""Seeded interaction coverage supplements individual attack regressions."""

from __future__ import annotations

import random
import unicodedata

import pytest

from llm_input_hardening import sanitize


@pytest.mark.parametrize("policy", ["preserve", "balanced_chat", "strict_exec", "code_mode"])
def test_composed_rules_preserve_determinism_bounds_and_fixed_points(policy: str) -> None:
    rng = random.Random(20260905)
    fragments = [
        "a", "B", "1", " ", "\t", "\n", "\r", "\x00", "\x1b", "\x7f",
        "\u202e", "\u200b", "\u200d", "\u2060", "\u0301", "\u0315",
        "\u07eb", "\U0001e944", "\u180b", "\ufe0f", "\U000e0100",
        "\U000e0061", "\U000e007f", "раypal", "a_а", "\ufdfa", "\u212b",
        "\u1100", "\u1161", "✈️", "שָׁלוֹם", "नमस्ते", "ᠠ᠋", "木\U000e0100",
    ]
    norm = "NFKC" if policy == "strict_exec" else "NFC"
    for _ in range(256):
        text = "".join(rng.choices(fragments, k=rng.randrange(1, 65)))
        result = sanitize(text, policy=policy, return_spans=True)
        clean, report = result
        assert sanitize(text, policy=policy, return_spans=True) == result
        assert sanitize(clean, policy=policy)[0] == clean
        assert unicodedata.normalize(norm, clean) == clean
        assert len(clean) <= max(128, len(text) * 8)
        assert report["changed"] is (clean != text)
        assert len(report["spans"]) <= 10_000
        scanned_bytes = unicodedata.normalize(norm, text).encode("utf-8")
        for span in report["spans"]:
            assert 0 <= span["start"] < span["end"] <= len(scanned_bytes)
            # Offsets must remain actual UTF-8 boundaries.
            scanned_bytes[span["start"]:span["end"]].decode("utf-8")


@pytest.mark.parametrize("text", ["\ud800", "text\udfff", "\ud800\udc00"])
def test_invalid_unicode_never_returns_a_partial_result(text: str) -> None:
    with pytest.raises((UnicodeError, ValueError)):
        sanitize(text)
