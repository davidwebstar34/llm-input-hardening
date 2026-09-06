from __future__ import annotations

import builtins
import sys
from types import SimpleNamespace

import pytest

from llm_input_hardening import meter, sanitize


class _Encoded:
    def __init__(self, text: str):
        self.ids = list(text)


class _Tokenizer:
    def encode(self, text: str) -> _Encoded:
        return _Encoded(text)


def test_meter_reports_before_after_counts() -> None:
    result = meter(
        "abc\u202edef",
        limit_tokens=32,
        reserved_output_tokens=4,
        policy="balanced_chat",
        tokenizer=_Tokenizer(),
    )
    assert result["sanitize"]["changed"] is True
    assert result["tokens_before"]["input_tokens"] == 7
    assert result["tokens_after"]["input_tokens"] == 6
    assert result["tokens_after"]["available_tokens"] == 22


def test_meter_reuses_precomputed_sanitize_result() -> None:
    sanitized = sanitize("x\u200dy", policy="code_mode")
    result = meter(
        "x\u200dy",
        policy="code_mode",
        tokenizer=_Tokenizer(),
        sanitized=sanitized,
    )
    assert result["sanitize"] is sanitized[1]
    assert result["tokens_after"]["input_tokens"] == 2


def test_meter_surfaces_fallback_estimator(monkeypatch) -> None:
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "tiktoken":
            raise ModuleNotFoundError("No module named 'tiktoken'", name="tiktoken")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    result = meter("hello world", policy="balanced_chat")
    assert result["tokens_before"]["tokenizer"] == "fallback:utf8_byte_estimate"
    assert result["tokens_before"]["estimated"] is True
    assert result["tokens_after"]["estimated"] is True


@pytest.mark.parametrize(
    "text",
    ["a" * 100_000, "漢字" * 50_000, "!" * 100_000],
    ids=["ascii-100k", "cjk-100k", "punctuation-100k"],
)
def test_fallback_scales_with_unbroken_input(monkeypatch, text: str) -> None:
    monkeypatch.setitem(sys.modules, "tiktoken", None)
    result = meter(text)
    assert result["tokens_before"]["input_tokens"] == len(text.encode("utf-8"))
    assert result["tokens_before"]["estimated"] is True


def test_strict_tokenizer_requires_available_tokenizer(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "tiktoken", None)
    with pytest.raises(ValueError, match="available tokenizer"):
        meter("hello", strict_tokenizer=True)


def test_strict_tokenizer_preserves_custom_failure() -> None:
    class BrokenTokenizer:
        def encode(self, text):
            raise RuntimeError("encoding failed")

    with pytest.raises(ValueError, match="supplied tokenizer") as error:
        meter("hello", tokenizer=BrokenTokenizer(), strict_tokenizer=True)
    assert isinstance(error.value.__cause__, RuntimeError)


def test_literal_special_token_text_does_not_trigger_fallback(monkeypatch) -> None:
    class Encoding:
        def encode(self, text, *, disallowed_special):
            assert text == "<|endoftext|>"
            assert disallowed_special == ()
            return [1, 2, 3]

    monkeypatch.setitem(
        sys.modules, "tiktoken", SimpleNamespace(get_encoding=lambda _: Encoding())
    )
    result = meter("<|endoftext|>", strict_tokenizer=True)
    assert result["tokens_before"]["input_tokens"] == 3
    assert result["tokens_before"]["estimated"] is False


def test_strict_tokenizer_rejects_unknown_model(monkeypatch) -> None:
    def unknown_model(_):
        raise KeyError("unknown model")

    monkeypatch.setitem(
        sys.modules, "tiktoken", SimpleNamespace(encoding_for_model=unknown_model)
    )
    with pytest.raises(ValueError, match="supported model"):
        meter("hello", model="unknown", strict_tokenizer=True)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_meter_rejects_invalid_limit(limit) -> None:
    with pytest.raises(ValueError, match="limit_tokens"):
        meter("hello", limit_tokens=limit)


def test_limit_tokens_measures_without_rejecting_text() -> None:
    result = meter("a" * 100, tokenizer=_Tokenizer(), limit_tokens=10)
    assert result["tokens_after"]["input_tokens"] == 100
    assert result["tokens_after"]["available_tokens"] == 0
