from __future__ import annotations

from typing import Any, Optional, Tuple, cast

from ._service import sanitize_text
from .types import MeterResult, SanitizeReport, TokenMeter


def _fallback_token_estimate(text: str) -> int:
    # A deliberately conservative approximation that scales for unbroken text,
    # CJK, and punctuation too. This is not a model-specific upper bound.
    return len(text.encode("utf-8"))


def _count_tokens(
    text: str,
    model: Optional[str],
    tokenizer: Optional[Any],
    *,
    strict_tokenizer: bool = False,
) -> Tuple[int, str]:
    if tokenizer is not None:
        try:
            enc = tokenizer.encode(text)
            return len(enc.ids), "hf_tokenizers:custom"
        except Exception as exc:
            if strict_tokenizer:
                raise ValueError(
                    "the supplied tokenizer could not encode the text"
                ) from exc

    try:
        import tiktoken

        if model:
            enc = tiktoken.encoding_for_model(model)
            return len(
                enc.encode(text, disallowed_special=())
            ), f"tiktoken:model:{model}"
        enc = tiktoken.get_encoding("o200k_base")
        return len(enc.encode(text, disallowed_special=())), "tiktoken:o200k_base"
    except Exception as exc:
        if strict_tokenizer:
            raise ValueError(
                "token counting requires an available tokenizer and a supported model; "
                "install tiktoken or supply a tokenizer"
            ) from exc
        return _fallback_token_estimate(text), "fallback:utf8_byte_estimate"


def meter(
    text: str,
    *,
    model: Optional[str] = None,
    limit_tokens: Optional[int] = None,
    reserved_output_tokens: int = 512,
    policy: str = "balanced_chat",
    tokenizer: Optional[Any] = None,
    sanitized: tuple[str, SanitizeReport] | None = None,
    strict_tokenizer: bool = False,
) -> MeterResult:
    """Estimate token usage before/after sanitization.

    This measures usage; callers must enforce any context window budget. The meter:
    - counts tokens on the original input
    - sanitizes the text (via `sanitize()`)
    - counts tokens again on the sanitized output

    Token counting strategy:
    1) If `tokenizer` is provided, it is used first.
    2) Else if `tiktoken` is installed, it is used (optionally with `model`).
    3) Else a rough fallback heuristic is used.

    Args:
        text: Input text to sanitize and measure.
        model: Optional model name for `tiktoken.encoding_for_model`.
        limit_tokens: Optional context window size for measurement, not enforcement.
        reserved_output_tokens: Tokens reserved for the model’s response.
        policy: Sanitization policy (`"preserve"`, `"balanced_chat"`, `"strict_exec"`, `"code_mode"`).
        tokenizer: Optional HuggingFace `tokenizers.Tokenizer`-like object.
        sanitized: Optional `(clean_text, report)` to reuse a prior `sanitize()` result.
        strict_tokenizer: Raise on tokenizer failure or unavailability instead of
            using the conservative UTF-8 byte estimate. Select the correct model
            or supply its tokenizer when enforcing a budget.

    Returns:
        A dict containing the sanitize report and token counts before/after.
    """
    if limit_tokens is not None and (
        isinstance(limit_tokens, bool)
        or not isinstance(limit_tokens, int)
        or limit_tokens <= 0
    ):
        raise ValueError("limit_tokens must be a positive integer")
    if (
        isinstance(reserved_output_tokens, bool)
        or not isinstance(reserved_output_tokens, int)
        or reserved_output_tokens < 0
    ):
        raise ValueError("reserved_output_tokens must be a nonnegative integer")
    if sanitized is None:
        cleaned, srep = sanitize_text(text, policy=policy)
    else:
        cleaned, srep = sanitized
    # Apply sanitizer resource limits before potentially expensive tokenization.
    before_tokens, before_label = _count_tokens(
        text, model, tokenizer, strict_tokenizer=strict_tokenizer
    )
    after_tokens, after_label = _count_tokens(
        cleaned, model, tokenizer, strict_tokenizer=strict_tokenizer
    )

    def mk(tokens: int, label: str) -> TokenMeter:
        if limit_tokens is not None:
            avail = max(0, limit_tokens - tokens - reserved_output_tokens)
            pct = (tokens / limit_tokens) * 100.0 if limit_tokens else None
        else:
            avail, pct = None, None
        return {
            "tokenizer": label,
            "estimated": label.startswith("fallback:"),
            "input_tokens": tokens,
            "limit_tokens": limit_tokens,
            "reserved_output_tokens": reserved_output_tokens,
            "available_tokens": avail,
            "percent_used": pct,
        }

    return cast(
        MeterResult,
        {
            "sanitize": srep,
            "tokens_before": mk(before_tokens, before_label),
            "tokens_after": mk(after_tokens, after_label),
        },
    )
