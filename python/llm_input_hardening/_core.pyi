"""Type stub for the compiled Rust extension module `_core`.

The primary exported entrypoint is `sanitize`. Prefer the high-level
`llm_input_hardening.sanitize` wrapper, which decorates this report with the
Python-side signals (hex, sliding-window entropy, confusables).
"""

from typing import Any

def sanitize(
    text: str,
    policy: str = ...,
    normalization: str | None = ...,
    tidy_whitespace: bool | None = ...,
    return_spans: bool = ...,
) -> tuple[str, dict[str, Any]]:
    """Sanitize `text` under a named policy, returning `(clean_text, report)`."""
    ...

def normalize_for_skeleton(text: str, max_chars: int = ...) -> str:
    """Native bounded NFKC; raise on overflow instead of returning partial identity."""
    ...

def is_identifier_decoration(ch: str) -> bool:
    """Share the core Unicode mark/default-ignorable classification."""
    ...

def encoded_codepoint_risk(ch: str, policy: str) -> str | None:
    """Classify an encoded scalar using the core policy and Unicode tables."""
    ...
