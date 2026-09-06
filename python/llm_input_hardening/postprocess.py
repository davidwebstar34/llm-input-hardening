from __future__ import annotations

import math
import re
from collections import Counter


_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]+")
_HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")
_ASCII85_FRAME_RE = re.compile(r"<~([!-u\s]{8,})~>")
_BASE85_RUN_RE = re.compile(r"(?<!\w)[!-u]{80,}(?!\w)")
_BINARY_BYTE_RE = re.compile(r"^[01]{8}$")
_MIN_HEX_BYTES = 32
_MIN_ASCII85_CHARS = 64
_MIN_BINARY_BYTES = 32


def hex_blob_format(text: str, *, min_bytes: int = _MIN_HEX_BYTES) -> str | None:
    """Return the detected hex blob shape, if any.

    This is a shape signal only. It does not decode the payload or classify the
    decoded intent. The scan looks for an encoded-looking run *anywhere* in the
    text rather than requiring the whole string to be one clean blob, so a
    payload wrapped in ordinary prose is still visible. The threshold (64 hex
    chars) sits comfortably above a 40-char git SHA and any single UUID field, so
    those do not trip it.
    """

    if not text:
        return None

    # Longest contiguous hex run embedded anywhere in the text.
    longest = max((len(m.group(0)) for m in _HEX_RUN_RE.finditer(text)), default=0)
    if longest >= min_bytes * 2:
        return "contiguous"

    # Longest run of consecutive space-separated hex byte pairs (promptfoo emits
    # this shape). Measured as a run so a couple of stray tokens in a sentence
    # don't hide a long byte sequence elsewhere.
    best = 0
    cur = 0
    for token in text.split():
        if _HEX_BYTE_RE.fullmatch(token):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    if best >= min_bytes:
        return "spaced_bytes"
    return None


def encoded_blob_format(
    text: str,
    *,
    min_ascii85_chars: int = _MIN_ASCII85_CHARS,
    min_binary_bytes: int = _MIN_BINARY_BYTES,
) -> str | None:
    """Return a non-base64/non-hex encoded-blob shape, if present."""

    if not text:
        return None

    framed_chars = 0
    for match in _ASCII85_FRAME_RE.finditer(text):
        framed_chars += sum(1 for ch in match.group(1) if not ch.isspace())
    if framed_chars >= min_ascii85_chars:
        return "ascii85"

    if any(len(match.group(0)) >= min_ascii85_chars for match in _BASE85_RUN_RE.finditer(text)):
        return "base85"

    best = 0
    cur = 0
    for token in text.split():
        if _BINARY_BYTE_RE.fullmatch(token):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    if best >= min_binary_bytes:
        return "binary_bytes"

    return None


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def max_entropy_window(text: str, *, window: int = 256, stride: int = 64) -> float:
    """Compute max entropy over sliding windows (signal only)."""

    if not text:
        return 0.0
    if len(text) <= window:
        return shannon_entropy(text)

    best = 0.0
    stop = len(text) - window + 1
    for i in range(0, stop, stride):
        ent = shannon_entropy(text[i : i + window])
        if ent > best:
            best = ent
    if (len(text) - window) % stride != 0:
        best = max(best, shannon_entropy(text[-window:]))
    return best
