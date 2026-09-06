"""Bounded, non-mutating inspection of escaped Unicode, not a document parser.

Only candidate views are decoded. Callers must still parse the actual input
format before hardening and inspect again after any later decoding operation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html import unescape
import re

from ._core import encoded_codepoint_risk
from .types import EncodedUnicodeSample

MAX_DECODE_DEPTH = 3
MAX_CANDIDATES = 4096
MAX_CANDIDATE_CHARS = 65536
MAX_SAMPLES = 8

# Each alternative is linear, has a distinct prefix, and consumes complete
# numeric/percent runs. Bounded names also cover HTML's semicolonless aliases.
_ESCAPE = re.compile(
    r"(?P<html>&(?:\#[xX][0-9a-fA-F]+;?|\#[0-9]+;?|[A-Za-z][A-Za-z0-9]{0,31};?))"
    r"|(?P<unicode>\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}"
    r"|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})"
    r"|(?P<percent>(?:%[0-9a-fA-F]{2})+)"
)
_FORMATS = {"html": "html_entity", "unicode": "unicode_escape", "percent": "percent_utf8"}


@dataclass(frozen=True)
class _Edit:
    start: int
    end: int
    out_start: int
    out_end: int
    encoding: str


@dataclass
class EncodedUnicodeInspection:
    count: int = 0
    candidates: int = 0
    candidate_chars: int = 0
    depth: int = 0
    limit: str | None = None
    samples: list[EncodedUnicodeSample] = field(default_factory=list)


def _decode(token: str, kind: str) -> tuple[str, str]:
    """Return the candidate replacement and scalars to inspect for risk.

    HTML5 drops/remaps some control references. Inspect their numeric target as
    well, without depending on a downstream parser making the same correction.
    No arbitrary Python escape evaluation or Latin-1 guessing takes place.
    """
    if kind == "html":
        target = ""
        if token.startswith("&#"):
            digits = token[2:].rstrip(";")
            base = 16 if digits[:1] in ("x", "X") else 10
            digits = (digits[1:] if base == 16 else digits).lstrip("0") or "0"
            # Avoid Python's integer digit limit and unbounded big integers.
            cp = int(digits, base) if len(digits) <= (6 if base == 16 else 7) else 0x110000
            if cp <= 0x10FFFF:
                target = chr(cp)
            token = f"&#{cp};"
        decoded = unescape(token)
        return decoded, target or decoded
    if kind == "unicode":
        cp = int(token[2:6] if token[1] == "u" else token[2:10], 16)
        if len(token) == 12:
            cp = 0x10000 + ((cp - 0xD800) << 10) + int(token[8:12], 16) - 0xDC00
        decoded = chr(cp) if cp <= 0x10FFFF else "\ufffd"
        return decoded, decoded
    # Keep undecodable bytes encoded: a different escape in this round may
    # produce their missing UTF-8 prefix (e.g. \\u0025E2%80%AE). Replacing them
    # would erase a candidate before the next round can inspect it. Valid UTF-8
    # alongside malformed bytes is still inspected. No %uXXXX or form '+' rules.
    decoded = bytes.fromhex(token.replace("%", "")).decode("utf-8", errors="surrogateescape")
    chunks: list[str] = []
    targets: list[str] = []
    byte_offset = 0
    for ch in decoded:
        if 0xDC80 <= ord(ch) <= 0xDCFF:
            chunks.append(token[byte_offset * 3:byte_offset * 3 + 3])
            byte_offset += 1
        else:
            chunks.append(ch)
            targets.append(ch)
            byte_offset += len(ch.encode("utf-8"))
    return "".join(chunks), "".join(targets)


def _origin(start: int, end: int, layers: list[list[_Edit]], encoding: str) -> tuple[int, int, list[str]]:
    """Trace a sampled candidate through shrinking views using sparse edits."""
    formats = {encoding}
    for edits in reversed(layers):
        left, right = start, end
        for edit in edits:
            delta = (edit.end - edit.start) - (edit.out_end - edit.out_start)
            if edit.out_end <= start:
                left += delta
            elif edit.out_start <= start < edit.out_end:
                left = edit.start
            if edit.out_end <= end:
                right += delta
            elif edit.out_start < end < edit.out_end:
                right = edit.end
            if edit.out_start < end and edit.out_end > start:
                formats.add(edit.encoding)
        start, end = left, right
    return start, end, sorted(formats)


def inspect_encoded_unicode(text: str, policy: str) -> EncodedUnicodeInspection:
    """Inspect up to three decoding layers with fixed work and evidence budgets.

    Sample offsets are Python character indices in ``text``, not core byte
    spans. Counts refer to risky scalars discovered in candidate replacements.
    Surrogates are flagged without passing invalid scalars through PyO3.
    """
    result = EncodedUnicodeInspection()
    if not any(prefix in text for prefix in ("&", "\\", "%")):
        return result
    view = text
    layers: list[list[_Edit]] = []
    risk_cache: dict[str, str | None] = {}
    for depth in range(1, MAX_DECODE_DEPTH + 2):
        chunks: list[str] = []
        edits: list[_Edit] = []
        previous = 0
        output_len = 0
        for match in _ESCAPE.finditer(view):
            token = match.group()
            if result.candidates >= MAX_CANDIDATES:
                result.limit = "candidates"
                return result
            if result.candidate_chars + len(token) > MAX_CANDIDATE_CHARS:
                result.limit = "candidate_chars"
                return result
            result.candidates += 1
            result.candidate_chars += len(token)
            kind = match.lastgroup
            assert kind is not None
            decoded, targets = _decode(token, kind)
            if decoded == token:
                continue
            if depth > MAX_DECODE_DEPTH:
                result.limit = "decode_depth"
                return result
            result.depth = depth
            encoding = _FORMATS[kind]
            codepoints: list[str] = []
            reasons: set[str] = set()
            for ch in targets:
                if ch not in risk_cache:
                    risk_cache[ch] = (
                        "invalid_unicode_scalar" if 0xD800 <= ord(ch) <= 0xDFFF
                        else encoded_codepoint_risk(ch, policy)
                    )
                reason = risk_cache[ch]
                if reason:
                    result.count += 1
                    if len(codepoints) < MAX_SAMPLES:
                        codepoints.append(f"U+{ord(ch):04X}")
                    reasons.add(reason)
            if reasons and len(result.samples) < MAX_SAMPLES:
                start, end, formats = _origin(match.start(), match.end(), layers, encoding)
                result.samples.append({
                    "start": start, "end": end, "encodings": formats,
                    "decode_depth": depth, "codepoints": codepoints,
                    "reasons": sorted(reasons), "source": "input",
                })
            copied = view[previous:match.start()]
            chunks.extend((copied, decoded))
            output_len += len(copied)
            edits.append(_Edit(match.start(), match.end(), output_len, output_len + len(decoded), encoding))
            output_len += len(decoded)
            previous = match.end()
        if not edits:
            return result
        chunks.append(view[previous:])
        view = "".join(chunks)
        layers.append(edits)
    return result
