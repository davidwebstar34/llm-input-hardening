from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from collections.abc import Iterator
from typing import Any, TypedDict


class ConfusableSignal(TypedDict):
    """Best-effort confusable/homoglyph signal for one text sample."""

    backend: str
    available: bool
    mixed_script: bool
    dangerous: bool
    restriction_level: str
    script_set: list[str]
    skeleton_stored: bool
    skeleton: str | None
    confusable_count: int
    mixed_word_count: int
    mixed_words: list[str]
    whole_script: bool
    whole_script_word_count: int
    whole_script_words: list[str]
    whole_script_actionable: bool
    error: str | None


_BACKEND_ALIASES = {
    "heuristic": "heuristic",
    "confusable-homoglyphs": "confusable_homoglyphs",
    "confusable_homoglyphs": "confusable_homoglyphs",
    "homoglyphs": "confusable_homoglyphs",
}
_PREFERRED_ALIASES = ["LATIN"]
_MAX_SAMPLE_CHARS = 160
_MAX_SKELETON_CHARS = 4096

# Scripts whose letters are visually confusable with each other. Mixing these
# within one word is the homoglyph attack shape (e.g. Cyrillic "р" in "раypal").
# CJK scripts are deliberately excluded: Han+Hiragana+Katakana words are normal
# Japanese orthography, and Latin mixes freely into CJK words ("Tシャツ", "T恤").
_CONFUSABLE_SCRIPTS = frozenset(
    {"LATIN", "CYRILLIC", "GREEK", "CHEROKEE", "ARMENIAN", "COPTIC"}
)

_SCRIPT_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x0041, 0x005A, "LATIN"),
    (0x0061, 0x007A, "LATIN"),
    (0x00C0, 0x00FF, "LATIN"),
    (0x0100, 0x024F, "LATIN"),
    (0x0250, 0x02AF, "LATIN"),
    (0x0370, 0x03FF, "GREEK"),
    (0x0400, 0x052F, "CYRILLIC"),
    (0x0531, 0x058F, "ARMENIAN"),
    (0x0590, 0x05FF, "HEBREW"),
    (0x0600, 0x06FF, "ARABIC"),
    (0x0700, 0x074F, "SYRIAC"),
    (0x0750, 0x077F, "ARABIC"),
    (0x0900, 0x097F, "DEVANAGARI"),
    (0x0E00, 0x0E7F, "THAI"),
    (0x1100, 0x11FF, "HANGUL"),
    (0x13A0, 0x13FF, "CHEROKEE"),
    (0x1D00, 0x1D7F, "LATIN"),
    (0x1D80, 0x1DBF, "LATIN"),
    (0x1E00, 0x1EFF, "LATIN"),
    (0x1F00, 0x1FFF, "GREEK"),
    (0x2C60, 0x2C7F, "LATIN"),
    (0x2C80, 0x2CFF, "COPTIC"),
    (0x3040, 0x309F, "HIRAGANA"),
    (0x30A0, 0x30FF, "KATAKANA"),
    (0x3100, 0x312F, "BOPOMOFO"),
    (0x31A0, 0x31BF, "BOPOMOFO"),
    (0x3400, 0x4DBF, "HAN"),
    (0x4E00, 0x9FFF, "HAN"),
    (0xAB30, 0xAB6F, "LATIN"),
    (0xAB70, 0xABBF, "CHEROKEE"),
    (0xAC00, 0xD7AF, "HANGUL"),
    (0xF900, 0xFAFF, "HAN"),
    (0xFF21, 0xFF3A, "LATIN"),
    (0xFF41, 0xFF5A, "LATIN"),
    (0x1D400, 0x1D7CB, "LATIN"),
    (0x20000, 0x2A6DF, "HAN"),
    (0x2A700, 0x2B73F, "HAN"),
    (0x2B740, 0x2B81F, "HAN"),
    (0x2B820, 0x2CEAF, "HAN"),
    (0x2CEB0, 0x2EBEF, "HAN"),
    (0x30000, 0x3134F, "HAN"),
    (0x31350, 0x323AF, "HAN"),
)
_SCRIPT_STARTS = tuple(start for start, _, _ in _SCRIPT_RANGES)

# Curated confusable -> Latin prototype map, in the spirit of a UTS #39 skeleton
# but scoped to the Cyrillic/Greek letters that are visually identical to Latin
# (the scripts this library treats as mutually confusable). Two strings that are
# homoglyph spoofs of each other collapse to the same skeleton, so a caller can
# compare `skeleton` against a trusted term ("paypal") to detect impersonation.
_CONFUSABLE_TO_LATIN: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ј": "j",
    "ѕ": "s", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I",
    "Ј": "J", "Ѕ": "S", "г": "r", "п": "n", "ӏ": "l", "Ӏ": "I",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Cherokee (single-codepoint Latin prototypes from the UTS #39 data)
    "Ꭰ": "D", "Ꭱ": "R", "Ꭲ": "T", "Ꭵ": "i", "Ꭹ": "Y", "Ꭺ": "A",
    "Ꭻ": "J", "Ꭼ": "E", "Ꮃ": "W", "Ꮇ": "M", "Ꮋ": "H", "Ꮍ": "Y",
    "Ꮐ": "G", "Ꮒ": "h", "Ꮓ": "Z", "Ꮟ": "b", "Ꮢ": "R", "Ꮤ": "W",
    "Ꮥ": "S", "Ꮩ": "V", "Ꮪ": "S", "Ꮮ": "L", "Ꮯ": "C", "Ꮲ": "P",
    "Ꮶ": "K", "Ꮷ": "d", "Ᏻ": "G", "Ᏼ": "B",
    # Armenian
    "Ս": "U", "Տ": "S", "Օ": "O", "ա": "w", "գ": "q", "զ": "q",
    "հ": "h", "ո": "n", "ռ": "n", "ս": "u", "ց": "g", "ք": "f",
    "օ": "o",
    # Coptic
    "ⲅ": "r", "Ⲏ": "H", "Ⲓ": "l", "Ⲕ": "K", "Ⲙ": "M", "Ⲛ": "N",
    "Ⲟ": "O", "ⲟ": "o", "Ⲣ": "P", "ⲣ": "p", "Ⲥ": "C", "ⲥ": "c",
    "Ⲧ": "T", "Ⲩ": "Y", "Ⲭ": "X", "Ⳑ": "L",
}


def confusable_skeleton(text: str) -> str:
    """Fold to a Latin skeleton with native NFKC and bounded identity output.

    Raises ValueError above one million input or normalized characters. Never
    returns a truncated identity, and does not use quadratic Python reordering.
    """
    from ._core import normalize_for_skeleton

    normalized = normalize_for_skeleton(text)
    return "".join(_CONFUSABLE_TO_LATIN.get(ch, ch) for ch in normalized)


def _is_styled_compatibility_char(ch: str) -> bool:
    if ord(ch) < 128:
        return False
    normalized = unicodedata.normalize("NFKC", ch)
    if normalized != ch and normalized.isascii() and any(
        folded.isalnum() for folded in normalized
    ):
        return True
    name = unicodedata.name(ch, "")
    return (
        name.startswith("LATIN LETTER SMALL CAPITAL")
        or "MODIFIER LETTER SMALL CAPITAL" in name
    )


def detect_styled_compatibility_tokens(text: str) -> list[str]:
    """Return sample tokens containing styled letters or compatibility digits."""

    words: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if not current:
            return
        token = "".join(current)
        if any(_is_styled_compatibility_char(ch) for ch in token):
            words.append(token)
        current.clear()

    for ch in text:
        if ch.isalnum() or _is_styled_compatibility_char(ch):
            current.append(ch)
        else:
            flush()
    flush()
    return [word[:_MAX_SAMPLE_CHARS] for word in words[:8]]


def detect_styled_latin_words(text: str) -> list[str]:
    """Backward-compatible alias for styled compatibility-token detection."""

    return detect_styled_compatibility_tokens(text)


def _normalized_backend(name: str) -> str:
    backend = _BACKEND_ALIASES.get(name, name)
    if backend not in {"heuristic", "confusable_homoglyphs"}:
        raise ValueError(
            f"unknown confusables backend: {name}. "
            "Supported backends: heuristic, confusable_homoglyphs"
        )
    return backend


def _script_alias(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    cp = ord(ch)
    idx = bisect_right(_SCRIPT_STARTS, cp) - 1
    if idx >= 0:
        start, end, script = _SCRIPT_RANGES[idx]
        if start <= cp <= end:
            return script
    return None


def _identifier_tokens(text: str) -> Iterator[tuple[str, str]]:
    """Yield original tokens and a mark/format-free view for script analysis.

    Digits and connector punctuation continue an identifier. Combining marks
    and format characters decorate a token rather than establish a new word.
    The caller's text and diagnostic samples retain every original character.
    """
    from ._core import is_identifier_decoration

    current: list[str] = []
    view: list[str] = []
    for ch in text:
        category = unicodedata.category(ch)
        decoration = not ch.isascii() and (
            category == "Cf" or is_identifier_decoration(ch)
        )
        if ch.isalnum() or category == "Pc" or decoration:
            current.append(ch)
            if not decoration:
                view.append(ch)
        elif current:
            yield "".join(current), "".join(view)
            current.clear()
            view.clear()
    if current:
        yield "".join(current), "".join(view)


def _detect_mixed_script_words(text: str) -> list[str]:
    words: list[str] = []
    for token, view in _identifier_tokens(text):
        scripts = {_script_alias(ch) for ch in view}
        scripts.discard(None)
        if len(scripts & _CONFUSABLE_SCRIPTS) >= 2:
            words.append(token)
    return words


def _detect_whole_script_confusable_words(text: str) -> list[str]:
    words: list[str] = []
    for token, view in _identifier_tokens(text):
        scripts = {_script_alias(ch) for ch in view}
        scripts.discard(None)
        if (
            sum(ch.isalpha() for ch in view) >= 3
            and len(scripts) == 1
            and "LATIN" not in scripts
            and scripts.issubset(_CONFUSABLE_SCRIPTS)
        ):
            skeleton = confusable_skeleton(view)
            if skeleton != view and all(
                (ch.isascii() and ch.isalpha())
                or ch.isnumeric()
                or unicodedata.category(ch) == "Pc"
                for ch in skeleton
            ):
                words.append(token)
    # Observation is independent of enforcement: native prose may contain
    # confusable words, but that must not hide them from execution policies.
    return words


_ASCII_LETTER_RE = re.compile(r"[A-Za-z]")


def _script_set(text: str) -> set[str]:
    if text.isascii():
        return {"LATIN"} if _ASCII_LETTER_RE.search(text) else set()
    scripts = set()
    for ch in text:
        alias = _script_alias(ch)
        if alias:
            scripts.add(alias)
    return scripts


def _restriction_level(text: str) -> tuple[str, list[str]]:
    scripts = _script_set(text)
    script_list = sorted(scripts)
    ascii_only = bool(text) and text.isascii()
    if ascii_only:
        return "ASCII_ONLY", script_list
    if len(scripts) <= 1:
        return "SINGLE_SCRIPT_RESTRICTIVE", script_list
    # UTS #39-aligned naming; this is heuristic classification, not a full spoof checker.
    highly = {"LATIN", "HAN", "HIRAGANA", "KATAKANA"}
    moderate = highly | {"BOPOMOFO", "HANGUL"}
    if scripts.issubset(highly):
        return "HIGHLY_RESTRICTIVE", script_list
    if scripts.issubset(moderate):
        return "MODERATELY_RESTRICTIVE", script_list
    if scripts == {"LATIN", "GREEK"} or scripts == {"LATIN", "CYRILLIC"}:
        return "UNRESTRICTIVE", script_list
    return "MINIMALLY_RESTRICTIVE", script_list


def detect_confusables(text: str, *, backend: str = "heuristic") -> ConfusableSignal:
    """Detect mixed- and whole-script confusables with optional enrichment."""

    backend = _normalized_backend(backend)
    # Pure-ASCII text cannot mix scripts; skip the per-character name lookups.
    mixed_words = [] if text.isascii() else _detect_mixed_script_words(text)
    whole_script_words = (
        [] if text.isascii() else _detect_whole_script_confusable_words(text)
    )
    heuristic_mixed = bool(mixed_words)
    heuristic_whole_script = bool(whole_script_words)
    heuristic_dangerous = heuristic_mixed or heuristic_whole_script
    restriction_level, script_set = _restriction_level(text)
    candidates = set(whole_script_words)
    native_words = sum(
        1 for token, view in _identifier_tokens(text)
        if sum(ch.isalpha() for ch in view) >= 3 and token not in candidates
    )
    # A token or one-letter suffix is not evidence of native prose. This remains
    # a chat-only severity heuristic; observations and strict decisions survive.
    native_context = (
        len(script_set) == 1 and "LATIN" not in script_set
        and native_words >= 3 and native_words > len(whole_script_words)
    )
    whole_script_actionable = heuristic_whole_script and not native_context
    # Store a skeleton only when the text actually looks confusable, so benign
    # text doesn't carry a redundant copy of itself in the report.
    skeleton = (
        confusable_skeleton(text)
        if heuristic_dangerous and len(text) <= _MAX_SKELETON_CHARS
        else None
    )
    if skeleton is not None and len(skeleton) > _MAX_SKELETON_CHARS:
        skeleton = None
    if backend == "heuristic":
        return {
            "backend": backend,
            "available": True,
            "mixed_script": heuristic_mixed,
            "dangerous": heuristic_dangerous,
            "restriction_level": restriction_level,
            "script_set": script_set,
            "skeleton_stored": skeleton is not None,
            "skeleton": skeleton,
            "confusable_count": len(mixed_words),
            "mixed_word_count": len(mixed_words),
            "mixed_words": [word[:_MAX_SAMPLE_CHARS] for word in mixed_words[:8]],
            "whole_script": heuristic_whole_script,
            "whole_script_word_count": len(whole_script_words),
            "whole_script_words": [word[:_MAX_SAMPLE_CHARS] for word in whole_script_words[:8]],
            "whole_script_actionable": whole_script_actionable,
            "error": None,
        }

    try:
        from confusable_homoglyphs import confusables
    except Exception as exc:
        return {
            "backend": backend,
            "available": False,
            "mixed_script": heuristic_mixed,
            "dangerous": heuristic_dangerous,
            "restriction_level": restriction_level,
            "script_set": script_set,
            "skeleton_stored": skeleton is not None,
            "skeleton": skeleton,
            "confusable_count": 0,
            "mixed_word_count": len(mixed_words),
            "mixed_words": [word[:_MAX_SAMPLE_CHARS] for word in mixed_words[:8]],
            "whole_script": heuristic_whole_script,
            "whole_script_word_count": len(whole_script_words),
            "whole_script_words": [word[:_MAX_SAMPLE_CHARS] for word in whole_script_words[:8]],
            "whole_script_actionable": whole_script_actionable,
            "error": str(exc),
        }

    try:
        # Use exactly the same token boundaries as the heuristic. Marks and
        # joiners must not make the optional backend inspect smaller fragments.
        mixed = heuristic_mixed
        dangerous = heuristic_dangerous
        count = 0
        for _original, token in _identifier_tokens(text):
            if not token or token.isascii():
                continue
            token_mixed = bool(confusables.is_mixed_script(token))
            details: Any = confusables.is_confusable(
                token, preferred_aliases=_PREFERRED_ALIASES
            )
            token_count = len(details) if isinstance(details, list) else 0
            mixed |= token_mixed
            dangerous |= token_mixed and token_count > 0
            count += token_count
        return {
            "backend": backend,
            "available": True,
            "mixed_script": mixed,
            "dangerous": dangerous,
            "restriction_level": restriction_level,
            "script_set": script_set,
            "skeleton_stored": skeleton is not None,
            "skeleton": skeleton,
            "confusable_count": max(count, len(mixed_words)),
            "mixed_word_count": len(mixed_words),
            "mixed_words": [word[:_MAX_SAMPLE_CHARS] for word in mixed_words[:8]],
            "whole_script": heuristic_whole_script,
            "whole_script_word_count": len(whole_script_words),
            "whole_script_words": [word[:_MAX_SAMPLE_CHARS] for word in whole_script_words[:8]],
            "whole_script_actionable": whole_script_actionable,
            "error": None,
        }
    except Exception as exc:
        return {
            "backend": backend,
            "available": True,
            "mixed_script": heuristic_mixed,
            "dangerous": heuristic_dangerous,
            "restriction_level": restriction_level,
            "script_set": script_set,
            "skeleton_stored": skeleton is not None,
            "skeleton": skeleton,
            "confusable_count": 0,
            "mixed_word_count": len(mixed_words),
            "mixed_words": [word[:_MAX_SAMPLE_CHARS] for word in mixed_words[:8]],
            "whole_script": heuristic_whole_script,
            "whole_script_word_count": len(whole_script_words),
            "whole_script_words": [word[:_MAX_SAMPLE_CHARS] for word in whole_script_words[:8]],
            "whole_script_actionable": whole_script_actionable,
            "error": str(exc),
        }
