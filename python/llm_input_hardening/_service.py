from __future__ import annotations

from typing import cast

from .confusables import detect_confusables, detect_styled_compatibility_tokens
try:
    from ._core import sanitize as _sanitize_core
except ModuleNotFoundError as exc:  # pragma: no cover - import-time guard
    if exc.name == "llm_input_hardening._core":
        raise ModuleNotFoundError(
            "llm_input_hardening._core is missing. "
            "Build it with: `uv run maturin develop --release`."
        ) from exc
    raise
from .encoded_unicode import MAX_SAMPLES, inspect_encoded_unicode
from .policies import resolve_policy_name, signal_thresholds
from .postprocess import encoded_blob_format, hex_blob_format, max_entropy_window
from .reason_codes import reason_code_counts
from .types import SanitizeReport

DEFAULT_MAX_INPUT_CHARS = 1_000_000


def _sanitize_stage(
    text: str,
    policy: str = "balanced_chat",
    *,
    return_spans: bool = False,
    normalization: str | None = None,
    tidy_whitespace: bool | None = None,
    confusables_backend: str | None = None,
) -> tuple[str, SanitizeReport]:
    """Sanitize untrusted text for safer prompt embedding."""

    canonical_policy = resolve_policy_name(policy)
    clean, report = _sanitize_core(
        text,
        canonical_policy,
        normalization,
        tidy_whitespace,
        return_spans,
    )
    if "report_version" not in report:
        report["report_version"] = 1

    report["policy"] = canonical_policy
    stats = report.setdefault("stats", {})
    removed = report.setdefault("removed_counts", {})
    flagged = report.setdefault("flagged_counts", {})
    sig = signal_thresholds()

    hex_format = hex_blob_format(clean, min_bytes=int(sig["hex_min_bytes"]))
    stats["hexish"] = hex_format is not None
    stats["hex_format"] = hex_format
    if hex_format is not None:
        flagged["hex_blob"] = int(flagged.get("hex_blob", 0)) + 1
        # A hex blob also matches the base64 alphabet; the core sets that flag
        # at most once per call, so drop it in favor of the more specific signal.
        flagged.pop("base64ish_blob", None)

    encoded_format = None
    if hex_format is None and int(flagged.get("base64ish_blob", 0)) == 0:
        encoded_format = encoded_blob_format(clean)
    stats["encoded_blob"] = encoded_format is not None
    stats["encoded_blob_format"] = encoded_format
    if encoded_format is not None:
        flagged["encoded_blob"] = int(flagged.get("encoded_blob", 0)) + 1

    ent_max = max_entropy_window(
        clean,
        window=int(sig["entropy_window_chars"]),
        stride=int(sig["entropy_window_stride"]),
    )
    stats["entropy_window_max"] = ent_max
    if (
        ent_max > sig["entropy_window_threshold"]
        and len(clean) >= int(sig["entropy_window_min_chars"])
        and int(flagged.get("high_entropy", 0)) == 0
    ):
        flagged["high_entropy"] = 1

    backend = confusables_backend
    if backend is None:
        backend = "confusable_homoglyphs" if canonical_policy == "code_mode" else "heuristic"
    signal = detect_confusables(clean, backend=backend)
    if clean != text:
        # Normalization/removal can hide the spelling that the caller supplied.
        # Keep original observations even when the returned text is plain ASCII.
        original_signal = detect_confusables(text, backend=backend)
        for key in ("mixed_script", "dangerous", "whole_script", "whole_script_actionable"):
            signal[key] = signal[key] or original_signal[key]
        for key in ("confusable_count", "mixed_word_count", "whole_script_word_count"):
            signal[key] = max(signal[key], original_signal[key])
        for key in ("mixed_words", "whole_script_words"):
            signal[key] = list(dict.fromkeys([*original_signal[key], *signal[key]]))[:8]
        signal["script_set"] = sorted(set(signal["script_set"]) | set(original_signal["script_set"]))
        if original_signal["skeleton"] is not None:
            signal["skeleton"] = original_signal["skeleton"]
            signal["skeleton_stored"] = True
    stats["confusables_backend"] = signal["backend"]
    stats["confusables_available"] = signal["available"]
    stats["confusables_mixed_script"] = signal["mixed_script"]
    stats["confusables_dangerous"] = signal["dangerous"]
    stats["confusables_restriction_level"] = signal["restriction_level"]
    stats["confusables_scripts"] = signal["script_set"]
    stats["confusables_skeleton_stored"] = signal["skeleton_stored"]
    if signal["skeleton"] is not None:
        stats["confusables_skeleton"] = signal["skeleton"]
    stats["confusable_count"] = signal["confusable_count"]
    stats["mixed_script_word_count"] = signal["mixed_word_count"]
    stats["mixed_script_words"] = signal["mixed_words"]
    stats["confusables_whole_script"] = signal["whole_script"]
    stats["whole_script_confusable_actionable"] = signal["whole_script_actionable"]
    stats["whole_script_word_count"] = signal["whole_script_word_count"]
    stats["whole_script_words"] = signal["whole_script_words"]
    if signal["error"] is not None:
        stats["confusables_error"] = signal["error"]
    if signal["mixed_script"] and signal["dangerous"]:
        flagged["mixed_script_word"] = int(flagged.get("mixed_script_word", 0)) + 1
    if signal["mixed_script"] and signal["dangerous"]:
        flagged["confusable_mixed_script"] = int(flagged.get("confusable_mixed_script", 0)) + 1
    if signal["whole_script"]:
        flagged["whole_script_confusable"] = int(
            flagged.get("whole_script_confusable", 0)
        ) + 1

    styled_tokens = detect_styled_compatibility_tokens(clean)
    if clean != text:
        styled_tokens = list(dict.fromkeys([
            *detect_styled_compatibility_tokens(text), *styled_tokens,
        ]))[:8]
    stats["confusables_styled_latin"] = bool(styled_tokens)
    stats["styled_latin_words"] = styled_tokens
    stats["confusables_styled_compatibility"] = bool(styled_tokens)
    stats["styled_compatibility_tokens"] = styled_tokens
    if styled_tokens:
        flagged["confusable_styled"] = int(flagged.get("confusable_styled", 0)) + 1

    report["reason_codes"] = reason_code_counts(removed, flagged)

    return clean, cast(SanitizeReport, report)


def sanitize_text(
    text: str,
    policy: str = "balanced_chat",
    *,
    return_spans: bool = False,
    normalization: str | None = None,
    tidy_whitespace: bool | None = None,
    confusables_backend: str | None = None,
    max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
) -> tuple[str, SanitizeReport]:
    """Sanitize bounded text and inspect encoded candidates without decoding output."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if isinstance(max_input_chars, bool) or not isinstance(max_input_chars, int):
        raise TypeError("max_input_chars must be an integer")
    if max_input_chars < 0:
        raise ValueError("max_input_chars must be >= 0")
    if len(text) > max_input_chars:
        raise ValueError(f"sanitize max_input_chars exceeded: {max_input_chars}")

    stage_options = dict(
        policy=policy,
        return_spans=return_spans,
        normalization=normalization,
        tidy_whitespace=tidy_whitespace,
        confusables_backend=confusables_backend,
    )
    clean, report = _sanitize_stage(text, **stage_options)
    original = inspect_encoded_unicode(text, report["policy"])
    inspections = [original]
    if clean != text:
        output = inspect_encoded_unicode(clean, report["policy"])
        for sample in output.samples:
            sample["source"] = "sanitized"
        inspections.append(output)
    stats = report["stats"]
    stats["encoded_unicode_samples"] = [
        sample for inspection in inspections for sample in inspection.samples
    ][:MAX_SAMPLES]
    stats["encoded_unicode_candidates"] = sum(i.candidates for i in inspections)
    stats["encoded_unicode_candidate_chars"] = sum(i.candidate_chars for i in inspections)
    stats["encoded_unicode_decode_depth"] = max(i.depth for i in inspections)
    stats["encoded_unicode_limit"] = next((i.limit for i in inspections if i.limit), None)
    count = max(i.count for i in inspections)
    if count:
        report["flagged_counts"]["encoded_risky_unicode"] = count
    if stats["encoded_unicode_limit"]:
        report["flagged_counts"]["encoded_unicode_inspection_limit"] = 1
    report["reason_codes"] = reason_code_counts(report["removed_counts"], report["flagged_counts"])
    return clean, report
