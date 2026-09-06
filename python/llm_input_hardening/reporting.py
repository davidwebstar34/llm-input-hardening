from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def compact_report(
    report: Mapping[str, Any],
    *,
    sanitized_text: str | None = None,
    decision: Mapping[str, Any] | None = None,
    timing_ms: float | None = None,
) -> dict[str, Any]:
    """Return a small, demo-friendly summary of a sanitizer report."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")

    payload: dict[str, Any] = {
        "policy": report.get("policy"),
        "changed": bool(report.get("changed", False)),
        "removed": _positive_counts(report.get("removed_counts", {})),
        "flagged": _positive_counts(report.get("flagged_counts", {})),
        "reason_codes": _positive_counts(report.get("reason_codes", {})),
    }
    if sanitized_text is not None:
        payload["sanitized_preview"] = _preview(sanitized_text)
    if decision is not None:
        payload["decision"] = str(decision.get("action", "unknown"))
    if timing_ms is not None:
        payload["timing_ms"] = round(float(timing_ms), 3)
    return payload


def _positive_counts(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    counts: dict[str, int] = {}
    for key, raw_count in value.items():
        try:
            count = int(raw_count)
        except (TypeError, ValueError):
            continue
        if count > 0:
            counts[str(key)] = count
    return {key: counts[key] for key in sorted(counts)}


def _preview(text: str, *, limit: int = 160) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 1]}..."
