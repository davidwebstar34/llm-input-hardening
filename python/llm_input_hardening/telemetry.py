from __future__ import annotations

from typing import Mapping

from .reason_codes import reason_code_counts
from .types import SanitizeReport


def to_otel_attributes(report: SanitizeReport) -> dict[str, bool | int | str]:
    """Convert a sanitize report to low-cardinality telemetry attributes."""

    removed_counts = report.get("removed_counts", {})
    flagged_counts = report.get("flagged_counts", {})

    report_reason_codes = report.get("reason_codes", {})
    if isinstance(report_reason_codes, Mapping) and report_reason_codes:
        code_counts = {
            str(code): int(count)
            for code, count in report_reason_codes.items()
            if int(count) > 0
        }
    else:
        code_counts = reason_code_counts(removed_counts, flagged_counts)

    sorted_codes = sorted(code_counts)
    attrs: dict[str, bool | int | str] = {
        "llm_input_hardening.schema_version": int(report.get("report_version", 1)),
        "llm_input_hardening.policy": str(report.get("policy", "")),
        "llm_input_hardening.normalization": str(report.get("normalization", "")),
        "llm_input_hardening.changed": bool(report.get("changed", False)),
        "llm_input_hardening.removed_total": sum(int(v) for v in removed_counts.values()),
        "llm_input_hardening.flagged_total": sum(int(v) for v in flagged_counts.values()),
        "llm_input_hardening.reason_code_count": len(sorted_codes),
        "llm_input_hardening.reason_codes": ",".join(sorted_codes),
    }
    for code in sorted_codes:
        attrs[f"llm_input_hardening.reason.{code}"] = int(code_counts[code])
    return attrs

