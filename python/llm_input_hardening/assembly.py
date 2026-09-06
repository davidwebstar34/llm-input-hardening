from __future__ import annotations

from collections.abc import Callable, Iterable

from ._service import DEFAULT_MAX_INPUT_CHARS
from .enforcement import EnforcementPolicy, sanitize_and_decide
from .types import EnforcementDecision, SanitizeReport


def sanitize_assembled(
    parts: Iterable[str],
    *,
    separator: str = "",
    max_parts: int = 10_000,
    max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
    sanitize_policy: str = "balanced_chat",
    enforcement_policy: EnforcementPolicy | None = None,
    reject_on_change: bool = False,
    validator: Callable[[str], bool] | None = None,
    **sanitize_kwargs: object,
) -> tuple[str, SanitizeReport, EnforcementDecision]:
    """Bound and join raw fragments, then inspect the complete untrusted text.

    Signals and normalization can cross fragment boundaries. Per-fragment
    decisions cannot authorize a later concatenation; this helper applies one
    decision to exactly the joined text. The caller controls the separator and
    which content belongs to this trust boundary. Do not include trusted role
    metadata or instructions, or concatenate additional text after validation.

    Limits count empty fragments and separators, and apply before joining.
    Spans use the same coordinates as ``sanitize_and_decide`` on the joined
    input. Errors from iteration, sanitization, or field validation propagate;
    no partially sanitized result is returned.
    """
    if isinstance(parts, (str, bytes)):
        raise TypeError("parts must be an iterable of strings, not a string or bytes")
    if not isinstance(separator, str):
        raise TypeError("separator must be a string")
    for name, limit in (("max_parts", max_parts), ("max_input_chars", max_input_chars)):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"{name} must be an integer")
        if limit < 0:
            raise ValueError(f"{name} must be >= 0")

    collected: list[str] = []
    total_chars = 0
    for part in parts:
        if len(collected) >= max_parts:
            raise ValueError(f"sanitize_assembled max_parts exceeded: {max_parts}")
        if not isinstance(part, str):
            raise TypeError(f"parts[{len(collected)}] must be a string")
        total_chars += len(part) + (len(separator) if collected else 0)
        if total_chars > max_input_chars:
            raise ValueError(
                f"sanitize_assembled max_input_chars exceeded: {max_input_chars}"
            )
        collected.append(part)

    clean, report, decision = sanitize_and_decide(
        separator.join(collected),
        sanitize_policy=sanitize_policy,
        enforcement_policy=enforcement_policy,
        reject_on_change=reject_on_change,
        validator=validator,
        max_input_chars=max_input_chars,
        **sanitize_kwargs,
    )
    report["stats"]["assembly_parts"] = len(collected)
    return clean, report, decision
