from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, cast

from ._service import sanitize_text
from .policies import resolve_policy_name
from .reason_codes import DECISION_REASON_CODES, reason_code_for_signal
from .types import EnforcementDecision, SanitizeReport


@dataclass(frozen=True)
class EnforcementPolicy:
    """Threshold policy for `decide_enforcement()`."""

    reject_flags: frozenset[str] = frozenset(
        {
            "confusable_mixed_script",
            "mixed_script_word",
            "whole_script_confusable",
        }
    )
    quarantine_flags: frozenset[str] = frozenset(
        {
            "base64ish_blob",
            "encoded_blob",
            "encoded_risky_unicode",
            "encoded_unicode_inspection_limit",
            "confusable_styled",
            "hex_blob",
            "high_entropy",
            "excessive_combining_stack",
            "invalid_variation_selector",
            # Tag characters have no benign use in prompt text (flag-emoji tag
            # runs are preserved and never flagged), so their mere presence is
            # actionable even if a custom policy preserved rather than removed
            # them. `bidi_mark` and `default_ignorable` are deliberately NOT here:
            # a single variation selector on an emoji, or an RTL mark in benign
            # Arabic/Hebrew, both flag those signals and must not quarantine.
            "tag_char",
        }
    )
    reject_removed: frozenset[str] = frozenset(
        {
            "bidi_control",
            "control_or_format",
            "line_separator",
            "normalization_amplified",
        }
    )
    quarantine_removed: frozenset[str] = frozenset(
        {
            "junk_invisible",
            "default_ignorable",
            "bidi_mark",
            "tag_char",
            "variation_selector_excess",
        }
    )
    quarantine_total_removed_at_or_above: int = 12
    # Native prose can contain confusable words; retain the observation while
    # using context only for chat severity. Execution policies never exempt it.
    allow_native_whole_script: bool = False
    removal_volume_exclusions: frozenset[str] = frozenset({"whitespace_tidy", "carriage_return"})

    def __post_init__(self) -> None:
        if not isinstance(self.allow_native_whole_script, bool):
            raise TypeError("allow_native_whole_script must be a bool")
        # frozen=True alone does not freeze caller-provided mutable sets.
        for name in (
            "reject_flags", "quarantine_flags", "reject_removed",
            "quarantine_removed", "removal_volume_exclusions",
        ):
            value = getattr(self, name)
            if isinstance(value, (str, bytes)):
                raise TypeError(f"{name} must be a collection of signal names")
            frozen = frozenset(value)
            if any(not isinstance(key, str) for key in frozen):
                raise TypeError(f"{name} must contain only strings")
            object.__setattr__(self, name, frozen)
        if isinstance(self.quarantine_total_removed_at_or_above, bool) or not isinstance(
            self.quarantine_total_removed_at_or_above, int
        ):
            raise TypeError("quarantine_total_removed_at_or_above must be an integer")
        if self.quarantine_total_removed_at_or_above < 1:
            raise ValueError("quarantine_total_removed_at_or_above must be >= 1")


DEFAULT_ENFORCEMENT_POLICY = EnforcementPolicy()

# Strict variant for execution-adjacent call sites: a mixed-script confusable is
# a hard reject (the default). Use for `strict_exec` / `code_mode`.
STRICT_ENFORCEMENT_POLICY = DEFAULT_ENFORCEMENT_POLICY

# Chat variant: mixed-script words are common in benign multilingual text (a
# Russian sentence with one Latin brand name, "Ωmega" branding), so they
# quarantine for review rather than hard-reject. Use for `preserve` /
# `balanced_chat`. Bidi overrides and control characters still reject.
CHAT_ENFORCEMENT_POLICY = EnforcementPolicy(
    allow_native_whole_script=True,
    reject_flags=frozenset(),
    quarantine_flags=DEFAULT_ENFORCEMENT_POLICY.quarantine_flags
    | {
        "confusable_mixed_script",
        "mixed_script_word",
        "whole_script_confusable",
    },
)

# Maps a sanitize policy to the enforcement policy whose strictness matches the
# call site's risk profile. `sanitize_and_decide` uses this when the caller does
# not pass an explicit enforcement policy.
ENFORCEMENT_BY_SANITIZE_POLICY: Mapping[str, EnforcementPolicy] = MappingProxyType({
    "preserve": CHAT_ENFORCEMENT_POLICY,
    "balanced_chat": CHAT_ENFORCEMENT_POLICY,
    "strict_exec": STRICT_ENFORCEMENT_POLICY,
    "code_mode": STRICT_ENFORCEMENT_POLICY,
})


def _triggered_counts(
    counts: Mapping[str, int], keys: frozenset[str]
) -> dict[str, int]:
    return {key: int(counts.get(key, 0)) for key in sorted(keys) if counts.get(key, 0) > 0}


class _DecisionDict(dict):
    """Enforcement decision mapping that deprecates the legacy `reasons` key.

    `reasons` is a backward-compatible alias of `reason_codes`. Reading it via
    subscript emits a `DeprecationWarning`; new code should read `reason_codes`.
    """

    def __getitem__(self, key):  # type: ignore[override]
        if key == "reasons":
            warnings.warn(
                "EnforcementDecision['reasons'] is deprecated; read 'reason_codes' "
                "instead. The alias will be removed in a future major release.",
                DeprecationWarning,
                stacklevel=2,
            )
        return super().__getitem__(key)


def _make_decision(
    action: str,
    reason_codes: list[str],
    triggered_flags: dict[str, int],
    triggered_removed: dict[str, int],
) -> EnforcementDecision:
    decision = _DecisionDict(
        action=action,
        reason_codes=reason_codes,
        reasons=reason_codes,
        triggered_flags=triggered_flags,
        triggered_removed=triggered_removed,
    )
    return cast(EnforcementDecision, decision)


def decide_enforcement(
    report: SanitizeReport, *, policy: EnforcementPolicy | None = None
) -> EnforcementDecision:
    """Map a sanitize report to `allow`, `quarantine`, or `reject`."""

    if policy is None:
        policy = enforcement_policy_for(report["policy"])
    stats = report.get("stats", {})
    field_reasons: set[str] = set()
    if stats.get("reject_on_change") and report.get("changed"):
        field_reasons.add(DECISION_REASON_CODES["input_transformed"])
    if stats.get("field_validation_passed") is False:
        field_reasons.add(DECISION_REASON_CODES["field_validation_failed"])
    removed_counts = report.get("removed_counts", {})
    flagged_counts = report.get("flagged_counts", {})
    if (
        policy.allow_native_whole_script
        and report.get("stats", {}).get("whole_script_confusable_actionable") is False
    ):
        flagged_counts = {k: v for k, v in flagged_counts.items() if k != "whole_script_confusable"}

    reject_flag_hits = _triggered_counts(flagged_counts, policy.reject_flags)
    reject_removed_hits = _triggered_counts(removed_counts, policy.reject_removed)
    if reject_flag_hits or reject_removed_hits or field_reasons:
        reason_codes = sorted(
            field_reasons | {
                code
                for key in [*reject_flag_hits.keys(), *reject_removed_hits.keys()]
                for code in [reason_code_for_signal(key)]
                if code is not None
            }
        )
        return _make_decision("reject", reason_codes, reject_flag_hits, reject_removed_hits)

    quarantine_flag_hits = _triggered_counts(flagged_counts, policy.quarantine_flags)
    quarantine_removed_hits = _triggered_counts(removed_counts, policy.quarantine_removed)

    total_removed = sum(
        int(v) for k, v in removed_counts.items() if k not in policy.removal_volume_exclusions
    )
    total_removed_trigger = total_removed >= policy.quarantine_total_removed_at_or_above

    if quarantine_flag_hits or quarantine_removed_hits or total_removed_trigger:
        reason_code_set = {
            code
            for key in [*quarantine_flag_hits.keys(), *quarantine_removed_hits.keys()]
            for code in [reason_code_for_signal(key)]
            if code is not None
        }
        if total_removed_trigger:
            reason_code_set.add(DECISION_REASON_CODES["total_removed_threshold"])
        reason_codes = sorted(reason_code_set)
        return _make_decision(
            "quarantine", reason_codes, quarantine_flag_hits, quarantine_removed_hits
        )

    return _make_decision("allow", [], {}, {})


def enforcement_policy_for(sanitize_policy: str) -> EnforcementPolicy:
    """Return the enforcement policy whose strictness matches a sanitize policy."""

    canonical = resolve_policy_name(sanitize_policy)
    return ENFORCEMENT_BY_SANITIZE_POLICY.get(canonical, DEFAULT_ENFORCEMENT_POLICY)


def sanitize_and_decide(
    text: str,
    *,
    sanitize_policy: str = "balanced_chat",
    enforcement_policy: EnforcementPolicy | None = None,
    reject_on_change: bool = False,
    validator: Callable[[str], bool] | None = None,
    **sanitize_kwargs: object,
) -> tuple[str, SanitizeReport, EnforcementDecision]:
    """Convenience wrapper that runs sanitize then enforcement decisioning.

    When `enforcement_policy` is omitted, the enforcement strictness is chosen to
    match `sanitize_policy`: execution-adjacent policies reject mixed-script
    confusables, while chat policies quarantine them. Pass an explicit
    `enforcement_policy` to override.

    `reject_on_change=True` rejects transformed fields. `validator` receives the
    actual sanitized text and must return a bool; failures propagate. Both field
    decisions remain reproducible from the returned report. Application schemas
    and authorization remain the caller's responsibility.
    """

    if enforcement_policy is None:
        enforcement_policy = enforcement_policy_for(sanitize_policy)

    clean, report = sanitize_text(text, policy=sanitize_policy, **sanitize_kwargs)
    if reject_on_change:
        report["stats"]["reject_on_change"] = True
    if validator is not None:
        valid = validator(clean)
        if not isinstance(valid, bool):
            raise TypeError("validator must return a bool")
        report["stats"]["field_validation_passed"] = valid
    return clean, report, decide_enforcement(report, policy=enforcement_policy)
