from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _version

from ._service import sanitize_text as sanitize
from .enforcement import (
    CHAT_ENFORCEMENT_POLICY,
    DEFAULT_ENFORCEMENT_POLICY,
    STRICT_ENFORCEMENT_POLICY,
    EnforcementPolicy,
    decide_enforcement,
    enforcement_policy_for,
    sanitize_and_decide,
)

try:
    __version__ = _version("llm-input-hardening")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0.dev0"
from .types import (
    EnforcementDecision,
    MeterResult,
    SanitizeReport,
    SanitizeStats,
    SpanEvent,
    TokenMeter,
)


from .meter import meter  # noqa: E402
from .middleware import (  # noqa: E402
    ASGIPromptSanitizerMiddleware,
    StarlettePromptSanitizerMiddleware,
)
from .json_sanitize import sanitize_json  # noqa: E402
from .assembly import sanitize_assembled  # noqa: E402
from .reporting import compact_report  # noqa: E402
from .telemetry import to_otel_attributes  # noqa: E402

__all__ = [
    "__version__",
    "MeterResult",
    "SanitizeReport",
    "SanitizeStats",
    "SpanEvent",
    "ASGIPromptSanitizerMiddleware",
    "StarlettePromptSanitizerMiddleware",
    "TokenMeter",
    "CHAT_ENFORCEMENT_POLICY",
    "DEFAULT_ENFORCEMENT_POLICY",
    "STRICT_ENFORCEMENT_POLICY",
    "EnforcementDecision",
    "EnforcementPolicy",
    "decide_enforcement",
    "enforcement_policy_for",
    "compact_report",
    "meter",
    "sanitize_json",
    "sanitize_and_decide",
    "sanitize_assembled",
    "sanitize",
    "to_otel_attributes",
]
