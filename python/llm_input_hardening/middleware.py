from __future__ import annotations

import asyncio
import contextvars
import json
import math
import re
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from threading import BoundedSemaphore
from typing import Any, Awaitable, Callable, Literal, Optional, cast

from ._service import sanitize_text
from .enforcement import EnforcementPolicy, decide_enforcement, enforcement_policy_for
from .json_sanitize import _format_path
from .meter import meter
from .reason_codes import reason_code_counts
from .types import EnforcementDecision, SanitizeReport


Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

# Default cap on buffered request body. A hardening middleware must not itself
# introduce an unbounded-memory DoS vector; oversized requests are rejected.
DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_BODY_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_REPORT_CHARS = 4 * 1024 * 1024


class _WorkerPool:
    """A process-shared pool with no waiting CPU-job queue."""

    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="llm-input-hardening"
        )
        self.slots = BoundedSemaphore(max_workers)

    def submit(self, function: Callable[[], Any]) -> Future[Any] | None:
        if not self.slots.acquire(blocking=False):
            return None
        context = contextvars.copy_context()
        try:
            future = self.executor.submit(context.run, function)
        except BaseException:
            self.slots.release()
            raise
        future.add_done_callback(lambda _: self.slots.release())
        return future


# These limits are shared across middleware instances and event loops. Admission
# is separate from CPU capacity so slow uploads cannot occupy every worker.
_WORKERS = _WorkerPool()
_ADMISSION = BoundedSemaphore(16)


@dataclass(frozen=True, slots=True)
class _JSONNumber:
    # Only the JSON parser constructs these, after validating number grammar.
    literal: str


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON object key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class _PreparedRequest:
    body: bytes
    report: SanitizeReport | None = None
    decision: EnforcementDecision | None = None
    tokens_before: int = 0
    tokens_after: int = 0


@dataclass(frozen=True, slots=True)
class _RejectedRequest:
    status: int
    detail: str
    report: SanitizeReport | None = None
    decision: EnforcementDecision | None = None


# Sentinel returned by `_read_body` when the client disconnected mid-stream, so a
# truncated partial body is never parsed and forwarded as if complete.
_DISCONNECTED = object()
# Sentinel for a body that exceeded the size cap.
_TOO_LARGE = object()
_FIELD_PATH_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*|\*|\[(\d+|\*)])")


def _header_value(scope: dict[str, Any], name: bytes) -> str:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return ""


def _set_content_length(scope: dict[str, Any], length: int) -> dict[str, Any]:
    headers = [
        (key, value)
        for key, value in scope.get("headers", [])
        if key.lower() != b"content-length"
    ]
    headers.append((b"content-length", str(length).encode("latin-1")))
    updated = dict(scope)
    updated["headers"] = headers
    return updated


def _parse_field_path(field: str) -> list[str | int]:
    """Parse a dotted/bracket path, including `messages[*].content`."""

    if not isinstance(field, str) or not field:
        raise ValueError("field selectors must be nonempty strings")
    parts: list[str | int] = []
    pos = 0
    while pos < len(field):
        if parts and field[pos] == ".":
            pos += 1
            if pos == len(field) or field[pos] in ".[":
                raise ValueError(f"invalid field selector: {field!r}")
        elif parts and field[pos] != "[":
            raise ValueError(f"invalid field selector: {field!r}")
        match = _FIELD_PATH_RE.match(field, pos)
        if match is None:
            raise ValueError(f"invalid field selector: {field!r}")
        token = match.group(1)
        if token.startswith("["):
            parts.append("*" if match.group(2) == "*" else int(match.group(2)))
        else:
            parts.append(token)
        pos = match.end()
    return parts


def _path_matches(
    data: Any, path: list[str | int], max_matches: int
) -> list[tuple[list[str | int], Any]]:
    matches: list[tuple[list[str | int], Any]] = []
    pending: list[tuple[Any, int, list[str | int]]] = [(data, 0, [])]
    while pending:
        current, index, resolved = pending.pop()
        if index == len(path):
            matches.append((resolved, current))
            continue
        part = path[index]
        if part == "*":
            if isinstance(current, (dict, list)) and (
                len(matches) + len(pending) + len(current) > max_matches
            ):
                raise ValueError("field selector exceeds max_selected_strings")
            items = (
                current.items()
                if isinstance(current, dict)
                else (enumerate(current) if isinstance(current, list) else ())
            )
            pending.extend((value, index + 1, [*resolved, key]) for key, value in items)
        elif isinstance(part, int):
            if isinstance(current, list) and part < len(current):
                pending.append((current[part], index + 1, [*resolved, part]))
        elif isinstance(current, dict) and part in current:
            pending.append((current[part], index + 1, [*resolved, part]))
    return matches


def _set_path(data: Any, path: list[str | int], value: Any) -> bool:
    if not path:
        return False
    current = data
    for part in path[:-1]:
        if isinstance(part, int):
            if not isinstance(current, list) or part >= len(current):
                return False
            current = current[part]
            continue
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]

    last = path[-1]
    if isinstance(last, int):
        if not isinstance(current, list) or last >= len(current):
            return False
        current[last] = value
        return True
    if not isinstance(current, dict) or last not in current:
        return False
    current[last] = value
    return True


async def _read_body(receive: Receive, max_body_bytes: int) -> bytes | object:
    body = bytearray()
    while True:
        message = await receive()
        # Stop on disconnect: servers may emit http.disconnect repeatedly,
        # so skipping it would loop forever. Return a sentinel rather than the
        # partial body — a truncated JSON body must not be parsed and forwarded.
        if message["type"] == "http.disconnect":
            return _DISCONNECTED
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        if len(body) + len(chunk) > max_body_bytes:
            return _TOO_LARGE
        body.extend(chunk)
        if not message.get("more_body", False):
            return bytes(body)


def _replay_body(body: bytes, upstream_receive: Receive) -> Receive:
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return await upstream_receive()
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _is_json_content_type(value: str) -> bool:
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _encode_json_body(data: Any, max_body_bytes: int) -> bytes:
    body = bytearray()

    def append(chunk: str) -> None:
        encoded = chunk.encode("utf-8")
        if len(body) + len(encoded) > max_body_bytes:
            raise OverflowError("sanitized request body too large")
        body.extend(encoded)

    # Stream containers with O(depth) traversal state. Numbers retain the exact
    # parser-validated literal instead of passing through binary floating point.
    frames: list[tuple[Any, bool, bool]] = []
    current = data
    while True:
        if isinstance(current, dict):
            append("{")
            frames.append((iter(current.items()), True, True))
        elif isinstance(current, list):
            append("[")
            frames.append((iter(enumerate(current)), False, True))
        elif isinstance(current, _JSONNumber):
            append(current.literal)
        else:
            append(json.dumps(current, ensure_ascii=False, allow_nan=False))

        while frames:
            entries, mapping, first = frames[-1]
            try:
                key, current = next(entries)
            except StopIteration:
                frames.pop()
                append("}" if mapping else "]")
                continue
            if not first:
                append(",")
            frames[-1] = (entries, mapping, False)
            if mapping:
                append(json.dumps(key, ensure_ascii=False))
                append(":")
            break
        else:
            break
    return bytes(body)


def _combine_reports(
    reports: list[tuple[list[str | int], SanitizeReport]],
    max_report_chars: int = DEFAULT_MAX_REPORT_CHARS,
) -> SanitizeReport:
    remaining = max_report_chars
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False)

    def account(value: Any) -> None:
        nonlocal remaining
        for chunk in encoder.iterencode(value):
            remaining -= len(chunk)
            if remaining < 0:
                raise OverflowError("input inspection report too large")

    if len(reports) == 1:
        account(reports[0][1])
        return reports[0][1]
    combined = dict(reports[0][1])
    removed: dict[str, int] = {}
    flagged: dict[str, int] = {}
    for _, report in reports:
        for target, source in (
            (removed, report["removed_counts"]),
            (flagged, report["flagged_counts"]),
        ):
            for key, count in source.items():
                target[key] = target.get(key, 0) + count
    combined.update(
        changed=any(report["changed"] for _, report in reports),
        removed_counts=removed,
        flagged_counts=flagged,
        reason_codes=reason_code_counts(removed, flagged),
        spans=[],
        stats={
            "json_path_reports": [],
            "whole_script_confusable_actionable": any(
                report["flagged_counts"].get("whole_script_confusable", 0)
                and report.get("stats", {}).get("whole_script_confusable_actionable")
                is not False
                for _, report in reports
            ),
        },
    )
    account(combined)
    path_reports = combined["stats"]["json_path_reports"]
    for path, report in reports:
        entry = {
            "path": _format_path(path),
            "changed": report["changed"],
            "removed_counts": report["removed_counts"],
            "flagged_counts": report["flagged_counts"],
        }
        if path_reports:
            remaining -= 2  # JSONEncoder's comma and space between list entries.
        account(entry)
        path_reports.append(entry)
    return cast(SanitizeReport, combined)


def _replay_disconnect() -> Receive:
    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    return receive


OnDecision = Callable[[EnforcementDecision, SanitizeReport], None]


async def _send_status(send: Send, status: int, detail: str) -> None:
    payload = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class ASGIPromptSanitizerMiddleware:
    """ASGI middleware that sanitizes selected JSON strings in the request body.

    Works with any ASGI app (Starlette/FastAPI included); it has no Starlette
    dependency. `StarlettePromptSanitizerMiddleware` is a backward-compatible
    alias.

    Behavior:
    - Accepts `application/json` and `application/*+json` media types.
    - Buffers the body up to `max_body_bytes` (oversized requests: 413).
    - Selects `field` or `fields`, with wildcard support, leaving other fields
      (including trusted message roles) untouched.
    - With enforcement enabled, rejects unsupported or uninspected requests and
      blocks reject/quarantine decisions by default.
    - Adds response headers for downstream visibility:
      `x-sanitize-changed`, `x-tokens-before`, `x-tokens-after`,
      and `x-enforcement-action`.

    Set `protected_paths` to limit inspection to exact URL paths, or mount this
    middleware around a dedicated ASGI application. `limit_tokens` only measures
    the selected strings; it does not enforce the model's context budget.
    """

    def __init__(
        self,
        app: Any,
        *,
        field: str = "prompt",
        fields: Sequence[str] | None = None,
        protected_paths: Sequence[str] | None = None,
        policy: str = "balanced_chat",
        model: Optional[str] = None,
        limit_tokens: Optional[int] = None,
        reserved_output_tokens: int = 512,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        body_timeout_seconds: float = DEFAULT_BODY_TIMEOUT_SECONDS,
        enforce: bool = False,
        reject_uninspected: bool | None = None,
        quarantine_action: Literal["reject", "allow"] = "reject",
        max_selected_strings: int = 10_000,
        max_report_chars: int = DEFAULT_MAX_REPORT_CHARS,
        strict_tokenizer: bool = False,
        enforcement_policy: Optional[EnforcementPolicy] = None,
        on_decision: Optional[OnDecision] = None,
    ):
        """Create the middleware.

        Args:
            app: Downstream ASGI app.
            field: JSON string path to sanitize (default: `"prompt"`).
            fields: Alternative or additional selectors, replacing `field`.
                Supports `messages[*].content` and `messages[*].content[*].text`.
                At least one selector must resolve to a string in strict mode.
            protected_paths: Exact HTTP paths to inspect; defaults to every path.
            policy: Sanitization policy.
            model: Optional model name for token counting.
            limit_tokens: Optional context window size for measurement only.
            reserved_output_tokens: Tokens reserved for the model's response.
            max_body_bytes: Cap on buffered request body; larger requests get 413.
            body_timeout_seconds: Maximum elapsed time to read a JSON body;
                incomplete uploads return HTTP 408. CPU preparation uses a shared
                four-worker pool and a shared 16-request admission limit; capacity
                exhaustion returns HTTP 503 instead of queueing more work.
            enforce: Block reject decisions with HTTP 403.
            reject_uninspected: Reject unsupported media types, invalid JSON, and
                missing/invalid selected fields. Defaults to `enforce`.
            quarantine_action: With enforcement, block quarantine decisions by
                default. Set `allow` only if the downstream app handles review.
            max_selected_strings: Bound wildcard expansion and selected strings.
            max_report_chars: Maximum serialized report characters, including
                repeated field paths; excess returns HTTP 413.
            strict_tokenizer: Fail rather than estimate when tokenization fails.
            enforcement_policy: Enforcement policy; defaults to the one matching
                `policy` (chat policies quarantine confusables, exec policies
                reject them).
            on_decision: Optional callback invoked with `(decision, report)` for
                every sanitized request, for logging/metrics.
        """
        self.app = app
        if (
            isinstance(body_timeout_seconds, bool)
            or not isinstance(body_timeout_seconds, (int, float))
            or not math.isfinite(body_timeout_seconds)
            or body_timeout_seconds <= 0
        ):
            raise ValueError("body_timeout_seconds must be a finite positive number")
        for name, value in (
            ("max_body_bytes", max_body_bytes),
            ("max_selected_strings", max_selected_strings),
            ("max_report_chars", max_report_chars),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if quarantine_action not in {"reject", "allow"}:
            raise ValueError("quarantine_action must be 'reject' or 'allow'")
        if fields is not None and (isinstance(fields, str) or not fields):
            raise ValueError("fields must be a nonempty sequence of selectors")
        if fields is not None and field != "prompt":
            raise ValueError("use field or fields, not both")
        if protected_paths is not None and (
            isinstance(protected_paths, str)
            or any(
                not isinstance(path, str) or not path.startswith("/")
                for path in protected_paths
            )
        ):
            raise ValueError("protected_paths must contain absolute URL paths")
        self.field = field
        self.protected_paths = (
            None if protected_paths is None else frozenset(protected_paths)
        )
        self.policy = policy
        self.model = model
        self.limit_tokens = limit_tokens
        self.reserved_output_tokens = reserved_output_tokens
        self.max_body_bytes = max_body_bytes
        self.body_timeout_seconds = float(body_timeout_seconds)
        self.enforce = enforce
        self.reject_uninspected = (
            enforce if reject_uninspected is None else reject_uninspected
        )
        self.quarantine_action = quarantine_action
        self.max_selected_strings = max_selected_strings
        self.max_report_chars = max_report_chars
        self.strict_tokenizer = strict_tokenizer
        self.enforcement_policy = enforcement_policy or enforcement_policy_for(policy)
        self.on_decision = on_decision
        self._field_paths = [
            _parse_field_path(selector) for selector in (fields or [field])
        ]

    def _prepare_body(self, body: bytes) -> _PreparedRequest | _RejectedRequest:
        """Perform all parsing and text processing in an admitted CPU worker."""

        try:
            data = json.loads(
                body.decode("utf-8"),
                parse_constant=_reject_json_constant,
                parse_float=_JSONNumber,
                parse_int=_JSONNumber,
                object_pairs_hook=_unique_object,
            )
        except _DuplicateKeyError:
            return _RejectedRequest(400, "duplicate JSON object key")
        except (ValueError, UnicodeError, RecursionError):
            if self.reject_uninspected:
                return _RejectedRequest(400, "invalid JSON request body")
            return _PreparedRequest(body)

        selected: dict[tuple[str | int, ...], str] = {}
        nonstrings: list[list[str | int]] = []
        try:
            for selector in self._field_paths:
                for path, value in _path_matches(
                    data, selector, self.max_selected_strings
                ):
                    if isinstance(value, str):
                        selected[tuple(path)] = value
                    else:
                        nonstrings.append(path)
                if len(selected) > self.max_selected_strings:
                    raise ValueError("too many selected strings")
        except ValueError:
            return _RejectedRequest(413, "too many selected input fields")

        covered_prefixes = {
            selected_path[:index]
            for selected_path in selected
            for index in range(len(selected_path) + 1)
        }
        invalid_type = any(tuple(path) not in covered_prefixes for path in nonstrings)
        if not selected or invalid_type:
            if self.reject_uninspected:
                return _RejectedRequest(
                    422, "selected input fields must contain strings"
                )
            if not selected:
                return _PreparedRequest(body)

        reports: list[tuple[list[str | int], SanitizeReport]] = []
        sanitized: list[tuple[str, str, SanitizeReport]] = []
        try:
            for path, original in selected.items():
                cleaned, report = sanitize_text(original, policy=self.policy)
                _set_path(data, list(path), cleaned)
                reports.append((list(path), report))
                sanitized.append((original, cleaned, report))
        except (ValueError, UnicodeError, RecursionError):
            return _RejectedRequest(400, "input could not be safely sanitized")

        try:
            report = _combine_reports(reports, self.max_report_chars)
        except OverflowError:
            return _RejectedRequest(413, "input inspection report too large")
        decision = decide_enforcement(report, policy=self.enforcement_policy)
        if self.enforce and (
            decision["action"] == "reject"
            or (
                decision["action"] == "quarantine"
                and self.quarantine_action == "reject"
            )
        ):
            return _RejectedRequest(
                403, "request blocked by input policy", report, decision
            )

        try:
            new_body = _encode_json_body(data, self.max_body_bytes)
        except OverflowError:
            return _RejectedRequest(
                413, "sanitized request body too large", report, decision
            )
        except (ValueError, UnicodeError, RecursionError):
            return _RejectedRequest(
                400, "input could not be safely serialized", report, decision
            )

        before_tokens = after_tokens = 0
        for original, cleaned, string_report in sanitized:
            measurement = meter(
                original,
                model=self.model,
                limit_tokens=self.limit_tokens,
                reserved_output_tokens=self.reserved_output_tokens,
                policy=self.policy,
                sanitized=(cleaned, string_report),
                strict_tokenizer=self.strict_tokenizer,
            )
            before_tokens += measurement["tokens_before"]["input_tokens"]
            after_tokens += measurement["tokens_after"]["input_tokens"]
        return _PreparedRequest(new_body, report, decision, before_tokens, after_tokens)

    async def __call__(
        self, scope: dict[str, Any], receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if (
            self.protected_paths is not None
            and scope.get("path") not in self.protected_paths
        ):
            return await self.app(scope, receive, send)

        ctype = _header_value(scope, b"content-type")
        if not _is_json_content_type(ctype):
            if self.reject_uninspected:
                return await _send_status(send, 415, "a JSON content type is required")
            return await self.app(scope, receive, send)

        # Pre-check the declared length so an oversized body is rejected without
        # buffering it at all.
        content_length = _header_value(scope, b"content-length")
        if content_length:
            if not content_length.isascii() or not content_length.isdigit():
                return await _send_status(send, 400, "invalid Content-Length")
            if len(content_length) > 20 or int(content_length) > self.max_body_bytes:
                return await _send_status(send, 413, "request body too large")

        if not _ADMISSION.acquire(blocking=False):
            return await _send_status(send, 503, "input inspection capacity exhausted")
        # Admission covers both inspection and downstream handling of the buffered
        # body. Cancellation retains it until any surviving CPU work has finished.
        admission = _ADMISSION
        worker: Future[Any] | None = None
        try:
            try:
                body = await asyncio.wait_for(
                    _read_body(receive, self.max_body_bytes), self.body_timeout_seconds
                )
            except asyncio.TimeoutError:
                return await _send_status(send, 408, "request body read timed out")
            if body is _TOO_LARGE:
                return await _send_status(send, 413, "request body too large")
            if body is _DISCONNECTED:
                return await self.app(scope, _replay_disconnect(), send)
            assert isinstance(body, bytes)
            worker = _WORKERS.submit(partial(self._prepare_body, body))
            if worker is None:
                return await _send_status(
                    send, 503, "input inspection capacity exhausted"
                )
            # Do not cancel the concurrent future: cancelled executor queue items
            # can retain their payload after releasing an apparent worker slot.
            pending = asyncio.wrap_future(worker)
            try:
                prepared = await asyncio.shield(pending)
            except asyncio.CancelledError:
                pending.add_done_callback(
                    lambda result: None if result.cancelled() else result.exception()
                )
                raise
            del body
            if prepared.report is not None and prepared.decision is not None:
                if self.on_decision is not None:
                    self.on_decision(prepared.decision, prepared.report)
            if isinstance(prepared, _RejectedRequest):
                return await _send_status(send, prepared.status, prepared.detail)
            if prepared.report is None or prepared.decision is None:
                return await self.app(scope, _replay_body(prepared.body, receive), send)
            srep = prepared.report
            decision = prepared.decision
            new_body = prepared.body

            async def send_wrapper(message: dict[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    message = dict(message)
                    headers = list(message.get("headers", []))
                    message["headers"] = headers

                    def add(k: str, v: str) -> None:
                        headers.append((k.encode("latin-1"), v.encode("latin-1")))

                    add("x-sanitize-changed", str(srep["changed"]).lower())
                    add("x-tokens-before", str(prepared.tokens_before))
                    add("x-tokens-after", str(prepared.tokens_after))
                    add("x-enforcement-action", str(decision["action"]))
                await send(message)

            updated_scope = _set_content_length(scope, len(new_body))
            state = dict(scope.get("state", {}))
            state["llm_input_hardening"] = {"decision": decision, "report": srep}
            updated_scope["state"] = state
            return await self.app(
                updated_scope, _replay_body(new_body, receive), send_wrapper
            )
        finally:
            if worker is None or worker.done():
                admission.release()
            else:
                worker.add_done_callback(lambda _: admission.release())


# Backward-compatible alias: the middleware never required Starlette.
StarlettePromptSanitizerMiddleware = ASGIPromptSanitizerMiddleware
