from __future__ import annotations

import asyncio
import contextvars
import importlib
import json
import subprocess
import sys
import textwrap
import threading

import pytest

from llm_input_hardening.middleware import StarlettePromptSanitizerMiddleware


def _run_middleware(
    body: bytes, *, field: str = "prompt"
) -> tuple[dict[str, object], list[dict[str, object]]]:
    captured: dict[str, object] = {}
    sent_messages: list[dict[str, object]] = []

    async def app(scope, receive, send):
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                continue
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        captured["scope"] = scope
        captured["body"] = b"".join(chunks)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("latin-1")),
        ],
    }
    middleware = StarlettePromptSanitizerMiddleware(
        app,
        field=field,
        policy="balanced_chat",
        limit_tokens=32,
    )
    asyncio.run(middleware(scope, receive, send))
    return captured, sent_messages


def test_middleware_rewrites_json_body_and_content_length() -> None:
    original = json.dumps({"prompt": "abc\u202edef"}).encode("utf-8")
    captured, sent_messages = _run_middleware(original)

    rewritten = json.loads(captured["body"])
    assert rewritten["prompt"] == "abcdef"

    headers = dict(captured["scope"]["headers"])
    assert headers[b"content-length"] == str(len(captured["body"])).encode("latin-1")

    response_start = next(
        msg for msg in sent_messages if msg["type"] == "http.response.start"
    )
    response_headers = dict(response_start["headers"])
    assert response_headers[b"x-sanitize-changed"] == b"true"
    assert int(response_headers[b"x-tokens-before"]) >= int(
        response_headers[b"x-tokens-after"]
    )


def test_middleware_replays_original_body_when_field_missing() -> None:
    original = json.dumps({"other": "value"}).encode("utf-8")
    captured, sent_messages = _run_middleware(original)

    assert captured["body"] == original
    response_start = next(
        msg for msg in sent_messages if msg["type"] == "http.response.start"
    )
    assert response_start["headers"] == []


def test_middleware_rewrites_nested_json_field_path() -> None:
    original = json.dumps({"messages": [{"content": "abc\u202edef"}]}).encode("utf-8")
    captured, _ = _run_middleware(original, field="messages[0].content")

    rewritten = json.loads(captured["body"])
    assert rewritten["messages"][0]["content"] == "abcdef"


def test_middleware_body_read_stops_on_disconnect() -> None:
    from llm_input_hardening.middleware import _DISCONNECTED, _read_body

    async def receive():
        return {"type": "http.disconnect"}

    # A disconnect returns a sentinel, never a (possibly truncated) partial body,
    # so the caller does not parse and forward incomplete JSON.
    body = asyncio.run(_read_body(receive, 1024))
    assert body is _DISCONNECTED


def _run_with_middleware(mw, body: bytes, *, content_length=None):
    """Drive a preconstructed middleware instance and return sent messages."""
    sent_messages: list[dict[str, object]] = []
    delivered = False

    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                if message["type"] == "http.disconnect":
                    break
                continue
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent_messages.append(message)

    cl = len(body) if content_length is None else content_length
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(cl).encode("latin-1")),
        ],
    }
    asyncio.run(mw(scope, receive, send))
    return sent_messages


def test_middleware_rejects_oversized_body_with_413() -> None:
    from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

    async def app(scope, receive, send):  # pragma: no cover - must not run
        raise AssertionError("oversized body should not reach the app")

    mw = ASGIPromptSanitizerMiddleware(app, max_body_bytes=16)
    body = json.dumps({"prompt": "x" * 100}).encode("utf-8")
    sent = _run_with_middleware(mw, body)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413


def test_middleware_enforce_blocks_reject_with_403() -> None:
    from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

    async def app(scope, receive, send):  # pragma: no cover - must not run
        raise AssertionError("rejected request should not reach the app")

    mw = ASGIPromptSanitizerMiddleware(app, policy="strict_exec", enforce=True)
    body = json.dumps({"prompt": "‮evil"}).encode("utf-8")
    sent = _run_with_middleware(mw, body)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 403


def test_middleware_on_decision_callback_invoked() -> None:
    from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

    seen = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = ASGIPromptSanitizerMiddleware(
        app, on_decision=lambda decision, report: seen.append(decision["action"])
    )
    body = json.dumps({"prompt": "hello world"}).encode("utf-8")
    _run_with_middleware(mw, body)
    assert seen == ["allow"]


def _request(body: bytes, *, content_type=b"application/json", path="/chat", **options):
    captured = {}
    messages = []
    upstream = [
        {"type": "http.request", "body": body, "more_body": False},
        {"type": "http.disconnect"},
    ]

    async def receive():
        return upstream.pop(0)

    async def send(message):
        messages.append(message)

    async def app(scope, receive, send):
        captured["state"] = scope.get("state", {})
        captured["body"] = (await receive())["body"]
        captured["after_body"] = await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    headers = [] if content_type is None else [(b"content-type", content_type)]
    middleware = StarlettePromptSanitizerMiddleware(app, **options)
    asyncio.run(
        middleware({"type": "http", "path": path, "headers": headers}, receive, send)
    )
    return messages[0]["status"], captured, messages


@pytest.mark.parametrize(
    "content_type",
    [
        b"application/json",
        b"application/vnd.api+json",
        b"APPLICATION/PROBLEM+JSON; charset=utf-8",
    ],
)
def test_enforcement_covers_json_media_types(content_type) -> None:
    body = json.dumps({"prompt": "abc\u202edef"}).encode()
    status, captured, _ = _request(body, content_type=content_type, enforce=True)
    assert status == 403
    assert captured == {}


@pytest.mark.parametrize(
    "content_type",
    [None, b"text/plain", b"application/json-invalid", b"text/application/json"],
)
def test_enforcement_rejects_uninspected_content_types(content_type) -> None:
    status, captured, _ = _request(
        b'{"prompt":"hello"}', content_type=content_type, enforce=True
    )
    assert status == 415
    assert captured == {}


@pytest.mark.parametrize("body", [b"", b"{", b"\xff", b'{"prompt":NaN}'])
def test_enforcement_rejects_invalid_json(body) -> None:
    status, captured, _ = _request(body, enforce=True)
    assert status == 400
    assert captured == {}


@pytest.mark.parametrize(
    "body", [b"{}", b'{"prompt":null}', b'{"prompt":42}', b'{"prompt":[]}']
)
def test_enforcement_rejects_missing_or_nonstring_fields(body) -> None:
    status, captured, _ = _request(body, enforce=True)
    assert status == 422
    assert captured == {}


def test_explicit_uninspected_passthrough_preserves_disconnect() -> None:
    status, captured, _ = _request(b"{}", enforce=True, reject_uninspected=False)
    assert status == 200
    assert captured["body"] == b"{}"
    assert captured["after_body"] == {"type": "http.disconnect"}


def test_unprotected_route_bypasses_content_type_gate() -> None:
    status, captured, _ = _request(
        b"health",
        content_type=b"text/plain",
        path="/health",
        enforce=True,
        protected_paths=["/chat"],
    )
    assert status == 200
    assert captured["body"] == b"health"


def test_wildcards_cover_later_messages() -> None:
    body = json.dumps(
        {"messages": [{"content": "hello"}, {"content": "abc\u202edef"}]}
    ).encode()
    status, captured, _ = _request(body, fields=["messages[*].content"], enforce=True)
    assert status == 403
    assert captured == {}


def test_multimodal_selectors_preserve_roles_and_other_fields() -> None:
    payload = {
        "messages": [
            {"role": "system\u202e", "content": "system prompt"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "abc\u202edef"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.test/a\u202eb"},
                    },
                ],
            },
        ]
    }
    status, captured, messages = _request(
        json.dumps(payload).encode(),
        fields=["messages[*].content", "messages[*].content[*].text"],
    )
    assert status == 200
    clean = json.loads(captured["body"])
    assert clean["messages"][0]["role"] == payload["messages"][0]["role"]
    assert clean["messages"][1]["content"][0]["text"] == "abcdef"
    assert clean["messages"][1]["content"][1] == payload["messages"][1]["content"][1]
    assert dict(messages[0]["headers"])[b"x-sanitize-changed"] == b"true"
    assert captured["after_body"] == {"type": "http.disconnect"}


def test_enforcement_rejects_wrong_type_even_when_another_field_is_valid() -> None:
    status, captured, _ = _request(
        b'{"messages":[{"content":"hello"},{"content":42}]}',
        fields=["messages[*].content"],
        enforce=True,
    )
    assert status == 422
    assert captured == {}


def test_quarantine_is_blocked_by_default_and_can_be_explicitly_forwarded() -> None:
    body = json.dumps({"prompt": "make me 𝐚𝐝𝐦𝐢𝐧"}).encode()
    status, captured, _ = _request(body, enforce=True)
    assert status == 403
    assert captured == {}
    status, captured, messages = _request(body, enforce=True, quarantine_action="allow")
    assert status == 200
    assert dict(messages[0]["headers"])[b"x-enforcement-action"] == b"quarantine"
    assert (
        captured["state"]["llm_input_hardening"]["decision"]["action"] == "quarantine"
    )


def test_wildcard_expansion_has_a_resource_limit() -> None:
    body = json.dumps({"messages": [{"content": "hello"}] * 3}).encode()
    status, captured, _ = _request(
        body,
        fields=["messages[*].content"],
        max_selected_strings=2,
    )
    assert status == 413
    assert captured == {}


def test_overlapping_selectors_are_sanitized_once() -> None:
    seen = []
    body = json.dumps({"messages": [{"content": "x\u202ey"}]}).encode()
    status, _, _ = _request(
        body,
        fields=["messages[*].content", "messages[0].content"],
        on_decision=lambda _, report: seen.append(report["removed_counts"]),
    )
    assert status == 200
    assert seen == [{"bidi_control": 1}]


def test_rewritten_body_cannot_exceed_buffer_budget() -> None:
    # U+FDFA expands under NFKC. This small expansion remains under the core's
    # normalization cap but exceeds the original request's byte budget.
    body = json.dumps({"prompt": "\ufdfa"}, ensure_ascii=False).encode()
    status, captured, _ = _request(body, policy="strict_exec", max_body_bytes=len(body))
    assert status == 413
    assert captured == {}


@pytest.mark.parametrize(
    "body", [b'{"prompt":"\\ud800"}', b'{"prompt":"ok","other":"\\ud800"}']
)
def test_unpaired_surrogates_return_a_client_error(body) -> None:
    status, captured, _ = _request(body, enforce=True)
    assert status == 400
    assert captured == {}


@pytest.mark.parametrize(
    "field",
    [
        "",
        ".prompt",
        "prompt.",
        "messages[0]content",
        "messages..content",
        "messages[-1].content",
    ],
)
def test_invalid_field_selectors_fail_at_configuration(field) -> None:
    with pytest.raises(ValueError, match="selector"):
        StarlettePromptSanitizerMiddleware(None, field=field)


def test_streaming_response_observes_disconnect_without_starving_event_loop() -> None:
    # A subprocess timeout is necessary: an immediate synthetic receive loop can
    # starve asyncio's own timeout machinery, which is the regression under test.
    script = textwrap.dedent("""
        import asyncio
        from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

        async def main():
            events = asyncio.Queue()
            await events.put({"type": "http.request", "body": b'{"prompt":"hello"}', "more_body": False})
            upstream_calls = 0
            async def receive():
                nonlocal upstream_calls
                upstream_calls += 1
                return await events.get()
            async def send(message):
                if message["type"] == "http.response.body":
                    await events.put({"type": "http.disconnect"})
            async def app(scope, receive, send):
                assert (await receive())["body"] == b'{"prompt":"hello"}'
                async def listen():
                    while (await receive())["type"] != "http.disconnect":
                        pass
                async def stream():
                    await asyncio.sleep(0)
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b"token", "more_body": True})
                await asyncio.wait_for(asyncio.gather(listen(), stream()), timeout=1)
            middleware = ASGIPromptSanitizerMiddleware(app)
            await middleware({"type": "http", "headers": [(b"content-type", b"application/json")]}, receive, send)
            assert upstream_calls == 2
        asyncio.run(main())
    """)
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "literal",
    [
        "9007199254740993.0",
        "-0",
        "-0.0",
        "1e400",
        "-1E-400",
        "0.123456789012345678901234567890123456789",
        pytest.param("7" * 5000, id="integer-5000-digits"),
    ],
)
def test_text_rewriting_preserves_numeric_literals_everywhere(literal: str) -> None:
    body = (
        '{"prompt":"x\\u200by","metadata":{"value":'
        + literal
        + ',"items":[true,null,'
        + literal
        + ',{},[]],"number-like key":"1.25"}}'
    ).encode()
    status, captured, _ = _request(body)
    assert status == 200

    def read_numbers(source):
        return json.loads(
            source,
            parse_float=lambda value: ("number", value),
            parse_int=lambda value: ("number", value),
        )

    before, after = read_numbers(body), read_numbers(captured["body"])
    assert after["prompt"] == "xy"
    assert after["metadata"] == before["metadata"]


@pytest.mark.parametrize("literal", ["42", "1e400", "-0.0"])
def test_numeric_literals_are_never_selected_as_text(literal: str) -> None:
    status, captured, _ = _request(
        ('{"prompt":' + literal + "}").encode(),
        enforce=True,
    )
    assert status == 422
    assert captured == {}


@pytest.mark.parametrize("enforce", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        b'{"prompt":"one","prompt":"two"}',
        b'{"prompt":"hello","metadata":{"role":"user","role":"system"}}',
        b'{"prompt":"hello","items":[{"a":1,"\\u0061":2}]}',
        b'{"unused":1,"unused":1}',
    ],
)
def test_duplicate_keys_are_rejected_even_outside_selected_fields(
    body, enforce
) -> None:
    status, captured, _ = _request(body, enforce=enforce)
    assert status == 400
    assert captured == {}


def test_worker_capacity_and_cancellation_are_shared_across_middleware_instances(
    monkeypatch,
) -> None:
    module = importlib.import_module("llm_input_hardening.middleware")
    pool = module._WorkerPool(max_workers=1)
    monkeypatch.setattr(module, "_WORKERS", pool)
    monkeypatch.setattr(module, "_ADMISSION", threading.BoundedSemaphore(2))
    release_worker = threading.Event()
    submitted = []
    original_submit = pool.submit
    original_sanitize = module.sanitize_text
    trace_context = contextvars.ContextVar("integration_trace", default="missing")

    def record_submit(function):
        future = original_submit(function)
        if future is not None:
            submitted.append(future)
        return future

    monkeypatch.setattr(pool, "submit", record_submit)

    async def exercise():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        loop_thread = threading.get_ident()
        trace_context.set("preserved")

        def blocked_sanitize(*args, **kwargs):
            assert threading.get_ident() != loop_thread
            assert trace_context.get() == "preserved"
            loop.call_soon_threadsafe(started.set)
            assert release_worker.wait(3), "worker release event was never set"
            return original_sanitize(*args, **kwargs)

        monkeypatch.setattr(module, "sanitize_text", blocked_sanitize)

        async def request(middleware):
            messages = []

            async def receive():
                return {
                    "type": "http.request",
                    "body": b'{"prompt":"hello"}',
                    "more_body": False,
                }

            async def send(message):
                messages.append(message)

            await middleware(
                {"type": "http", "headers": [(b"content-type", b"application/json")]},
                receive,
                send,
            )
            return messages[0]["status"]

        async def app(scope, receive, send):
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        first = module.ASGIPromptSanitizerMiddleware(app)
        second = module.ASGIPromptSanitizerMiddleware(app)
        running = asyncio.create_task(request(first))
        try:
            await asyncio.wait_for(started.wait(), 1)
            # The ASGI loop can handle another request while the CPU worker waits.
            assert await asyncio.wait_for(request(second), 1) == 503
            running.cancel()
            with pytest.raises(asyncio.CancelledError):
                await running
            # Cancelling the requester does not free the still-running worker.
            assert await asyncio.wait_for(request(second), 1) == 503
            assert len(submitted) == 1
            release_worker.set()
            await asyncio.wrap_future(submitted[0])
            assert await request(second) == 200
        finally:
            release_worker.set()
            if not running.done():
                running.cancel()
                await asyncio.gather(running, return_exceptions=True)

    try:
        asyncio.run(exercise())
    finally:
        release_worker.set()
        pool.executor.shutdown(wait=True, cancel_futures=True)


def test_global_admission_rejects_before_reading_and_recovers_on_upload_cancellation(
    monkeypatch,
) -> None:
    module = importlib.import_module("llm_input_hardening.middleware")
    monkeypatch.setattr(module, "_ADMISSION", threading.BoundedSemaphore(1))

    async def exercise():
        upload_started = asyncio.Event()
        never = asyncio.Event()

        async def stalled_receive():
            upload_started.set()
            await never.wait()

        async def no_read():
            pytest.fail("an overloaded request must not start buffering")

        async def app(*args):
            pytest.fail("these requests must not reach the app")

        messages = []

        async def send(message):
            messages.append(message)

        scope = {"type": "http", "headers": [(b"content-type", b"application/json")]}
        first = module.ASGIPromptSanitizerMiddleware(app)
        second = module.ASGIPromptSanitizerMiddleware(app)
        pending = asyncio.create_task(first(scope, stalled_receive, send))
        try:
            await asyncio.wait_for(upload_started.wait(), 1)
            await second(scope, no_read, send)
            assert messages[0]["status"] == 503
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        finally:
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)

    asyncio.run(exercise())
    assert _request(b'{"prompt":"hello"}')[0] == 200


def test_body_read_timeout_returns_408_and_releases_admission(monkeypatch) -> None:
    module = importlib.import_module("llm_input_hardening.middleware")
    monkeypatch.setattr(module, "_ADMISSION", threading.BoundedSemaphore(1))

    async def exercise():
        async def receive():
            await asyncio.Event().wait()

        async def app(*args):
            pytest.fail("a timed-out request must not reach the app")

        messages = []

        async def send(message):
            messages.append(message)

        await module.ASGIPromptSanitizerMiddleware(app, body_timeout_seconds=0.01)(
            {"type": "http", "headers": [(b"content-type", b"application/json")]},
            receive,
            send,
        )
        assert messages[0]["status"] == 408

    asyncio.run(exercise())
    assert _request(b'{"prompt":"hello"}')[0] == 200


def test_callback_runs_on_asgi_thread_and_can_prevent_forwarding() -> None:
    asgi_thread = threading.get_ident()

    def callback(decision, report):
        assert threading.get_ident() == asgi_thread
        raise RuntimeError("review service unavailable")

    with pytest.raises(RuntimeError, match="review service unavailable"):
        _request(b'{"prompt":"hello"}', on_decision=callback)


@pytest.mark.parametrize("timeout", [0, -1, True, float("inf"), float("nan")])
def test_body_timeout_validates_configuration(timeout) -> None:
    with pytest.raises(ValueError, match="body_timeout_seconds"):
        StarlettePromptSanitizerMiddleware(None, body_timeout_seconds=timeout)


def test_admission_stays_reserved_while_downstream_apps_hold_bodies(
    monkeypatch,
) -> None:
    module = importlib.import_module("llm_input_hardening.middleware")
    monkeypatch.setattr(module, "_ADMISSION", threading.BoundedSemaphore(16))

    async def exercise():
        entered = asyncio.Queue()
        release_apps = asyncio.Event()
        tasks = []
        scope = {"type": "http", "headers": [(b"content-type", b"application/json")]}

        async def app(scope, receive, send):
            entered.put_nowait(True)
            await release_apps.wait()
            await receive()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        middleware = module.ASGIPromptSanitizerMiddleware(app)

        async def request(receive):
            messages = []

            async def send(message):
                messages.append(message)

            await middleware(scope, receive, send)
            return messages[0]["status"]

        async def receive():
            return {
                "type": "http.request",
                "body": b'{"prompt":"hello"}',
                "more_body": False,
            }

        async def no_read():
            pytest.fail("request 17 must be rejected before its body is read")

        try:
            for _ in range(16):
                tasks.append(asyncio.create_task(request(receive)))
                # Entering the app proves CPU preparation has already completed.
                await asyncio.wait_for(entered.get(), 1)
            assert await request(no_read) == 503
            release_apps.set()
            assert await asyncio.gather(*tasks) == [200] * 16
        finally:
            release_apps.set()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(exercise())
    assert _request(b'{"prompt":"hello"}')[0] == 200


def test_repeated_long_paths_cannot_amplify_aggregate_report() -> None:
    payload = {"a" * 10_000: [""] * 1000}
    status, captured, _ = _request(
        json.dumps(payload).encode(),
        fields=["*[*]"],
        max_report_chars=100_000,
    )
    assert status == 413
    assert captured == {}


def test_single_string_diagnostics_follow_report_budget_too() -> None:
    status, captured, _ = _request(b'{"prompt":"hello"}', max_report_chars=10)
    assert status == 413
    assert captured == {}
