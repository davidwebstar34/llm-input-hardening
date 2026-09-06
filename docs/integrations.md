# Integrations

This project is most useful when it runs **automatically** on every inbound user input.

---

## FastAPI / Starlette middleware

Select the text fields in your request schema and restrict middleware to the
routes that accept those requests. Message roles, model names, and authorization
metadata should be validated by your application, rather than rewritten as text.

Example:

```python
from fastapi import FastAPI
from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

app = FastAPI()
app.add_middleware(
    ASGIPromptSanitizerMiddleware,
    protected_paths=["/chat"],
    fields=["messages[*].content", "messages[*].content[*].text"],
    policy="balanced_chat",
    limit_tokens=128_000,             # measurement only
    max_body_bytes=4 * 1024 * 1024,   # input and rewritten output limits
    max_report_chars=4 * 1024 * 1024, # serialized diagnostic budget
    body_timeout_seconds=10.0,       # complete body-read deadline
    enforce=True,                    # reject and quarantine return HTTP 403
    on_decision=lambda decision, report: None,  # hook for logging/metrics
)
```

`ASGIPromptSanitizerMiddleware` works with asyncio-based ASGI applications and
has no Starlette dependency. Its bounded worker adapter requires asyncio;
Trio-only runtimes need their own adapter. `StarlettePromptSanitizerMiddleware`
remains an alias.

### Request mutation semantics

The middleware:
- inspects all HTTP paths by default; `protected_paths` selects exact URL paths
- accepts `application/json` and `application/*+json`, including charset parameters
- bounds buffered input and rewritten output to `max_body_bytes` (HTTP 413)
- supports a single `field="prompt"` or a sequence of `fields` with dotted paths,
  indexes, and `*` wildcards
- sanitizes every matched string once; fields outside the selectors are unchanged
- preserves JSON numeric literals exactly, including large integers, decimals,
  signed zero and exponents; downstream schema/range validation still applies
- rejects duplicate object keys anywhere with HTTP 400 in every mode
- bounds serialized diagnostics with `max_report_chars` (HTTP 413), including
  long repeated JSON paths
- supports alternative selectors for string content and multimodal text blocks;
  a selected container must contain a string covered by a more specific selector
- bounds wildcard expansion and selected strings with `max_selected_strings`
  (10,000 by default; excess returns HTTP 413)
- with `enforce=True`, rejects missing/unsupported Content-Type (415), invalid JSON
  (400), and missing or incorrectly typed selected inputs (422)
- blocks both `reject` and `quarantine` decisions with HTTP 403 when enforcing
- preserves the ASGI receive lifecycle, including streaming client disconnects
- exposes the decision and report through
  `scope["state"]["llm_input_hardening"]` (FastAPI/Starlette:
  `request.state.llm_input_hardening`)
- adds response headers:
  - `x-sanitize-changed: true|false`
  - `x-tokens-before: <int>`
  - `x-tokens-after: <int>`
  - `x-enforcement-action: allow|quarantine|reject`

The field selectors must cover every text location your endpoint sends to the
model. These selectors deliberately leave fields such as `role`, `type`, and
`image_url` untouched; this library does not inspect image/audio payloads or decide
whether the caller may set a message role. Validate those with your request schema
and authorization rules. If none of the configured selectors finds text, enforcing
middleware rejects the request, including requests containing only media blocks.

`reject_uninspected` defaults to the value of `enforce`. Set it explicitly to
`False` only when another boundary validates uninspected requests. With
`enforce=False`, missing fields, invalid JSON, and unsupported Content-Type pass
through for compatibility, while inspected text is still sanitized and reported.
Duplicate object keys are always rejected because their interpretation is ambiguous.

`quarantine_action="allow"` explicitly forwards quarantine decisions to the app.
It does not create a review queue: the app must route the request using the decision
in request state. The default `"reject"` prevents quarantined input reaching the
app. `on_decision` runs once for each inspected request, with counts aggregated
across selected fields.

Parsing, sanitization, serialization and token measurement run in a process-wide
pool of four workers, with no waiting CPU-job queue. A separate shared admission
limit permits at most 16 requests to hold buffered input through inspection and
downstream processing. Capacity exhaustion returns HTTP 503 before further work.
Cancellation retains capacity until any running worker actually finishes; slow
downstream applications retain admission until they finish too.

`body_timeout_seconds` defaults to ten seconds for the complete body read and
returns HTTP 408 on timeout. It is not a total request or CPU deadline. The
`on_decision` callback runs on the ASGI task and should complete promptly; its
errors propagate and prevent forwarding. These per-process bounds complement
your server's request limits and application-specific rate controls.

Token headers count selected strings only. `limit_tokens` supplies measurement
metadata and **does not reject an over-budget request**. For an actual context
budget, count the complete model request with the correct tokenizer, reserve output
tokens, and enforce that budget separately. `strict_tokenizer=True` makes tokenizer
unavailability/errors fail rather than using an estimate.

---

## LangChain

Where to plug in:
- before you format prompt templates
- before you append user inputs to memory
- before tool/function argument strings are passed to an LLM

Pattern:

```python
clean, report = sanitize(user_text)
chain.invoke({"input": clean})
```

Enforcement pattern:

```python
from llm_input_hardening import sanitize_and_decide

clean, report, decision = sanitize_and_decide(
    user_text,
    sanitize_policy="strict",
    confusables_backend="confusable_homoglyphs",
)
if decision["action"] != "allow":
    # route to human review / challenge flow
    ...
```

---

## Tool calling / function calling

Sanitize *every* untrusted string:
- user instructions
- retrieved documents (indirect injection risk)
- tool arguments

For full nested payload coverage, use `sanitize_json(obj)` to sanitize every
string key and value. Its report includes `stats["json_path_reports"]`, with
entries such as `{"path": "messages[2].content", ...}`. Changed keys use a
`<key>` suffix; if two keys sanitize to the same value, the call raises
`ValueError` rather than overwriting data. The iterative walker bounds depth
(1,000), nodes including keys (100,000), total input and output string characters
(4 Mi), path reports (10,000), and serialized path-report characters (4 Mi) by
default. Configure `max_depth`, `max_nodes`, `max_total_chars`, `max_path_reports`,
and `max_report_chars` for your workload. Exceeding a budget raises `ValueError`;
the input is unchanged and no partially sanitized object is returned. Individual
strings also follow the text sanitizer's size and span limits.

With `return_spans=True`, spans are retained in each entry of
`stats["json_path_reports"]`, where offsets refer to that individual string.
Encoded Unicode samples use separate character offsets in the named source
string. The top-level `spans` list stays empty because a JSON tree has
no single string-offset coordinate system.

## RAG warning (retrieved text)

If you use retrieval, treat retrieved text as **untrusted**:
- sanitize it before it enters the prompt
- consider separate policies/thresholds for retrieved sources
- log flags by document source to find compromised content
