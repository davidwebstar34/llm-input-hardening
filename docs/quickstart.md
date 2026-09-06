# Quickstart

## Sanitize text before prompt construction

```python
from llm_input_hardening import sanitize

clean, report = sanitize(user_text, policy="balanced_chat")
```

## Sanitize nested JSON-like payloads

```python
from llm_input_hardening import sanitize_json

clean_payload, report = sanitize_json(payload, policy="balanced_chat")
```

## Add an enforcement decision

```python
from llm_input_hardening import sanitize_and_decide

clean, report, decision = sanitize_and_decide(
    user_text,
    sanitize_policy="strict_exec",
    confusables_backend="confusable_homoglyphs",
)
```

## Use middleware in an HTTP stack

```python
from fastapi import FastAPI
from llm_input_hardening.middleware import ASGIPromptSanitizerMiddleware

app = FastAPI()
app.add_middleware(
    ASGIPromptSanitizerMiddleware,
    field="prompt",
    policy="balanced_chat",
    limit_tokens=128_000,
)
```
