# Langfuse Recipe

Attach sanitize telemetry to traces without logging raw text.

```python
from llm_input_hardening import sanitize, to_otel_attributes

clean, report = sanitize(user_text, policy="balanced_chat")
attrs = to_otel_attributes(report)

langfuse.trace(
    name="chat_request",
    metadata=attrs,
)
```

Store only counts/codes to keep cardinality and privacy manageable.
