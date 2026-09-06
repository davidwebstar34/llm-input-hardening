# Telemetry Helper

`to_otel_attributes(report)` converts a sanitize report into low-cardinality attributes:
- totals
- stable reason codes
- no raw text

## OpenTelemetry example

```python
from llm_input_hardening import sanitize, to_otel_attributes

clean, report = sanitize(user_text, policy="balanced_chat")
attrs = to_otel_attributes(report)
span.set_attributes(attrs)
```

## Langfuse example

```python
from llm_input_hardening import sanitize, to_otel_attributes

clean, report = sanitize(user_text, policy="balanced_chat")
langfuse.trace(name="sanitize", metadata=to_otel_attributes(report))
```

## Gateway logging pattern

```python
clean_payload, report = sanitize_json(payload, policy="strict_exec")
logger.info("sanitize_report", extra=to_otel_attributes(report))
```
