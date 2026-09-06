# Gateway Recipe

Sanitize inbound JSON recursively and enforce on reason codes.

```python
from llm_input_hardening import sanitize_json
from llm_input_hardening.enforcement import decide_enforcement

clean_payload, report = sanitize_json(
    request_payload,
    policy="balanced_chat",
    max_nodes=10_000,
    max_total_chars=1_000_000,
    max_path_reports=5_000,
    max_report_chars=1_000_000,
)
decision = decide_enforcement(report)
if decision["action"] != "allow":
    raise ValueError({"reason_codes": decision["reason_codes"]})
```

Recommended split:
- user chat content: `balanced_chat`
- tool args / privileged ops: `strict_exec`

`decide_enforcement` uses the report's sanitization policy unless you supply an
explicit enforcement policy. Handle `quarantine` by holding the request for review
or rejecting it; the decision helper does not create a review queue.

Apply `sanitize_json` to an already-selected untrusted payload. It rewrites string
keys and values, so a full model-request envelope containing trusted roles or
authorization metadata should instead use explicit text selectors through the
[ASGI middleware](../integrations.md). Validate envelope fields with your schema.
Catch resource-budget and key-collision `ValueError`s at the boundary and return a
client error; do not fall back to submitting the original payload.
