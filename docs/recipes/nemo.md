# Nemo Guardrails Recipe

Use `llm-input-hardening` before input reaches Nemo guardrails.

```python
from llm_input_hardening import sanitize

clean_text, report = sanitize(user_text, policy="balanced_chat")
# pass clean_text into Nemo rails.generate(...)
```

This preserves architecture boundaries:
- deterministic text integrity first
- semantic policy and moderation later in guardrail frameworks
