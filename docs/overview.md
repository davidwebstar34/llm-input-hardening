# Overview

`llm-input-hardening` is a deterministic text integrity layer for LLM applications.

It focuses on character-level hardening before prompt construction:
- canonical normalization
- invisible/control character cleanup
- obfuscation signal detection
- structured, stable reporting

It does not perform moderation or semantic jailbreak prevention.

## Presets

- `balanced_chat`: preserves linguistic joiners and emoji variation selectors.
- `strict_exec`: aggressive cleanup for tool arguments and execution-adjacent paths.

## Quick start

```python
from llm_input_hardening import sanitize

clean, report = sanitize(user_text, policy="balanced_chat")
```

For recursive gateway payloads:

```python
from llm_input_hardening import sanitize_json

clean_payload, report = sanitize_json(payload, policy="balanced_chat")
```
