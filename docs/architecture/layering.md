# Layering

Text integrity should run before orchestration and model safety layers.

```mermaid
flowchart LR
    A["Untrusted Input (user, tool args, retrieval)"] --> B["Text Integrity Layer<br/>llm-input-hardening"]
    B --> C["Prompt Assembly / Orchestration"]
    C --> D["Model + Safety/Moderation Layer"]
    D --> E["Output Validation + Tool Policy"]
```

`llm-input-hardening` is intentionally narrow:
- sanitize text deterministically
- emit signals and counts
- never make semantic policy claims
