# Unicode Threat Model

This page defines the Unicode-focused adversary model for this project.

## Security objective

Reduce ambiguity and stealth text channels before downstream LLM safety and policy layers run.

## Adversary goals

- Hide or reorder instructions visually (`bidi_control`, invisible controls).
- Evade naive string matching via confusables and mixed scripts.
- Smuggle encoded payloads (base64/hex/high-entropy blobs).
- Degrade reviewability with combining-mark storms and rendering edge cases.
- Create copy/paste traps where displayed text differs from logical text.

## Adversary constraints

- Operates at text layer only (no privileged runtime access required).
- Can submit arbitrary Unicode strings through user inputs, documents, tool args, or logs.
- Relies on renderer/tokenizer differences and human review blind spots.

## In-scope classes

### Homoglyphs and confusables

- Mixed-script confusable words (for example Latin + Cyrillic lookalikes).
- Restriction-level analysis is exposed as telemetry for risk scoring.

### Bidi controls and isolate hazards

- Embedding/override controls (`RLO`, `LRO`, etc.).
- Isolates (`LRI/RLI/FSI/PDI`) including unpaired/mismatched patterns.
- Goal: prevent Trojan Source-style visual reorder tricks.

### Default-ignorables

- Joiners (`ZWJ`, `ZWNJ`)
- Variation selectors (including extended selectors)
- Tag characters
- `strict_exec` removes them; free-text policies may preserve selected characters.

### Encoded payload signals

- Base64-like blocks
- Hex-only blocks
- High-entropy windows

These are detection signals, not semantic malware classification.

### Combining mark abuse

- Excessive combining marks used to distort rendering and token boundaries.
- Flagged with ratio-based heuristic.

## Out of scope

- Prompt injection prevention as a complete semantic defense.
- Moderation/policy decisions by meaning.
- Tool sandboxing, capability isolation, or output-policy enforcement.
- Deobfuscating arbitrary encodings beyond scoped heuristics.

## Non-goal reminder

This project is a deterministic text-integrity layer, not a standalone prompt-injection prevention system.
