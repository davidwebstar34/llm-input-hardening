# Threat Model (Text Integrity)

This project addresses text-level integrity failures before model invocation.

Deep dives:

- [Unicode threat model](threat-model/unicode.md)
- [Safe display guide](threat-model/safe-display.md)
- [Security limitations](security/limitations.md)
- [Hardening contract and regression strategy](security/hardening-contract.md)

## In scope

- Unicode ambiguity and compatibility bypasses
- bidi control abuse
- hidden/invisible character injection
- control-character prompt boundary corruption
- obfuscation-shaped payload signals (entropy, base64-like, combining storms, confusables)

## Out of scope

- semantic moderation
- jailbreak intent interpretation
- policy enforcement over model output
- tool sandboxing and access control

## Design constraints

- deterministic transforms for identical input + config
- stable report schema for observability pipelines
- minimal overhead suitable for inline gateway execution
