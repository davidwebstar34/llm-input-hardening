# Security Limitations

This project is text-level hardening, not a full prompt-injection defense.

## What it does not guarantee

- It does not prove semantic intent safety.
- It does not guarantee model obedience to system/developer instructions.
- It does not sandbox tools, credentials, or downstream side effects.
- It does not replace application authorization checks.

## Required downstream controls

Use this library together with:

- strict output validation (schemas, allowlists, type/range checks)
- least-privilege tool access and scoped credentials
- enforcement policy (`allow` / `quarantine` / `reject`) on suspicious inputs
- logging/monitoring and alerting for signal spikes

## Practical stance

Treat sanitizer signals as one control layer in a defense-in-depth stack, not a final gate.
