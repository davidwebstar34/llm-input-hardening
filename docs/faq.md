# FAQ

## Does this stop prompt injection?

No. It addresses text integrity only, not semantic intent.

## Does it run moderation or policy engines?

No. It emits deterministic signals that other systems can consume.

## Should I always use `strict_exec`?

No. Use `balanced_chat` for normal user-facing chat. Use `strict_exec` for high-risk execution contexts.

## Can I sanitize nested gateway payloads?

Yes. Use `sanitize_json()` to sanitize string keys and values. Sanitized-key
collisions fail with `ValueError` instead of overwriting a value.
