# Detection Boundary

The sanitizer has two detection layers by design:

1. **Rust core:** deterministic Unicode transforms and low-level signals that
   must run for every call before Python decoration. This includes bidi/control
   removal, bounded Unicode normalization, default-ignorable handling, Unicode
   space tidying, base64-ish runs, prefix entropy, and combining-mark ratio/stacks.
2. **Python decoration:** signals that either depend on optional Python packages
   or are easier to evolve without changing the core ABI. This includes hex and
   alt-encoded blob shapes, sliding-window entropy, mixed-script/confusable
   analysis, styled-compatibility checks, reason-code derivation, enforcement
   helpers, JSON key/value traversal, middleware, and CLI behavior.

The contract is:

- Text mutation happens in Rust. JSON traversal applies the same text sanitizer
  to each leaf. Python inspects bounded decoded candidates for encoded risky
  Unicode, without returning those decoded views.
- Python may add non-mutating `flagged_counts` signals and stats.
- Stable reason codes are derived after both layers have contributed counts.
- Original confusable/styled observations survive normalization. Encoded Unicode
  inspection checks input and sanitized output, with separate character offsets
  for each view and per-signal maxima to avoid duplicate counts.
- Transformation, observation, and application decisions remain distinct.
  Normalized output is a fixed point; application validators see that output.
- If a Python signal becomes required for core safety or performance, move it
  down deliberately with tests and report-schema compatibility.

This keeps the Rust core as the authoritative text boundary while allowing
package-level integrations to evolve quickly.
