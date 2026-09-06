# Fuzzing the sanitizer core

The deterministic Rust core must never panic on arbitrary input (a panic in a
text-hardening library is a denial-of-service), and `sanitize` must be
idempotent. This target enforces both over arbitrary UTF-8.

Requires a nightly toolchain and `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run sanitize
```

Reproduce a crash from an artifact:

```bash
cargo +nightly fuzz run sanitize fuzz/artifacts/sanitize/<id>
```
