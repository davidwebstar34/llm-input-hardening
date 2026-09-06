# Scope Boundaries

The canonical scope contract lives in
[SCOPE.md](https://github.com/davidwebstar34/llm-input-hardening/blob/main/SCOPE.md).
This page intentionally stays short so the docs site does not drift from the
repository-level contract.

In one sentence: this library is a deterministic text-integrity layer for
Unicode/control-character cleanup and suspicious text-shape signals; it is not a
semantic jailbreak detector, tool sandbox, output policy engine, URL decoder, or
HTML entity decoder. Bounded [encoded-Unicode inspection](security/encoded-unicode.md)
adds signals without decoding returned text.
