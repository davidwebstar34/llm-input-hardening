# Red-team corpus — novel attacks

`novel_attacks.json` is a corpus of attack shapes found by **category-walking**
the Unicode/encoding surface rather than re-testing known cases. Unlike
`bench/obfuscation_corpus/cases.json` (which contains handled cases and asserts
recall), this file is a **discovery snapshot**. Its `current` fields record
behavior at discovery time; fixed cases are promoted into the main corpus
instead of rewriting the historical snapshot.

It exists to make the Part 9 discipline concrete: confidence is a function of
the corpus, so this records what the corpus did not cover when the sweep ran.

## Fields

- `category` — attack family (invisible-tag, combining-abuse, structural,
  whitespace, styled-latin, homoglyph-script, encoding).
- `severity` — critical/high/medium/low, or `benign` for control cases that must
  keep passing.
- `in_scope` — whether closing it fits the library's text-integrity mandate
  (`false` = a conscious scope decision, e.g. non-Latin homoglyph scripts).
- `text` — the input (ascii-escaped; no literal control characters in the file).
- `current` — live-captured v1.3.0 action/removed/flagged.
- `expected_action` / `expected_signal` — the target behavior.
- `note` — why it matters and, where relevant, the fix approach.

## How to use it

Regenerate the `current` snapshot after any change and diff it:

```bash
uv run python - <<'PY'
import json
from llm_input_hardening import sanitize_and_decide
cases = json.load(open("bench/redteam/novel_attacks.json"))
for c in cases:
    _, rep, dec = sanitize_and_decide(c["text"], sanitize_policy="balanced_chat")
    ok = dec["action"] == c["expected_action"]
    print(("ok " if ok else "MISS"), c["severity"], c["name"], "->", dec["action"])
PY
```

**Promotion path:** when a fix lands and a case's current behavior matches its
expected behavior, move it into `bench/obfuscation_corpus/cases.json` as a
first-class labeled case so the bakeoff enforces it forever. A red-team finding
isn't closed until it's a regression test.

## Historical priority (2026-07 sweep)

1. `flag_emoji_tag_bypass` (**critical**) — a **regression introduced in
   v1.3.0**: the flag-emoji preservation exception preserves any tag run after
   U+1F3F4, reopening the invisible-tag smuggling hole. Fix: only preserve a
   well-formed, bounded regional-indicator sequence terminated by E007F.
2. `line_separator_injection` (**high**) — U+2028/U+2029 survive every policy; a
   structural newline-injection primitive. Add a `line_separator` signal +
   removal, sibling to `carriage_return`.
3. `combining-abuse` family — the Zalgo ratio detector only counts three
   combining blocks; enclosing/symbol/half-mark/script-specific ranges escape it.

These findings are fixed and promoted. Ongoing findings and closure evidence are
described in the repository `SCOPE.md`; handled text cases live in the main
bakeoff corpus.

Not text-sanitize cases, tracked separately (see repo `SCOPE.md`):
`sanitize_json` unbounded recursion (RecursionError DoS on deep nesting), and
`meter()` silently using the crude fallback token estimator.
