# Safe Display Guide

Unicode obfuscation can make displayed text differ from logical text. Treat untrusted text as binary data until inspected.

## Quick codepoint inspection (CLI)

```bash
python - <<'PY'
import sys
text = sys.argv[1] if len(sys.argv) > 1 else "SAFE \u202Eevil\u200b"
for i, ch in enumerate(text):
    print(f"{i:03d} U+{ord(ch):04X} {repr(ch)}")
PY "SAFE ‮evil​"
```

## Inspect suspicious characters in git diffs

```bash
# Show escaped bytes for changed lines (helps reveal invisibles/bidi controls)
git diff --unified=0 | sed -n 's/^+//p' | python - <<'PY'
import sys
for line in sys.stdin:
    line = line.rstrip("\n")
    escaped = "".join(f"\\u{ord(c):04X}" if ord(c) < 32 or ord(c) > 126 else c for c in line)
    print(escaped)
PY
```

## Copy/paste risk notes

- Copying from rendered markdown, chat, terminals, or screenshots can insert invisible controls.
- Bidi controls can reorder what reviewers see versus what parsers process.
- Emoji joiners/selectors and tag characters can carry hidden payload content.
- Prefer tooling that shows codepoints when triaging suspicious text.

## Operational recommendations

- Keep raw input access restricted; prefer sanitized/escaped views in logs and dashboards.
- When sharing incidents, include escaped representations (`U+XXXX`) alongside raw text.
- Review corpus contributions using explicit codepoint dumps before merge.
