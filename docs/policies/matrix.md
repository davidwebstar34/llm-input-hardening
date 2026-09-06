# Policy Behaviour Matrix

This matrix shows default behavior by policy preset.

## Strict vs balanced vs permissive

| Label / action | `strict_exec` (strict) | `balanced_chat` (balanced) | `preserve` (permissive) |
|---|---|---|---|
| `bidi_control` | remove | remove | remove |
| `junk_invisible` | remove | remove | remove |
| `default_ignorable` (joiners / VS / tags) | remove | flag only | flag only |
| `line_separator` | remove | remove | remove |
| `normalization_amplified` | truncate + reject | truncate + reject | truncate + reject |
| `control_or_format` | remove | remove | remove |
| `base64ish_blob` | flag only | flag only | off |
| `hex_blob` | flag only | flag only | flag only |
| `encoded_blob` | flag only | flag only | flag only |
| `high_entropy` | flag only | flag only | flag only |
| `high_combining_ratio` | flag only | flag only | flag only |
| `confusable_mixed_script` | flag only | flag only | flag only |
| `whole_script_confusable` | flag only | flag only | flag only |
| `confusable_styled` | flag only | flag only | flag only |
| Unicode normalization | NFKC | NFC | NFC |
| Whitespace tidying | on | on | off |

## Code mode (source-text profile)

`code_mode` is an explicit source-text preset:

- normalization: `NFC` (avoid compatibility fold for code-like text)
- bidi/control/junk invisibles: removed
- default-ignorables (joiners/VS/tags): removed
- whitespace tidying: off (preserve source formatting)
- confusable analysis backend default: `confusable_homoglyphs`

## When to use which

- `strict_exec`: tool arguments, policy text, high-risk execution paths.
- `balanced_chat`: default for user chat and normal multilingual prose.
- `preserve`: low-touch rendering contexts where formatting fidelity is highest priority.
- `code_mode`: source code, config snippets, and identifier-heavy payloads.
