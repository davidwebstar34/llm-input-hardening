# How llm-input-hardening actually works — the nitty-gritty story

This is the long-form, mechanical account of what happens to a string when it
passes through this library: every branch, in the order it runs, and what each
branch is defending against. It's written to be read start-to-finish, not
skimmed. If you want the API surface, read the README; if you want to understand
*why the code is shaped the way it is*, read this.

---

## Part 1 — The threat: text that humans and machines read differently

Almost every defense in this library exists because of one uncomfortable fact:
**the bytes of a string, the glyphs a human sees, and the tokens a model
consumes are three different things.** An attacker who controls the gap between
them can make you approve text you'd never approve if you could see it clearly.

Concretely, here are the tricks this library is built to blunt. Keep them in
mind — every function below is a response to one of these.

1. **Bidirectional override (the Trojan Source class).** Unicode has invisible
   control characters (U+202E RIGHT-TO-LEFT OVERRIDE and friends) that reorder
   how text *renders* without changing its logical byte order. `"user‮admin"`
   can display as `"usernimda"` — or worse, in code, `if (accessLevel != "user"‮ ⁦// Check if admin⁩ ⁦"`
   reorders so a comment looks like live code. A reviewer approves what they see;
   the machine runs what's stored.

2. **Invisible / zero-width characters.** ZWSP (U+200B), word joiner (U+2060),
   BOM (U+FEFF), soft hyphen (U+00AD). They render as *nothing*. They let an
   attacker (a) split a keyword past a naïve filter — `"ig​nore previous"` —
   or (b) hide a payload marker that a downstream system keys off.

3. **Tag characters (U+E0000–E007F).** This is the sharpest one. There is a
   full invisible copy of ASCII in the Unicode Tags block. `"ignore all rules"`
   can be re-encoded character-for-character into codepoints that render as
   *absolutely nothing* in almost every font, yet a model that was trained on
   text containing them may still "read" the instruction. This is the modern
   invisible-prompt-injection vector.

4. **Variation selectors as a data channel (emoji steganography).** VS15/VS16
   (U+FE0E/FE0F) and the 240 supplementary selectors (U+E0100+) attach to a base
   character to pick a glyph variant. Nothing stops you from attaching *hundreds*
   of them to one emoji; they're invisible, and they can encode arbitrary data —
   a covert channel riding on a 😀.

5. **Homoglyphs / mixed-script confusables.** `раypal` looks like `paypal` but
   the first two letters are Cyrillic. Different bytes, identical glyphs. Defeats
   string allowlists, blocklists, and human review simultaneously.

6. **Combining-mark abuse ("Zalgo").** Stacking dozens of combining diacritics
   (U+0300–036F) on one base character. Wrecks display, can break downstream
   parsers, and inflates token counts.

7. **Encoding-shaped payloads.** Base64 or hex blobs carrying an instruction the
   model is asked to decode and obey. The library can't and won't decode intent —
   but a long high-entropy blob in a chat message is itself a signal worth
   surfacing.

8. **Normalization ambiguity.** The same visual string has many byte
   representations (composed vs decomposed, fullwidth vs ASCII, compatibility
   forms). Without canonicalization, every comparison, log line, and filter
   downstream sees a different string than its neighbor.

What this library **deliberately does not do**: it does not judge whether visible
natural-language text is "a jailbreak." `"ignore your instructions"` written in
plain ASCII passes through untouched — that's a semantic-intent problem for a
model-based guardrail, not a text-integrity problem. The dividing line is:
*can I detect this with deterministic Unicode analysis, without inferring meaning?*
If yes, it's in scope. If it needs a model to judge intent, it's out.

---

## Part 2 — The pipeline, stage by stage

The public entrypoint is `sanitize(text, policy=...)` (Python name), which calls
into the Rust extension `_core.sanitize`, then Python decoration adds the signals
Rust doesn't compute. Here is the actual order of operations.

### Stage 0 — Policy resolution

`resolve_policy_name` maps aliases (`"balanced"` → `"balanced_chat"`) and rejects
unknown names. There are four presets, defined once in
`policy_registry.json` and read by *both* the Rust core and the Python layer:

| Policy | Normalization | Removes default-ignorables | Tidies whitespace | Intended use |
|---|---|---|---|---|
| `preserve` | NFC | no | no | logging / observability, minimal mutation |
| `balanced_chat` | NFC | no | yes | general chat input (the default) |
| `strict_exec` | NFKC | **yes** | yes | tool args, execution-adjacent strings |
| `code_mode` | NFC | **yes** | no | code snippets (whitespace is significant) |

The registry supplies shared heuristic thresholds (entropy cutoffs,
base64 minimum length, combining ratio). Stack and span-budget limits are named
constants in the Rust core. Rust `include_str!`s the registry at compile time;
Python reads it at runtime. Canonical names are derived from registry keys, so a
new preset does not require a second hard-coded list.

### Stage 1 — Input bound and encoded-candidate inspection

Original input is bounded first. The Python API inspects original and sanitized
text for encoded risky Unicode, using the core's scalar classification. Only
inspection views are decoded; returned text is not. Candidate work, decoding
depth and evidence are bounded. Risk observations and incomplete inspection
quarantine by default. See [the exact contract](security/encoded-unicode.md).

Rust owns bounded Unicode normalization and all returned text mutation.

### Stage 2 — Unicode normalization (Rust, `normalize_text`)

The text is normalized to the policy's form:

- **NFC** (canonical composition) for `preserve`/`balanced_chat`/`code_mode`:
  collapses composed/decomposed equivalents so `é` (one codepoint) and `e` + `́`
  (two) become the same bytes. Low-risk, preserves meaning.
- **NFKC** (compatibility composition) for `strict_exec`: additionally folds
  *compatibility* characters — fullwidth `Ａ` → `A`, ligatures, superscripts,
  the U+2100-block symbols. This is aggressive on purpose: for a tool argument
  you want one canonical spelling, not seven visually-distinct-but-equivalent
  ones.

A subtle ordering fact: **normalization happens before and after removal.** NFKC can
*materialize* new ASCII from a compatibility character. That's intended, but it's
also why the core streams normalized output into a bounded buffer. Output is
limited to `max(128, input_chars * 8)`; hitting the limit records
`normalization_amplified`, truncates before the character scan, and rejects by
default. The fixed-point tests also verify that normalization cannot resurrect a
character class the removal pass stripped.

### Stage 3 — The ASCII fast-path

If the normalized text is pure ASCII, contains no `\r`, the policy doesn't tidy
whitespace, and normalization changed nothing, the core can skip the
per-character transform loop. It still runs the whole-string signal pass, so
pure-ASCII base64/high-entropy payloads are not missed.

### Stage 4 — The character-transform loop (Rust)

For non-fast-path text, the core walks the string codepoint by codepoint. Each
character is tested against an ordered series of gates. The **order matters** —
the first gate that matches wins and the character is dropped (`continue`):

1. **Carriage return** (`\r`) → removed, counted as `carriage_return`. Normalizes
   line endings so `\r\n` smuggling and display tricks don't survive.

2. **Bidi controls**: overrides, embeddings, and isolates (U+202A–202E,
   U+2066–2069) are removed as `bidi_control`. Plain LRM/RLM/ALM marks are
   handled separately as `bidi_mark`: preserved and flagged under chat policies,
   removed under strict policies.

3. **Junk invisibles** (if `remove_junk_invisibles`): ZWSP, WORD JOINER, BOM →
   removed, counted `junk_invisible`. These have no legitimate role in the middle
   of prompt text.

4. **Controls & curated format chars** (if `remove_other_controls`): all C0/C1
   control characters *except* `\n` and `\t`, plus a **deliberately curated** set
   of Cf format ranges (`CURATED_CF_RANGES`). The curation is the interesting
   part: the code does **not** strip the full Unicode "Format" category, because
   that would corrupt legitimate Arabic (U+0600–0605 number signs, U+06DD end of
   ayah) and Syriac text. Only ranges that are invisible in chat AND have
   documented smuggling value are listed. ZWNJ/ZWJ (U+200C/200D) are special-cased
   here: they're *preserved* unless the policy also strips default-ignorables,
   because they're load-bearing in Persian, Arabic, and emoji sequences.

5. **Tag characters and variation-selector runs**: chat policies preserve only
   the England/Scotland/Wales RGI subdivision flags; strict policies remove all
   tags. Selector caps include Mongolian selectors and cannot be reset by
   deleted separators or preserved default-ignorables. Pinned standardized/emoji
   pairs and the explicit Han-context policy distinguish supported base-selector
   contexts; unsupported contexts emit actionable `invalid_variation_selector`.

6. **Default-ignorables** (if `remove_default_ignorables` — only `strict_exec`
   and `code_mode`): the big net. `DEFAULT_IGNORABLE_RANGES` covers soft hyphen,
   Mongolian selectors, the zero-width block, **variation selectors (U+FE00–FE0F
   and U+E0100–E01EF)**, and **the tag block (U+E0000–E007F)**. Removal is
   sub-classified in the stats into joiner / variation-selector / tag / other, so
   you can tell *what kind* of invisible was present. Dedicated gates have
   already removed tag payloads and excess variation-selector runs.

7. **Flagging default-ignorables** (if `flag_default_ignorables` — all presets):
   policies that preserve legitimate joiners/selectors still expose their
   presence as telemetry. Actionable tag and excess-selector cases have already
   been handled by their dedicated gates.

8. **Combining-mark tally** (if `flag_combining_abuse`): complete native Unicode
   General_Category=Mark data counts nonspacing, spacing and enclosing marks
   without removing them. Reports disclose the data version. Final output is
   measured for density and pathological stacks separately.

Anything that survives all gates is appended to the output buffer. If
`return_spans=True`, character-level removals/flags record a `{kind, reason,
start, end, detail}` span, up to 10,000 events before an explicit error. These
are UTF-8 offsets into the initial normalized scan, before deletion or final
composition; with repair, original-pass spans are kept separately.

### Stage 5 — Whitespace tidy (Rust, policies that enable it)

`tidy_whitespace` collapses runs of ASCII spaces/tabs and Unicode separator
spaces (Zs: NBSP, thin/hair spaces, ideographic space, Ogham space, etc.) to one
plain ASCII space, trims spaces around newlines, and strips leading/trailing
space and trailing newlines. It's off for `code_mode` (whitespace is
semantically significant in code) and `preserve`. `whitespace_tidy` counts the
collapsed/trimmed characters rather than a flat one-bit signal.

### Stage 6 — Whole-string signals (split across Rust and Python)

After the per-character pass, the library computes *shape* signals. These never
mutate text; they only annotate the report. This is the "flag suspicious, don't
decode" philosophy.

Computed in **Rust**:
- **Prefix Shannon entropy** over the first 2000 chars, summed in stable order.
  Above 5.0 bits/char on
  a long-enough string → `high_entropy`. High entropy = looks like compressed or
  encrypted or encoded data, not prose.
- **base64-ish shape**: contiguous or whitespace-wrapped base64/base64url regions
  in the output, with length/shape checks → `base64ish_blob`.
- **combining ratio**: combining marks ÷ total chars; above 0.2 on > 40 chars →
  `high_combining_ratio`, retained as observational telemetry for multilingual text.
- **combining stacks**: `excessive_combining_stack` for eight marks on one base,
  three stacks of five marks, or five marks plus the high-ratio signal. This
  separate signal drives default quarantine.

Computed in **Python** (`_service.py`, layered on top of the Rust report):
- **hex-blob shape** (`hex_blob_format`): detects both contiguous hex (≥ 32
  bytes) and promptfoo-style space-separated byte hex. If found, it *replaces*
  the base64 flag (a hex blob also matches the base64 alphabet, so the more
  specific signal wins).
- **alt-encoded shape** (`encoded_blob_format`): detects ascii85/base85-looking
  payloads and long space-separated binary-byte strings → `encoded_blob`.
- **sliding-window entropy** (`max_entropy_window`): a 256-char window every 64
  chars, catching a high-entropy blob *embedded in* otherwise-normal prose that
  the prefix-only Rust check would miss.
- **styled compatibility forms**: detects Latin-looking styled letters and
  compatibility digits (mathematical bold, circled/fullwidth, small caps) that
  NFC chat policies intentionally do not fold → `confusable_styled`.
- **confusables / mixed-script detection** (`confusables.py`): the homoglyph
  defense. See Part 3.

The Rust/Python ownership split is intentional and documented in
`docs/architecture/detection-boundary.md`; encoded-run checks scan within prose,
not only whole-string matches.

### Stage 7 — Reason codes and the report

Every removed/flagged signal maps to a stable reason code (`IH001_BIDI_CONTROL`,
`IH002_DEFAULT_IGNORABLE`, `IH030_BASE64_LIKE_PAYLOAD`, …) via
`reason_codes.py`. These are the contract: they're designed to be
backward-compatible across releases so you can build alerting and dashboards on
them without worrying about internal renames. `to_otel_attributes` turns the
report into low-cardinality OpenTelemetry span attributes for exactly this.

The final `SanitizeReport` is a `TypedDict` carrying: `policy`, `normalization`,
`changed`, `removed_counts`, `flagged_counts`, `reason_codes`, optional `spans`,
and a `stats` bag with all the raw measurements.

---

## Part 3 — Homoglyph detection in detail

`detect_confusables` has two backends:

- **`heuristic`** (default, no dependency): walks the text word by word, assigns
  each alphabetic character a script using static Unicode ranges, and flags any
  word that mixes ≥ 2 visually-confusable scripts (Latin, Cyrillic, Greek,
  Cherokee, Armenian, Coptic). CJK is deliberately excluded —
  Han+Hiragana+Katakana in one word is normal Japanese, and Latin mixes freely
  into CJK ("Tシャツ"). It separately flags non-Latin single-script words of at
  least three letters when every letter folds to an ASCII-Latin skeleton, so
  both `раypal` and all-Cyrillic `раураӏ` are visible.
- **`confusable_homoglyphs`** (opt-in `[security]` extra): adds the
  `confusable_homoglyphs` package's UTS-#39-based `is_dangerous` /
  `is_mixed_script` checks on top of the heuristic. `code_mode` auto-selects this
  backend when available.

It also computes a UTS-#39-flavored **restriction level** (ASCII_ONLY →
SINGLE_SCRIPT → HIGHLY/MODERATELY/MINIMALLY_RESTRICTIVE → UNRESTRICTIVE) as a
coarse "how script-mixed is this" gauge. This is heuristic classification, not a
certified spoof-checker — the docstrings are honest about that.

The heuristic is still deliberately scoped; it is not a full UTS #39
implementation. Use the optional `confusable_homoglyphs` backend for stronger
spoof-checking data.

---

## Part 4 — From report to decision: enforcement

`sanitize` only *describes*. `decide_enforcement` (and the
`sanitize_and_decide` wrapper) turn the report into an action: **allow /
quarantine / reject.** The default `EnforcementPolicy`:

- **reject** for execution-policy confusables, dangerous structural removals, or
  a truncated normalization expansion.
- **quarantine** if any quarantine-flag fired (`base64ish_blob`, `hex_blob`,
  `encoded_blob`, styled/whole-script confusables, `high_entropy`,
  `excessive_combining_stack`), any quarantine-removal happened, or the total
  security-removal count crosses a threshold (12). Ordinary whitespace tidying
  and carriage returns are excluded from that volume count. Chat permits
  whole-script candidates in sufficiently established native prose while
  retaining the observation; strict policies reject them.
- **allow** otherwise.

Both decision APIs infer severity from the report's sanitize policy unless an
explicit enforcement policy is supplied. For execution fields,
`sanitize_and_decide(..., reject_on_change=True, validator=...)` can reject
transformation and apply the application's schema to the actual returned text.
These decisions remain reproducible from the resulting report.

The CLI mirrors this: `llm-input-hardening decide` exits 0 / 2 / 3 for
allow / quarantine / reject, so you can gate a shell pipeline on it.

---

## Part 5 — Integration surfaces

- **`sanitize_json`** iteratively sanitizes every string key and value of a JSON
  payload, preserving shape and insertion order and retaining per-path reports.
  Sanitized-key collisions raise `ValueError` rather than overwriting data.
- **`meter`** counts tokens before/after sanitization (tiktoken if available,
  HF tokenizer if you pass one, crude fallback otherwise) so you can enforce
  context-window budgets and see how much sanitization changed the count.
- **`ASGIPromptSanitizerMiddleware`** (aliased as `StarlettePromptSanitizerMiddleware`)
  works with asyncio-based ASGI applications without a Starlette dependency. It sanitizes one
  configured field or dotted/indexed JSON path in flight and caps the buffered body at `max_body_bytes`
  (oversized → 413), runs enforcement decisioning with an optional `on_decision`
  hook, and can block `reject` decisions with HTTP 403 when `enforce=True`. It
  adds `x-sanitize-changed` / `x-tokens-before` / `x-tokens-after` /
  `x-enforcement-action` response headers.

---

## Part 6 — The mental model in one paragraph

Untrusted text comes in. **Normalize** it to one canonical byte form per policy.
**Remove** the characters that are invisible-or-controlling and have no
legitimate place in prompt text — bidi overrides always, the broader
default-ignorable net (tag chars, variation selectors, zero-width) under strict
policies. **Flag** the suspicious *shapes* — encoded blobs, high entropy, Zalgo
stacking, mixed- and whole-script homoglyphs — without decoding or judging intent. Emit a
**structured, reason-coded report** so the rest of your stack can log it, meter
it, and **decide** allow/quarantine/reject. Keep semantic jailbreak judgment as a
separate, model-based layer — this library makes text *honest*, it doesn't make
it *safe*.
