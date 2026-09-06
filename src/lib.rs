//! Multilingual-safe LLM input hardening.
//!
//! This crate implements a deterministic, low-overhead sanitizer intended for use
//! on untrusted text before it is embedded into LLM prompts or templates.
//!
//! The core entrypoint is [`sanitize_inner`]. When built with the `python` feature,
//! the sanitizer is exposed as a Python extension module via PyO3.
#![allow(clippy::useless_conversion)] // PyO3 macro expansion triggers this lint on PyResult paths.

pub mod policy;
pub mod report;
mod unicode_tables;
mod variation_tables;

use unicode_tables::DEFAULT_IGNORABLE_RANGES;
use variation_tables::{STANDARDIZED_VARIATION_PAIRS, VARIATION_DATA_VERSION};

use policy::{get_policy, signal_spec, Normalization};
use report::{SanitizeReport, SpanEvent};

use serde_json::json;
use unicode_normalization::UnicodeNormalization;
#[cfg(feature = "python")]
use {
    pyo3::exceptions::PyValueError,
    pyo3::prelude::*,
    pyo3::sync::PyOnceLock,
    pyo3::types::{PyAny, PyModule},
    pyo3::Bound,
};

use std::borrow::Cow;

const NORMALIZATION_EXPANSION_RATIO_LIMIT: usize = 8;
const NORMALIZATION_MIN_OUTPUT_CHARS: usize = 128;
const MAX_SPAN_EVENTS: usize = 10_000;
// Ordinary vowel/diacritic sequences often have a high mark ratio. Stacks of
// five marks merit scrutiny; eight on one base are independently actionable.
const COMBINING_STACK_THRESHOLD: usize = 5;
const COMBINING_EXTREME_STACK_THRESHOLD: usize = 8;

// Bidi controls are split by danger. Overrides, embeddings, and isolates can all
// force a visual order that disagrees with logical order — the Trojan Source
// weapon — and have no legitimate role in execution-adjacent prompt text, so
// they are removed under every policy. The plain directional marks
// (LRM/RLM/ALM), by contrast, are ordinary content in Arabic/Hebrew: they keep
// an embedded Latin phone number or brand name rendering correctly and are
// emitted automatically by any bidi-aware editor. Removing them wholesale
// mangles benign RTL text, so they get a distinct, softer classification —
// preserved-and-flagged under chat policies, removed only under strict ones.
// Both lists must stay sorted.
const BIDI_OVERRIDES: &[u32] = &[
    0x202A, // LEFT-TO-RIGHT EMBEDDING
    0x202B, // RIGHT-TO-LEFT EMBEDDING
    0x202C, // POP DIRECTIONAL FORMATTING
    0x202D, // LEFT-TO-RIGHT OVERRIDE
    0x202E, // RIGHT-TO-LEFT OVERRIDE
    0x2066, // LEFT-TO-RIGHT ISOLATE
    0x2067, // RIGHT-TO-LEFT ISOLATE
    0x2068, // FIRST STRONG ISOLATE
    0x2069, // POP DIRECTIONAL ISOLATE
];
const BIDI_MARKS: &[u32] = &[
    0x061C, // ARABIC LETTER MARK
    0x200E, // LEFT-TO-RIGHT MARK
    0x200F, // RIGHT-TO-LEFT MARK
];
const LINE_SEPARATORS: &[u32] = &[
    0x2028, // LINE SEPARATOR
    0x2029, // PARAGRAPH SEPARATOR
];

// Waving black flag: the base of a subdivision tag flag sequence
// (e.g. the England/Scotland/Wales flags), the one legitimate use of tag chars
// in chat text.
const FLAG_EMOJI_BASE: u32 = 0x1F3F4;
// Cancel tag: terminates a tag flag sequence.
const TAG_CANCEL: u32 = 0xE007F;

// Must stay sorted for binary_search
const JUNK_INVISIBLES: &[u32] = &[
    0x200B, // ZWSP
    0x2060, // WORD JOINER
    0xFEFF, // BOM
];

const PRESERVE_JOINERS: &[u32] = &[
    0x200C, // ZWNJ
    0x200D, // ZWJ
];

// Unicode separator-space characters (General_Category=Zs). These render as
// spacing but are not ASCII space/tab, so tidy-whitespace policies canonicalize
// them to plain spaces.
const UNICODE_SPACE_SEPARATORS: &[u32] = &[
    0x00A0, // NO-BREAK SPACE
    0x1680, // OGHAM SPACE MARK
    0x2000, // EN QUAD
    0x2001, // EM QUAD
    0x2002, // EN SPACE
    0x2003, // EM SPACE
    0x2004, // THREE-PER-EM SPACE
    0x2005, // FOUR-PER-EM SPACE
    0x2006, // SIX-PER-EM SPACE
    0x2007, // FIGURE SPACE
    0x2008, // PUNCTUATION SPACE
    0x2009, // THIN SPACE
    0x200A, // HAIR SPACE
    0x202F, // NARROW NO-BREAK SPACE
    0x205F, // MEDIUM MATHEMATICAL SPACE
    0x3000, // IDEOGRAPHIC SPACE
];

fn is_bidi_override(cp: u32) -> bool {
    BIDI_OVERRIDES.binary_search(&cp).is_ok()
}
fn is_bidi_mark(cp: u32) -> bool {
    BIDI_MARKS.binary_search(&cp).is_ok()
}
fn is_line_separator(cp: u32) -> bool {
    LINE_SEPARATORS.binary_search(&cp).is_ok()
}
fn is_junk_invisible(cp: u32) -> bool {
    JUNK_INVISIBLES.binary_search(&cp).is_ok()
}
fn is_preserve_joiner(cp: u32) -> bool {
    PRESERVE_JOINERS.binary_search(&cp).is_ok()
}
fn is_unicode_space_separator(cp: u32) -> bool {
    UNICODE_SPACE_SEPARATORS.binary_search(&cp).is_ok()
}
fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&cp))
}
fn is_combining_mark(cp: u32) -> bool {
    char::from_u32(cp).is_some_and(unicode_normalization::char::is_combining_mark)
}
fn is_default_ignorable(cp: u32) -> bool {
    in_ranges(cp, DEFAULT_IGNORABLE_RANGES)
}
fn is_variation_selector(cp: u32) -> bool {
    (0x180B..=0x180D).contains(&cp)
        || cp == 0x180F
        || (0xFE00..=0xFE0F).contains(&cp)
        || (0xE0100..=0xE01EF).contains(&cp)
}

fn valid_variation_pair(base: Option<char>, selector: u32) -> bool {
    let Some(base) = base.map(|ch| ch as u32) else {
        return false;
    };
    if (0xE0100..=0xE01EF).contains(&selector) {
        // IVD is a separate registry. Preserve ideographic variants on Han
        // bases for interoperability; do not claim exact IVD registration.
        return matches!(base, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF
            | 0x20000..=0x2FA1F | 0x30000..=0x3347F);
    }
    STANDARDIZED_VARIATION_PAIRS
        .binary_search(&(base, selector))
        .is_ok()
}

fn push_output(out: &mut String, selector_pending: &mut bool, ch: char) {
    let cp = ch as u32;
    if is_variation_selector(cp) {
        *selector_pending = true;
    } else if !is_default_ignorable(cp) {
        *selector_pending = false;
    }
    out.push(ch);
}
fn is_tag_char(cp: u32) -> bool {
    (0xE0000..=0xE007F).contains(&cp) || (0xE0080..=0xE00FF).contains(&cp)
}
fn valid_flag_tag_sequence_end(s: &str, tag_start: usize) -> Option<usize> {
    // The RGI subdivision flags are England, Scotland, and Wales. Accepting
    // arbitrary bounded letters would allow attackers to hide text in chunks.
    // Source: Unicode emoji-sequences.txt, RGI_Emoji_Tag_Sequence.
    const SUBDIVISIONS: [&str; 3] = ["gbeng", "gbsct", "gbwls"];
    SUBDIVISIONS.iter().find_map(|subdivision| {
        let mut chars = s[tag_start..].chars();
        let matches = subdivision
            .bytes()
            .all(|letter| chars.next().map(|ch| ch as u32) == Some(0xE0000 + letter as u32));
        (matches && chars.next().map(|ch| ch as u32) == Some(TAG_CANCEL))
            .then_some(tag_start + (subdivision.len() + 1) * 4)
    })
}

fn is_allowed_control(ch: char) -> bool {
    ch == '\n' || ch == '\t'
}

// Cf coverage is deliberately curated, not the full Unicode Format category.
// Full Cf removal would strip characters that are legitimate in benign
// multilingual text — e.g. U+0600..U+0605 (Arabic number signs), U+06DD
// (ARABIC END OF AYAH, common in Quranic quotations), U+070F (SYRIAC
// ABBREVIATION MARK) — corrupting ordinary Arabic/Syriac content. Only
// ranges that are invisible in chat-style text and have documented
// prompt-smuggling value are listed here. Default-ignorable and bidi
// characters have their own dedicated handling above this check.
const CURATED_CF_RANGES: &[(u32, u32)] = &[
    (0x200B, 0x200F), // zero-width chars + direction marks
    (0x202A, 0x202E), // bidi embedding/override controls
    (0x2060, 0x206F), // word joiner, invisible operators, deprecated format chars
    (0xFFF9, 0xFFFB), // interlinear annotation controls
];

fn is_control_or_format(ch: char) -> bool {
    // Cc exactly (via char::is_control), Cf via the curated ranges above.
    ch.is_control() || in_ranges(ch as u32, CURATED_CF_RANGES)
}

/// Scalar-level risk for inspection of encoded candidates. Context-dependent
/// chat joiners/selectors are deliberately excluded; this is not a substitute
/// for sanitizing a fully parsed document with its surrounding text.
pub fn encoded_scalar_risk(ch: char, policy_name: &str) -> Result<Option<&'static str>, String> {
    let pol = get_policy(policy_name).ok_or_else(|| format!("unknown policy: {policy_name}"))?;
    let cp = ch as u32;
    let reason = if pol.remove_bidi && is_bidi_override(cp) {
        Some("bidi_control")
    } else if pol.remove_bidi_marks && is_bidi_mark(cp) {
        Some("bidi_mark")
    } else if is_bidi_mark(cp) {
        None
    } else if pol.remove_other_controls && is_line_separator(cp) {
        Some("line_separator")
    } else if pol.remove_tag_chars && is_tag_char(cp) {
        Some("tag_char")
    } else if pol.remove_junk_invisibles && is_junk_invisible(cp) {
        Some("junk_invisible")
    } else if pol.remove_default_ignorables && is_default_ignorable(cp) {
        Some("default_ignorable")
    } else if pol.remove_other_controls
        && is_control_or_format(ch)
        && !is_allowed_control(ch)
        && ch != '\r'
        && !is_preserve_joiner(cp)
    {
        Some("control_or_format")
    } else {
        None
    };
    Ok(reason)
}

struct NormalizedText<'a> {
    text: Cow<'a, str>,
    input_chars: usize,
    output_chars: usize,
    output_limit_chars: usize,
    truncated: bool,
}

fn collect_normalized_bounded<'a>(
    s: &'a str,
    mut chars: impl Iterator<Item = char>,
    limit: Option<usize>,
) -> NormalizedText<'a> {
    let input_chars = s.chars().count();
    let output_limit_chars = input_chars
        .saturating_mul(NORMALIZATION_EXPANSION_RATIO_LIMIT)
        .max(NORMALIZATION_MIN_OUTPUT_CHARS);
    let output_limit_chars =
        limit.map_or(output_limit_chars, |limit| limit.min(output_limit_chars));
    let mut normalized = String::with_capacity(s.len().min(output_limit_chars.saturating_mul(4)));
    let mut output_chars = 0usize;

    for ch in chars.by_ref().take(output_limit_chars) {
        normalized.push(ch);
        output_chars += 1;
    }
    let truncated = chars.next().is_some();
    let text = if !truncated && normalized == s {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(normalized)
    };

    NormalizedText {
        text,
        input_chars,
        output_chars,
        output_limit_chars,
        truncated,
    }
}

fn normalize_text<'a>(s: &'a str, norm: Normalization) -> NormalizedText<'a> {
    normalize_text_with_limit(s, norm, None)
}

fn normalize_text_with_limit(
    s: &str,
    norm: Normalization,
    limit: Option<usize>,
) -> NormalizedText<'_> {
    match norm {
        Normalization::Nfc => collect_normalized_bounded(s, s.nfc(), limit),
        Normalization::Nfkc => collect_normalized_bounded(s, s.nfkc(), limit),
    }
}

/// Count mark density separately from pathological stacks. Preserved invisible
/// characters cannot reset a stack, while visible letters and spaces can.
fn combining_stats(s: &str) -> (usize, usize, usize, usize) {
    if s.is_ascii() {
        return (s.len(), 0, 0, 0);
    }
    let mut total = 0usize;
    let mut combining = 0usize;
    let mut stack = 0usize;
    let mut max_stack = 0usize;
    let mut suspicious_stacks = 0usize;
    for ch in s.chars() {
        total += 1;
        if ch.is_ascii() {
            stack = 0;
            continue;
        }
        let cp = ch as u32;
        if is_default_ignorable(cp) {
            continue;
        }
        if is_combining_mark(cp) {
            combining += 1;
            stack += 1;
            max_stack = max_stack.max(stack);
            if stack == COMBINING_STACK_THRESHOLD {
                suspicious_stacks += 1;
            }
        } else {
            stack = 0;
        }
    }
    (total, combining, max_stack, suspicious_stacks)
}

fn shannon_entropy(prefix: &str) -> f64 {
    // Stable key order also makes floating-point accumulation repeatable.
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    let mut n: usize = 0;
    for ch in prefix.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let mut ent = 0.0f64;
    for (_k, v) in counts {
        let p = (v as f64) / (n as f64);
        ent -= p * p.ln() / 2f64.ln();
    }
    ent
}

fn is_base64_run_char(c: char) -> bool {
    // Standard and URL-safe base64 alphabets, including '=' padding so a blob's
    // trailing (or concatenated-internal) padding doesn't split the run.
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_' || c == '='
}

/// Length of the longest contiguous base64-alphabet run in `s`.
///
/// This is a *shape* signal only. It scans for an encoded-looking run anywhere
/// in the text rather than requiring the whole string to be one clean blob, so a
/// payload wrapped in ordinary prose ("please decode this: <blob> thanks") is
/// still visible. The `len % 4 == 0` constraint is deliberately dropped — it was
/// trivially defeated by appending a single character.
fn longest_base64_run(s: &str) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    for c in s.chars() {
        if is_base64_run_char(c) {
            cur += 1;
            if cur > best {
                best = cur;
            }
        } else {
            cur = 0;
        }
    }
    best
}

fn looks_base64ish(s: &str, min_chars: usize) -> bool {
    longest_base64_run(s) >= min_chars
}

/// Detect whitespace-wrapped runs without joining the whole input or treating
/// every long English paragraph as base64. A fixed-size alphabet window must
/// contain a whitespace boundary and characteristic mixed case/digit/symbol
/// proportions. Uniform uppercase chunks cover encodings such as QUFB... .
fn looks_wrapped_base64ish(s: &str, min_chars: usize) -> bool {
    use std::collections::VecDeque;
    if min_chars == 0 {
        return false;
    }
    let mut window = VecDeque::with_capacity(min_chars);
    let mut counts = [0usize; 4]; // uppercase, lowercase, digits, +/=_-
    let mut gaps = 0usize;
    let mut whitespace = false;
    let mut token_len = 0usize;
    let mut token_uppercase = true;
    let mut previous_uppercase_len = 0usize;
    let mut uniform_uppercase_chars = 0usize;
    for ch in s.chars().chain(std::iter::once(' ')) {
        if ch.is_whitespace() {
            if token_len > 0 {
                if token_uppercase && (4..=76).contains(&token_len) {
                    uniform_uppercase_chars = if token_len == previous_uppercase_len {
                        uniform_uppercase_chars + token_len
                    } else {
                        token_len
                    };
                    previous_uppercase_len = token_len;
                    if uniform_uppercase_chars >= min_chars
                        && uniform_uppercase_chars >= token_len * 2
                    {
                        return true;
                    }
                } else {
                    previous_uppercase_len = 0;
                    uniform_uppercase_chars = 0;
                }
                token_len = 0;
                token_uppercase = true;
            }
            whitespace = true;
            continue;
        }
        if !is_base64_run_char(ch) {
            window.clear();
            counts = [0; 4];
            gaps = 0;
            whitespace = false;
            token_len = 0;
            token_uppercase = true;
            previous_uppercase_len = 0;
            uniform_uppercase_chars = 0;
            continue;
        }
        token_len += 1;
        token_uppercase &= ch.is_ascii_uppercase();
        let category = if ch.is_ascii_uppercase() {
            0
        } else if ch.is_ascii_lowercase() {
            1
        } else if ch.is_ascii_digit() {
            2
        } else {
            3
        };
        if window.len() == min_chars {
            let (old_category, old_gap): (usize, bool) = window.pop_front().unwrap();
            counts[old_category] -= 1;
            gaps -= usize::from(old_gap);
        }
        counts[category] += 1;
        gaps += usize::from(whitespace);
        window.push_back((category, whitespace));
        whitespace = false;
        let internal_gaps = gaps - usize::from(window.front().is_some_and(|(_, gap)| *gap));
        if window.len() == min_chars && internal_gaps > 0 {
            let letters = counts[0] + counts[1];
            if (counts[0] * 5 >= min_chars && counts[1] * 10 >= min_chars)
                || (counts[2] * 8 >= min_chars && letters * 4 >= min_chars)
                || (counts[3] > 0 && counts[0] * 8 >= min_chars && letters * 2 >= min_chars)
            {
                return true;
            }
        }
    }
    false
}

fn tidy_whitespace(s: String) -> String {
    // collapse spaces/tabs (not newlines), trim around newlines, strip ends
    // fast-ish manual pass:
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    let mut last_was_nl = false;

    for ch in s.chars() {
        if ch == ' ' || ch == '\t' || is_unicode_space_separator(ch as u32) {
            if last_was_nl {
                continue;
            } // trim after newline
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        if ch == '\n' {
            // trim space before newline
            if out.ends_with(' ') {
                out.pop();
            }
            out.push('\n');
            last_was_space = false;
            last_was_nl = true;
            continue;
        }
        last_was_space = false;
        last_was_nl = false;
        out.push(ch);
    }

    // trim ends
    while out.starts_with(' ') {
        out.remove(0);
    }
    while out.ends_with(' ') {
        out.pop();
    }
    while out.ends_with('\n') {
        out.pop();
    }

    out
}

#[cfg(feature = "python")]
fn parse_normalization(name: &str) -> Result<Normalization, String> {
    match name.to_ascii_uppercase().as_str() {
        "NFC" => Ok(Normalization::Nfc),
        "NFKC" => Ok(Normalization::Nfkc),
        _ => Err(format!("unknown normalization: {name}")),
    }
}

/// Sanitize text using a named policy preset.
///
/// Returns the cleaned text and a structured report with removal counts, heuristic flags,
/// and optional span events.
pub fn sanitize_inner(
    text: &str,
    policy_name: &str,
    return_spans: bool,
) -> Result<(String, SanitizeReport), String> {
    sanitize_inner_with_overrides(text, policy_name, None, None, return_spans)
}

fn sanitize_inner_with_overrides(
    text: &str,
    policy_name: &str,
    normalization: Option<Normalization>,
    tidy_override: Option<bool>,
    return_spans: bool,
) -> Result<(String, SanitizeReport), String> {
    let mut pol =
        get_policy(policy_name).ok_or_else(|| format!("unknown policy: {policy_name}"))?;
    if let Some(norm) = normalization {
        pol.normalize = norm;
    }
    if let Some(tidy) = tidy_override {
        pol.tidy_whitespace = tidy;
    }

    // Normalize first
    let normalized = normalize_text(text, pol.normalize);
    let norm_changed = match &normalized.text {
        Cow::Borrowed(_) => false,
        Cow::Owned(_) => true,
    };
    let scan = normalized.text.as_ref();

    // ASCII fast-path when every byte is printable or an allowed control.
    let normalization_label = match pol.normalize {
        Normalization::Nfc => "NFC",
        Normalization::Nfkc => "NFKC",
    }
    .to_string();

    // The fast path skips only the per-character transform loop, never the
    // whole-string signal pass below. Pure-ASCII text can still carry a base64
    // blob or a high-entropy region, and those must be flagged under every
    // policy — skipping the signal pass here was a real detection hole.
    let fast_path = !pol.tidy_whitespace
        && !norm_changed
        && scan
            .bytes()
            .all(|byte| matches!(byte, b'\n' | b'\t' | 0x20..=0x7E));

    let mut out = String::with_capacity(scan.len());
    let mut rep = SanitizeReport {
        policy: pol.name.clone(),
        normalization: normalization_label,
        ..Default::default()
    };

    if normalized.truncated {
        rep.bump_removed("normalization_amplified", 1);
    }

    let mut changed = norm_changed;

    let mut default_ignorable_removed = 0usize;
    let mut default_ignorable_removed_joiner = 0usize;
    let mut default_ignorable_removed_variation_selector = 0usize;
    let mut default_ignorable_removed_tag = 0usize;
    let mut default_ignorable_removed_other = 0usize;
    // Only chat policies preserve the three RGI subdivision flags.
    let mut preserve_flag_tag_until = 0usize;
    let mut selector_pending = false;
    let mut invalid_variation_selectors = 0usize;

    if fast_path {
        out.push_str(scan);
    } else {
        for (i, ch) in scan.char_indices() {
            if rep.spans.len() > MAX_SPAN_EVENTS {
                return Err(format!("span event limit exceeded (maximum {MAX_SPAN_EVENTS}); disable return_spans or split the input"));
            }
            let cp = ch as u32;

            if ch == '\r' {
                changed = true;
                rep.bump_removed("carriage_return", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "removed".into(),
                        reason: "carriage_return".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: "U+000D".into(),
                    });
                }
                preserve_flag_tag_until = 0;
                continue;
            }

            if is_line_separator(cp) {
                changed = true;
                rep.bump_removed("line_separator", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "removed".into(),
                        reason: "line_separator".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: format!("U+{cp:04X}"),
                    });
                }
                preserve_flag_tag_until = 0;
                continue;
            }

            // Bidi overrides / embeddings: the Trojan Source weapon. Removed hard.
            if pol.remove_bidi && is_bidi_override(cp) {
                changed = true;
                rep.bump_removed("bidi_control", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "removed".into(),
                        reason: "bidi_control".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: format!("U+{cp:04X}"),
                    });
                }
                preserve_flag_tag_until = 0;
                continue;
            }

            // Bidi marks: legitimate RTL content. Removed only under
            // strict policies; otherwise preserved and flagged. Handled here so
            // they never reach the control_or_format gate that would strip them.
            if is_bidi_mark(cp) {
                if pol.remove_bidi_marks {
                    changed = true;
                    rep.bump_removed("bidi_mark", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "removed".into(),
                            reason: "bidi_mark".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                    preserve_flag_tag_until = 0;
                    continue;
                }
                if pol.flag_bidi_marks {
                    rep.bump_flagged("bidi_mark", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "flag".into(),
                            reason: "bidi_mark".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                }
                push_output(&mut out, &mut selector_pending, ch);
                preserve_flag_tag_until = 0;
                continue;
            }

            // Tag characters (invisible ASCII, U+E0000..E007F): the modern
            // invisible-prompt-injection carrier. Strict policies remove every
            // tag; chat policies preserve only the three RGI flag sequences.
            if is_tag_char(cp) {
                if i < preserve_flag_tag_until {
                    push_output(&mut out, &mut selector_pending, ch);
                    if i + ch.len_utf8() >= preserve_flag_tag_until {
                        preserve_flag_tag_until = 0;
                    }
                    continue;
                }
                if pol.remove_tag_chars {
                    changed = true;
                    rep.bump_removed("tag_char", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "removed".into(),
                            reason: "tag_char".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                    preserve_flag_tag_until = 0;
                    continue;
                }
                rep.bump_flagged("tag_char", 1);
                push_output(&mut out, &mut selector_pending, ch);
                preserve_flag_tag_until = 0;
                continue;
            }

            // Variation-selector run capping: one selector per base character is
            // legitimate (emoji presentation, ideographic variation sequences);
            // a long run is a steganographic data channel. Strict policies remove
            // all selectors outright below, so this only applies to policies that
            // otherwise preserve default-ignorables.
            if pol.cap_variation_selectors && is_variation_selector(cp) {
                // Inspect surviving output: deleted separators must not let
                // multiple selectors collect on the same base character.
                if selector_pending {
                    changed = true;
                    rep.bump_removed("variation_selector_excess", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "removed".into(),
                            reason: "variation_selector_excess".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                    preserve_flag_tag_until = 0;
                    continue;
                }
                if !valid_variation_pair(out.chars().next_back(), cp) {
                    invalid_variation_selectors += 1;
                    rep.bump_flagged("invalid_variation_selector", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "flag".into(),
                            reason: "invalid_variation_selector".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                }
                if pol.flag_default_ignorables {
                    rep.bump_flagged("default_ignorable", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "flag".into(),
                            reason: "default_ignorable".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                }
                push_output(&mut out, &mut selector_pending, ch);
                preserve_flag_tag_until = 0;
                continue;
            }

            if pol.remove_junk_invisibles && is_junk_invisible(cp) {
                changed = true;
                rep.bump_removed("junk_invisible", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "removed".into(),
                        reason: "junk_invisible".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: format!("U+{cp:04X}"),
                    });
                }
                preserve_flag_tag_until = 0;
                continue;
            }

            if pol.remove_other_controls && is_control_or_format(ch) && !is_allowed_control(ch) {
                if is_preserve_joiner(cp) {
                    if !pol.remove_default_ignorables {
                        push_output(&mut out, &mut selector_pending, ch);
                        preserve_flag_tag_until = 0;
                        continue;
                    }
                } else {
                    changed = true;
                    rep.bump_removed("control_or_format", 1);
                    if return_spans {
                        rep.spans.push(SpanEvent {
                            kind: "removed".into(),
                            reason: "control_or_format".into(),
                            start: i,
                            end: i + ch.len_utf8(),
                            detail: format!("U+{cp:04X}"),
                        });
                    }
                    preserve_flag_tag_until = 0;
                    continue;
                }
            }

            if pol.remove_default_ignorables && is_default_ignorable(cp) {
                changed = true;
                default_ignorable_removed += 1;
                if is_preserve_joiner(cp) {
                    default_ignorable_removed_joiner += 1;
                } else if is_variation_selector(cp) {
                    default_ignorable_removed_variation_selector += 1;
                } else if is_tag_char(cp) {
                    default_ignorable_removed_tag += 1;
                } else {
                    default_ignorable_removed_other += 1;
                }
                rep.bump_removed("default_ignorable", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "removed".into(),
                        reason: "default_ignorable".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: format!("U+{cp:04X}"),
                    });
                }
                preserve_flag_tag_until = 0;
                continue;
            }

            if pol.flag_default_ignorables && !is_preserve_joiner(cp) && is_default_ignorable(cp) {
                rep.bump_flagged("default_ignorable", 1);
                if return_spans {
                    rep.spans.push(SpanEvent {
                        kind: "flag".into(),
                        reason: "default_ignorable".into(),
                        start: i,
                        end: i + ch.len_utf8(),
                        detail: format!("U+{cp:04X}"),
                    });
                }
            }

            push_output(&mut out, &mut selector_pending, ch);
            preserve_flag_tag_until = if cp == FLAG_EMOJI_BASE && !pol.remove_default_ignorables {
                valid_flag_tag_sequence_end(scan, i + ch.len_utf8()).unwrap_or(0)
            } else {
                0
            };
        }
    }
    if rep.spans.len() > MAX_SPAN_EVENTS {
        return Err(format!("span event limit exceeded (maximum {MAX_SPAN_EVENTS}); disable return_spans or split the input"));
    }

    if pol.tidy_whitespace {
        let before = out.clone();
        let after = tidy_whitespace(out);
        if after != before {
            changed = true;
            // Count the characters actually collapsed/trimmed rather than a flat
            // 1, so the removal total (which feeds enforcement thresholds) isn't
            // conflated with a single per-character removal. `max(1)` covers the
            // in-place replacements (e.g. tab -> space) that change content
            // without changing length.
            let removed = before.chars().count().saturating_sub(after.chars().count());
            rep.bump_removed("whitespace_tidy", removed.max(1));
        }
        out = after;
    }

    // Deleting a character can join a starter to marks previously separated
    // from it. Compose the result again so NFC/NFKC and idempotence hold for the
    // returned text, using the original expansion budget rather than growing it.
    // Span offsets continue to refer to `scan`, never to this composed output.
    let mut post_removal_norm_changed = false;
    let mut normalization_truncated = normalized.truncated;
    if !out.is_ascii() && !rep.removed_counts.is_empty() {
        let final_normalized =
            normalize_text_with_limit(&out, pol.normalize, Some(normalized.output_limit_chars));
        normalization_truncated |= final_normalized.truncated;
        if final_normalized.truncated && !normalized.truncated {
            rep.bump_removed("normalization_amplified", 1);
        }
        if let Cow::Owned(final_text) = final_normalized.text {
            post_removal_norm_changed = true;
            out = final_text;
        }
    }
    changed |= post_removal_norm_changed;

    // Flags: base64-ish, entropy, combining ratio
    let mut stats = serde_json::Map::new();
    stats.insert("ascii_fast_path".into(), json!(fast_path));
    let (unicode_major, unicode_minor, unicode_patch) = unicode_normalization::UNICODE_VERSION;
    stats.insert(
        "unicode_normalization_version".into(),
        json!(format!("{unicode_major}.{unicode_minor}.{unicode_patch}")),
    );
    stats.insert(
        "unicode_mark_version".into(),
        json!(format!("{unicode_major}.{unicode_minor}.{unicode_patch}")),
    );
    stats.insert(
        "variation_data_version".into(),
        json!(VARIATION_DATA_VERSION),
    );
    stats.insert("ideographic_variation_policy".into(), json!("han_context"));
    stats.insert(
        "invalid_variation_selector_count".into(),
        json!(invalid_variation_selectors),
    );
    stats.insert("normalized_changed".into(), json!(norm_changed));
    stats.insert(
        "post_removal_normalized_changed".into(),
        json!(post_removal_norm_changed),
    );
    stats.insert(
        "normalization_input_chars".into(),
        json!(normalized.input_chars),
    );
    stats.insert(
        "normalization_output_chars".into(),
        json!(normalized.output_chars),
    );
    stats.insert(
        "normalization_output_limit_chars".into(),
        json!(normalized.output_limit_chars),
    );
    stats.insert(
        "normalization_truncated".into(),
        json!(normalization_truncated),
    );
    stats.insert(
        "default_ignorable_removed".into(),
        json!(default_ignorable_removed),
    );
    stats.insert(
        "default_ignorable_removed_joiner".into(),
        json!(default_ignorable_removed_joiner),
    );
    stats.insert(
        "default_ignorable_removed_variation_selector".into(),
        json!(default_ignorable_removed_variation_selector),
    );
    stats.insert(
        "default_ignorable_removed_tag".into(),
        json!(default_ignorable_removed_tag),
    );
    stats.insert(
        "default_ignorable_removed_other".into(),
        json!(default_ignorable_removed_other),
    );
    stats.insert(
        "default_ignorable_stripped".into(),
        json!(pol.remove_default_ignorables),
    );

    let sig = signal_spec();

    if pol.flag_combining_abuse {
        let (total, combining, max_stack, suspicious_stacks) = combining_stats(&out);
        let ratio = if total == 0 {
            0.0
        } else {
            (combining as f64) / (total as f64)
        };
        stats.insert("combining_ratio".into(), json!(ratio));
        stats.insert("combining_max_stack".into(), json!(max_stack));
        stats.insert(
            "combining_suspicious_stacks".into(),
            json!(suspicious_stacks),
        );
        let high_ratio = ratio > sig.combining_ratio_threshold && total > sig.combining_min_chars;
        if high_ratio {
            rep.bump_flagged("high_combining_ratio", 1);
        }
        if max_stack >= COMBINING_EXTREME_STACK_THRESHOLD
            || suspicious_stacks >= 3
            || (max_stack >= COMBINING_STACK_THRESHOLD && high_ratio)
        {
            rep.bump_flagged("excessive_combining_stack", 1);
        }
    }

    if pol.flag_base64ish {
        let wrapped = looks_wrapped_base64ish(&out, sig.base64_min_chars);
        let b64 = looks_base64ish(&out, sig.base64_min_chars) || wrapped;
        stats.insert("base64ish".into(), json!(b64));
        stats.insert("base64ish_wrapped".into(), json!(wrapped));
        if b64 {
            rep.bump_flagged("base64ish_blob", 1);
        }
    }

    let prefix: String = out.chars().take(sig.entropy_prefix_chars).collect();
    let ent = shannon_entropy(&prefix);
    stats.insert("entropy_2000".into(), json!(ent));
    if ent > sig.entropy_prefix_threshold && out.chars().count() > sig.entropy_prefix_min_chars {
        rep.bump_flagged("high_entropy", 1);
    }

    rep.stats = serde_json::Value::Object(stats);
    rep.changed = changed;

    Ok((out, rep))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidi_override_removed_marks_preserved_in_chat() {
        let (clean, rep) = sanitize_inner("abc\u{202E}def", "balanced_chat", false).unwrap();
        assert_eq!(clean, "abcdef");
        assert_eq!(rep.removed_counts.get("bidi_control"), Some(&1));

        // A right-to-left mark is preserved under chat policies.
        let (clean, rep) = sanitize_inner("a\u{200F}b", "balanced_chat", false).unwrap();
        assert_eq!(clean, "a\u{200F}b");
        assert_eq!(rep.flagged_counts.get("bidi_mark"), Some(&1));
    }

    #[test]
    fn tag_chars_removed_flag_emoji_preserved() {
        let hidden: String = "hi"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let (clean, rep) = sanitize_inner(&format!("x{hidden}"), "balanced_chat", false).unwrap();
        assert_eq!(clean, "x");
        assert_eq!(rep.removed_counts.get("tag_char"), Some(&2));

        let flag = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        let (clean, _) = sanitize_inner(&format!("t{flag}"), "balanced_chat", false).unwrap();
        assert_eq!(clean, format!("t{flag}"));

        let invalid = "\u{1F3F4}\u{E0069}\u{E0067}\u{E006E}\u{E006F}\u{E0072}\u{E0065}";
        let (clean, rep) = sanitize_inner(invalid, "balanced_chat", false).unwrap();
        assert_eq!(clean, "\u{1F3F4}");
        assert_eq!(rep.removed_counts.get("tag_char"), Some(&6));
    }

    #[test]
    fn line_separators_are_removed() {
        let (clean, rep) =
            sanitize_inner("safe\u{2028}SYSTEM\u{2029}tail", "balanced_chat", false).unwrap();
        assert_eq!(clean, "safeSYSTEMtail");
        assert_eq!(rep.removed_counts.get("line_separator"), Some(&2));
    }

    #[test]
    fn normalization_expansion_is_bounded() {
        let input = "\u{FDFA}".repeat(100);
        let (clean, rep) = sanitize_inner(&input, "strict_exec", false).unwrap();
        assert!(clean.chars().count() <= input.chars().count() * 8);
        assert_eq!(rep.removed_counts.get("normalization_amplified"), Some(&1));
        assert_eq!(rep.stats["normalization_truncated"], true);

        let (again, _) = sanitize_inner(&clean, "strict_exec", false).unwrap();
        assert_eq!(again, clean);
    }

    #[test]
    fn variation_selector_run_capped() {
        let run = "\u{FE0F}".repeat(5);
        let (clean, rep) = sanitize_inner(&format!("a{run}"), "balanced_chat", false).unwrap();
        assert_eq!(clean.chars().filter(|c| *c == '\u{FE0F}').count(), 1);
        assert_eq!(
            rep.removed_counts.get("variation_selector_excess"),
            Some(&4)
        );
    }

    #[test]
    fn ascii_controls_never_take_fast_path() {
        for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
            for cp in (0u8..=31).chain(std::iter::once(127)) {
                if matches!(cp, b'\n' | b'\t') {
                    continue;
                }
                let input = format!("a{}b", cp as char);
                let (clean, report) =
                    sanitize_inner_with_overrides(&input, policy, None, Some(false), true).unwrap();
                assert_eq!(clean, "ab", "{policy}: U+{cp:04X}");
                assert_eq!(report.stats["ascii_fast_path"], false);
                assert_eq!(report.spans.len(), 1);
                assert_eq!((report.spans[0].start, report.spans[0].end), (1, 2));
            }
        }
    }

    #[test]
    fn tag_exception_is_an_allowlist_and_chat_only() {
        for name in ["gbeng", "gbsct", "gbwls", "ignore", "all", "sct", "gbengx"] {
            let tags: String = name
                .chars()
                .map(|ch| char::from_u32(0xE0000 + ch as u32).unwrap())
                .collect();
            let input = format!("\u{1F3F4}{tags}\u{E007F}");
            for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
                let (clean, report) = sanitize_inner(&input, policy, true).unwrap();
                let preserve = matches!(policy, "preserve" | "balanced_chat")
                    && matches!(name, "gbeng" | "gbsct" | "gbwls");
                if preserve {
                    assert_eq!(clean, input);
                    assert!(report.removed_counts.is_empty());
                } else {
                    assert_eq!(clean, "\u{1F3F4}");
                    assert_eq!(
                        report.removed_counts.get("tag_char"),
                        Some(&(name.len() + 1))
                    );
                }
            }
        }
    }

    #[test]
    fn normalization_after_deletion_keeps_original_scan_spans() {
        let input = "e\u{200B}\u{0301}";
        for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
            let (clean, report) = sanitize_inner(input, policy, true).unwrap();
            assert_eq!(clean, "é");
            assert_eq!(report.stats["normalized_changed"], false);
            assert_eq!(report.stats["post_removal_normalized_changed"], true);
            assert_eq!(report.spans.len(), 1);
            assert_eq!(
                &input[report.spans[0].start..report.spans[0].end],
                "\u{200B}"
            );
        }
    }

    #[test]
    fn removal_interactions_produce_normalized_fixed_points() {
        let separators = ["\u{200B}", "\r", "\u{202E}", "\u{E0061}", "\0", "\u{2060}"];
        for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
            for separator in separators {
                for (left, right) in [
                    ("e", "\u{0301}"),
                    ("a\u{FE0F}", "\u{E0100}"),
                    ("\u{1100}", "\u{1161}"),
                ] {
                    let input = format!("{left}{separator}{right}");
                    let (clean, _) = sanitize_inner(&input, policy, true).unwrap();
                    let (again, _) = sanitize_inner(&clean, policy, false).unwrap();
                    assert_eq!(clean, again, "{policy}: {input:?}");
                    let normalized: String = if policy == "strict_exec" {
                        clean.nfkc().collect()
                    } else {
                        clean.nfc().collect()
                    };
                    assert_eq!(clean, normalized, "{policy}: {input:?}");
                }
            }
        }
    }

    #[test]
    fn combining_density_is_separate_from_pathological_stacks() {
        let ordinary = "नमस्ते दुनिया ".repeat(4);
        let (_, report) = sanitize_inner(&ordinary, "balanced_chat", false).unwrap();
        assert_eq!(report.flagged_counts.get("high_combining_ratio"), Some(&1));
        assert!(!report
            .flagged_counts
            .contains_key("excessive_combining_stack"));
        for storm in [
            format!("x{}", "\u{0338}".repeat(8)),
            format!("x{} ", "\u{0338}".repeat(5)).repeat(3),
        ] {
            let (_, report) = sanitize_inner(&storm, "balanced_chat", false).unwrap();
            assert_eq!(
                report.flagged_counts.get("excessive_combining_stack"),
                Some(&1)
            );
        }
    }

    #[test]
    fn span_event_budget_fails_without_silent_truncation() {
        let within_budget = "\u{200B}".repeat(MAX_SPAN_EVENTS);
        let (_, report) = sanitize_inner(&within_budget, "balanced_chat", true).unwrap();
        assert_eq!(report.spans.len(), MAX_SPAN_EVENTS);
        let over_budget = format!("{within_budget}\u{200B}");
        assert!(sanitize_inner(&over_budget, "balanced_chat", true)
            .unwrap_err()
            .contains("span event limit exceeded"));
        assert!(sanitize_inner(&over_budget, "balanced_chat", false).is_ok());
    }

    #[test]
    fn base64_run_detected_inside_prose() {
        let blob = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==".repeat(3);
        assert!(looks_base64ish(&format!("decode this {blob} thanks"), 64));
        assert!(!looks_base64ish(
            "the quick brown fox jumps over the lazy dog",
            64
        ));
    }

    #[test]
    fn sanitize_is_idempotent_over_policies() {
        let samples = [
            "plain",
            "abc\u{202E}def\u{200F}",
            "\u{1F600}\u{FE0F}\u{FE0F}\u{FE0F}",
        ];
        for policy in ["preserve", "balanced_chat", "strict_exec", "code_mode"] {
            for s in samples {
                let (once, _) = sanitize_inner(s, policy, false).unwrap();
                let (twice, _) = sanitize_inner(&once, policy, false).unwrap();
                assert_eq!(once, twice, "not idempotent under {policy} for {s:?}");
            }
        }
    }

    #[test]
    fn unknown_policy_errors() {
        assert!(sanitize_inner("x", "nope", false).is_err());
    }
}

#[cfg(feature = "python")]
#[allow(clippy::useless_conversion)]
#[pyfunction(signature = (text, policy="balanced_chat", normalization=None, tidy_whitespace=None, return_spans=false))]
fn sanitize(
    py: Python<'_>,
    text: &str,
    policy: &str,
    normalization: Option<&str>,
    tidy_whitespace: Option<bool>,
    return_spans: bool,
) -> PyResult<(String, Py<PyAny>)> {
    static JSON_LOADS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

    let norm_override = match normalization {
        Some(n) => Some(parse_normalization(n).map_err(PyValueError::new_err)?),
        None => None,
    };
    let result = py.detach(|| {
        sanitize_inner_with_overrides(text, policy, norm_override, tidy_whitespace, return_spans)
    });
    let (clean, report) = result.map_err(PyValueError::new_err)?;

    let json_str =
        serde_json::to_string(&report).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let loads = JSON_LOADS.get_or_try_init(py, || {
        Ok::<Py<PyAny>, PyErr>(py.import("json")?.getattr("loads")?.unbind())
    })?;
    let py_val = loads.bind(py).call1((json_str.as_str(),))?;
    py_val.cast::<pyo3::types::PyDict>()?;
    Ok((clean, py_val.unbind()))
}

#[cfg(feature = "python")]
#[pyfunction(signature = (text, max_chars=1_000_000))]
fn normalize_for_skeleton(py: Python<'_>, text: &str, max_chars: usize) -> PyResult<String> {
    // This helper never returns a partial identifier. It shares the native
    // normalization implementation and releases the GIL like sanitization.
    py.detach(|| {
        if text.chars().count() > max_chars {
            return Err(format!(
                "confusable skeleton input exceeds max_chars={max_chars}"
            ));
        }
        let mut chars = text.nfkc();
        let normalized: String = chars.by_ref().take(max_chars).collect();
        if chars.next().is_some() {
            return Err(format!(
                "confusable skeleton output exceeds max_chars={max_chars}"
            ));
        }
        Ok(normalized)
    })
    .map_err(PyValueError::new_err)
}

#[cfg(feature = "python")]
#[pyfunction]
fn is_identifier_decoration(ch: char) -> bool {
    is_combining_mark(ch as u32) || is_default_ignorable(ch as u32)
}

#[cfg(feature = "python")]
#[pyfunction]
fn encoded_codepoint_risk(ch: char, policy: &str) -> PyResult<Option<&'static str>> {
    encoded_scalar_risk(ch, policy).map_err(PyValueError::new_err)
}

#[cfg(feature = "python")]
// Preserve the existing interpreter requirement until free-threaded builds are validated.
#[pymodule(gil_used = true)]
fn _core(_py: Python<'_>, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sanitize, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_for_skeleton, m)?)?;
    m.add_function(wrap_pyfunction!(is_identifier_decoration, m)?)?;
    m.add_function(wrap_pyfunction!(encoded_codepoint_risk, m)?)?;
    Ok(())
}
