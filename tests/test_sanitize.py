from llm_input_hardening import sanitize

def test_removes_bidi():
    s = "abc\u202Edef"
    clean, rep = sanitize(s, policy="balanced_chat", return_spans=True)
    assert clean == "abcdef"
    assert rep["removed_counts"].get("bidi_control", 0) == 1

def test_removes_zwsp_bom_word_joiner():
    s = "a\u200Bb\uFEFFc\u2060d"
    clean, rep = sanitize(s, policy="balanced_chat")
    assert clean == "abcd"
    removed_total = rep["removed_counts"].get("default_ignorable", 0) + rep["removed_counts"].get(
        "junk_invisible", 0
    )
    assert removed_total >= 3

def test_preserves_zwj_zwnj_in_balanced_chat():
    s = "a\u200Cb\u200Dd"
    clean, rep = sanitize(s, policy="balanced_chat")
    assert clean == s
    assert rep["removed_counts"].get("default_ignorable", 0) == 0

def test_removes_zwj_zwnj_in_strict_exec():
    s = "a\u200Cb\u200Dd"
    clean, rep = sanitize(s, policy="strict_exec")
    assert clean == "abd"
    assert rep["removed_counts"].get("default_ignorable", 0) == 2

def test_normalization_override_nfkc():
    s = "x\u00b2"  # superscript two
    clean, rep = sanitize(s, policy="preserve", normalization="NFKC")
    assert clean == "x2"

def test_tidy_whitespace_override_on_preserve_policy():
    s = "a  b"
    clean, _ = sanitize(s, policy="preserve", tidy_whitespace=True)
    assert clean == "a b"


def test_tidy_whitespace_normalizes_unicode_space_separators():
    s = " hello\u00a0\u3000thin\u2009\u200ahair\u1680 "
    clean, rep = sanitize(s, policy="balanced_chat")
    assert clean == "hello thin hair"
    assert rep["removed_counts"].get("whitespace_tidy", 0) >= 1


def test_no_tidy_whitespace_override_preserves_unicode_space_separators():
    s = "hello\u00a0\u3000world"
    clean, rep = sanitize(s, policy="balanced_chat", tidy_whitespace=False)
    assert clean == s
    assert rep["removed_counts"].get("whitespace_tidy", 0) == 0

def test_flags_base64_entropy_and_combining():
    # Base64ish blob alone should trigger base64 flag
    base64ish = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 3  # len 96
    _, rep_b64 = sanitize(base64ish, policy="balanced_chat")
    assert rep_b64["flagged_counts"].get("base64ish_blob", 0) == 1

    # Combining-heavy text should trigger combining flag (but not base64).
    # The filler is deliberately word-broken by spaces so it is not itself a
    # long base64-alphabet run (the base64 signal now scans for encoded-looking
    # runs embedded anywhere, not just whole-string blobs).
    combining = "e\u0338" * 120  # heavy combining to exceed 20% threshold
    noisy = "the quick brown fox jumps over the lazy dog " * 8
    payload = combining + noisy
    _, rep = sanitize(payload, policy="balanced_chat")
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1
    assert rep["flagged_counts"].get("base64ish_blob", 0) == 0

    # High-entropy blob should trigger entropy flag
    high_entropy_payload = "".join(chr(0x2500 + (i % 64)) for i in range(512))
    _, rep_ent = sanitize(high_entropy_payload, policy="balanced_chat")
    assert rep_ent["flagged_counts"].get("high_entropy", 0) == 1

def test_flags_hex_blob_without_transform():
    hex_blob = "deadbeef" * 32
    clean, rep = sanitize(hex_blob, policy="balanced_chat")
    assert clean == hex_blob
    assert rep["flagged_counts"].get("hex_blob", 0) == 1


def test_nfkc_normalization_and_removal_are_fixed_point():
    clean, rep = sanitize("Ａ\u200bＢ\u202eＣ", policy="strict_exec")
    assert clean == "ABC"
    assert rep["removed_counts"].get("junk_invisible", 0) == 1
    assert rep["removed_counts"].get("bidi_control", 0) == 1

    clean_again, rep_again = sanitize(clean, policy="strict_exec")
    assert clean_again == clean
    assert rep_again["changed"] is False


def test_normalization_expansion_is_bounded_and_reported():
    text = "\ufdfa" * 8
    clean, rep = sanitize(text, policy="strict_exec")
    assert rep["removed_counts"].get("normalization_amplified", 0) == 1
    assert rep["reason_codes"].get("IH013_NORMALIZATION_EXPANSION_LIMIT", 0) == 1
    assert rep["stats"]["normalization_truncated"] is True
    assert rep["stats"]["normalization_output_chars"] == 128
    assert len(clean) <= 128

    clean_again, _ = sanitize(clean, policy="strict_exec")
    assert clean_again == clean
