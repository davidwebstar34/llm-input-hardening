from __future__ import annotations

from llm_input_hardening import sanitize
from llm_input_hardening.policies import policy_preset


def test_persian_zwnj_preserved_in_balanced_chat() -> None:
    text = "می‌خواهم کتاب"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["removed_counts"].get("default_ignorable", 0) == 0


def test_persian_zwnj_removed_in_strict_exec() -> None:
    text = "می‌خواهم کتاب"
    clean, rep = sanitize(text, policy="strict_exec")
    assert clean == "میخواهم کتاب"
    assert rep["removed_counts"].get("default_ignorable", 0) >= 1


def test_emoji_joiner_chain_preserved_in_balanced_chat() -> None:
    text = "👨‍👩‍👧‍👦"
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["removed_counts"].get("default_ignorable", 0) == 0


def test_combining_mark_heavy_text_flags_in_balanced_chat() -> None:
    text = ("क\u093f" * 200) + ("e\u0338" * 200)
    clean, rep = sanitize(text, policy="balanced_chat")
    assert clean == text
    assert rep["flagged_counts"].get("high_combining_ratio", 0) == 1


def test_backward_compatible_policy_aliases() -> None:
    text = "abc\u202Edef"
    clean_old, _ = sanitize(text, policy="balanced")
    clean_new, _ = sanitize(text, policy="balanced_chat")
    assert clean_old == clean_new == "abcdef"


def test_code_mode_strips_default_ignorables_without_whitespace_tidy() -> None:
    text = "let  value = 'a\u200db';"
    clean, rep = sanitize(text, policy="code_mode")
    assert clean == "let  value = 'ab';"
    assert rep["removed_counts"].get("default_ignorable", 0) >= 1


def test_code_mode_forces_confusable_backend_by_default() -> None:
    clean, rep = sanitize("раypal", policy="code_mode")
    assert clean == "раypal"
    assert rep["stats"].get("confusables_backend") == "confusable_homoglyphs"
    assert rep["flagged_counts"].get("confusable_mixed_script", 0) >= 1


def test_code_mode_alias_kept_for_cli_and_api() -> None:
    text = "abc\u202Edef"
    clean_alias, _ = sanitize(text, policy="code")
    clean_policy, _ = sanitize(text, policy="code_mode")
    assert clean_alias == clean_policy == "abcdef"


def test_policy_registry_matches_runtime_behavior() -> None:
    for policy_name in ("preserve", "balanced_chat", "strict_exec", "code_mode"):
        preset = policy_preset(policy_name)
        clean, report = sanitize("x\u200dy", policy=policy_name)
        assert report["policy"] == preset.name
        assert report["normalization"] == preset.normalization
        removed = report["removed_counts"].get("default_ignorable", 0)
        if preset.remove_default_ignorables:
            assert clean == "xy"
            assert removed >= 1
        else:
            assert clean == "x\u200dy"
            assert removed == 0
