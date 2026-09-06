from __future__ import annotations

import re

import pytest

from llm_input_hardening import sanitize, sanitize_and_decide
from llm_input_hardening.enforcement import STRICT_ENFORCEMENT_POLICY, decide_enforcement




def test_normalization_preserves_styled_original_observation() -> None:
    clean, report, decision = sanitize_and_decide("𝐚𝐝𝐦𝐢𝐧", sanitize_policy="strict_exec")
    assert clean == "admin"
    assert report["flagged_counts"]["confusable_styled"] == 1
    assert report["stats"]["styled_compatibility_tokens"] == ["𝐚𝐝𝐦𝐢𝐧"]
    assert decision["action"] == "quarantine"


@pytest.mark.parametrize("text", ["раураӏ", "раураӏ раураӏ", "раураӏ привет"])
def test_execution_confusables_remain_visible_in_every_context(text: str) -> None:
    _, report, decision = sanitize_and_decide(text, sanitize_policy="strict_exec")
    assert report["flagged_counts"]["whole_script_confusable"] == 1
    assert decision["action"] == "reject"


def test_repeating_confusable_does_not_allow_chat() -> None:
    _, _, decision = sanitize_and_decide("раураӏ раураӏ")
    assert decision["action"] == "quarantine"


@pytest.mark.parametrize("suffix", [" а", " अ", " привет"])
def test_short_padding_cannot_establish_native_prose(suffix: str) -> None:
    _, _, decision = sanitize_and_decide("раураӏ раураӏ" + suffix)
    assert decision["action"] == "quarantine"


@pytest.mark.parametrize("text", [
    "Παρακαλώ γράψε μια σύντομη περίληψη αυτού του κειμένου.",
    "Пожалуйста, сделай краткое резюме этого сообщения.",
])
def test_native_context_changes_chat_severity_without_erasing_evidence(text: str) -> None:
    _, report, decision = sanitize_and_decide(text)
    assert report["flagged_counts"]["whole_script_confusable"] == 1
    assert decision["action"] == "allow"
    assert decide_enforcement(report, policy=STRICT_ENFORCEMENT_POLICY)["action"] == "reject"


def test_separate_and_combined_enforcement_agree() -> None:
    for policy in ("preserve", "balanced_chat", "strict_exec", "code_mode"):
        _, report, decision = sanitize_and_decide("раypal", sanitize_policy=policy)
        assert decide_enforcement(report) == decision


def test_formatting_volume_does_not_quarantine() -> None:
    text = "def add(a, b):\n" + " " * 24 + "return a + b"
    _, report, decision = sanitize_and_decide(text)
    assert report["removed_counts"]["whitespace_tidy"] >= 12
    assert decision["action"] == "allow"


def test_execution_field_rejects_transformed_path() -> None:
    clean, report, decision = sanitize_and_decide(
        "．．／admin", sanitize_policy="strict_exec", reject_on_change=True,
    )
    assert clean == "../admin"
    assert decision["action"] == "reject"
    assert "IH091_INPUT_TRANSFORMED" in decision["reason_codes"]
    assert decide_enforcement(report) == decision


def test_validator_checks_actual_normalized_output() -> None:
    seen = []

    def validate(text: str) -> bool:
        seen.append(text)
        return bool(re.fullmatch(r"[a-z][a-z0-9_]{0,31}", text))

    _, report, decision = sanitize_and_decide(
        "．．／admin", sanitize_policy="strict_exec", validator=validate,
    )
    assert seen == ["../admin"]
    assert report["stats"]["field_validation_passed"] is False
    assert decision["action"] == "reject"
    assert "IH092_FIELD_VALIDATION_FAILED" in decision["reason_codes"]
    assert decide_enforcement(report) == decision
    assert sanitize_and_decide("account_name", validator=validate)[2]["action"] == "allow"


def test_validator_errors_never_become_allow() -> None:
    def broken(text: str) -> bool:
        raise RuntimeError("validation unavailable")

    with pytest.raises(RuntimeError, match="validation unavailable"):
        sanitize_and_decide("hello", validator=broken)
    with pytest.raises(TypeError, match="return a bool"):
        sanitize_and_decide("hello", validator=lambda _: None)




@pytest.mark.parametrize("limit", [-1, True, 1.5])
def test_invalid_input_budget(limit) -> None:
    with pytest.raises((TypeError, ValueError), match="max_input_chars"):
        sanitize("hello", max_input_chars=limit)


def test_diagnostic_samples_are_bounded() -> None:
    _, report = sanitize("раypal" * 1000)
    assert len(report["stats"]["mixed_script_words"][0]) <= 160
    assert report["stats"]["confusables_skeleton_stored"] is False


def test_skeleton_expansion_cannot_exceed_report_limit() -> None:
    _, report = sanitize("aра" + "\ufdfa" * 300)
    assert report["stats"]["confusables_skeleton_stored"] is False


@pytest.mark.parametrize("text", ["ad\u200cmin\u200d task\ufe0f 1", "Hello Привет", "Tシャツを買いました"])
def test_optional_backend_does_not_treat_formatting_or_separate_words_as_spoofs(text: str) -> None:
    _, report = sanitize(text, confusables_backend="confusable_homoglyphs")
    assert report["flagged_counts"].get("confusable_mixed_script", 0) == 0
