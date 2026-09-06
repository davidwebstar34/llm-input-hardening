from __future__ import annotations

import pytest

from llm_input_hardening import sanitize_and_decide, sanitize_assembled


@pytest.mark.parametrize("policy", ["preserve", "balanced_chat", "strict_exec", "code_mode"])
@pytest.mark.parametrize("text", [
    "ordinary prose",
    "ab" * 20 + "cd" * 20,
    "раypal",
    "x" + "\u0301" * 12,
    "a\u200b\u0301",
    "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f",
    "hello\u202eevil",
])
def test_every_partition_has_same_decision_and_evidence_as_final_input(text, policy) -> None:
    expected_clean, expected_report, expected_decision = sanitize_and_decide(
        text, sanitize_policy=policy, return_spans=True,
    )
    for split in range(len(text) + 1):
        clean, report, decision = sanitize_assembled(
            [text[:split], text[split:]], sanitize_policy=policy, return_spans=True,
        )
        assert report["stats"].pop("assembly_parts") == 2
        assert (clean, report, decision) == (expected_clean, expected_report, expected_decision)


def test_assembly_detects_signal_created_by_joining_allowed_fragments() -> None:
    parts = ["ab" * 20, "cd" * 20]
    assert all(sanitize_and_decide(part)[2]["action"] == "allow" for part in parts)
    _, report, decision = sanitize_assembled(parts)
    assert report["flagged_counts"]["hex_blob"] == 1
    assert decision["action"] == "quarantine"


def test_assembly_validates_actual_final_text_and_change() -> None:
    seen: list[str] = []

    def valid(text):
        seen.append(text)
        return text == "admin/account"

    clean, report, decision = sanitize_assembled(
        ["admin", "account"], separator="/", validator=valid,
    )
    assert seen == [clean] == ["admin/account"]
    assert decision["action"] == "allow"
    assert report["stats"]["field_validation_passed"] is True
    assert sanitize_assembled(["a", "\u0301"], reject_on_change=True)[2]["action"] == "reject"


def test_assembly_counts_separators_and_empty_parts() -> None:
    with pytest.raises(ValueError, match="max_input_chars"):
        sanitize_assembled(["", "", ""], separator="--", max_input_chars=3)
    with pytest.raises(ValueError, match="max_parts"):
        sanitize_assembled(("" for _ in range(4)), max_parts=3)
    assert sanitize_assembled([], max_parts=0, max_input_chars=0)[0] == ""


def test_assembly_stops_at_budget_before_sanitization(monkeypatch) -> None:
    from llm_input_hardening import assembly

    def unexpected(*args, **kwargs):
        pytest.fail("oversized assembly reached sanitization")

    def parts():
        yield "too long"
        pytest.fail("oversized assembly kept consuming input")

    monkeypatch.setattr(assembly, "sanitize_and_decide", unexpected)
    with pytest.raises(ValueError, match="max_input_chars"):
        sanitize_assembled(parts(), max_input_chars=3)


@pytest.mark.parametrize("parts", ["hello", b"hello", ["valid", 123], [None]])
def test_assembly_rejects_invalid_parts(parts) -> None:
    with pytest.raises(TypeError, match="parts"):
        sanitize_assembled(parts)


@pytest.mark.parametrize("name", ["max_parts", "max_input_chars"])
@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_assembly_rejects_invalid_budgets(name, value) -> None:
    with pytest.raises((TypeError, ValueError), match=name):
        sanitize_assembled([], **{name: value})


def test_assembly_propagates_iterator_errors() -> None:
    def broken():
        yield "hello"
        raise RuntimeError("source failed")

    with pytest.raises(RuntimeError, match="source failed"):
        sanitize_assembled(broken())
