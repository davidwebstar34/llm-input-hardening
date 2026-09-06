from __future__ import annotations

import json
import subprocess
import sys

import pytest

from llm_input_hardening import sanitize, sanitize_and_decide, sanitize_json
from llm_input_hardening import encoded_unicode as inspection
from llm_input_hardening.enforcement import EnforcementPolicy, decide_enforcement


@pytest.mark.parametrize("payload", [
    "abc&#x202E;def", "< abc&#x202E;def", "abc&#8238;def", "abc&#X0000202e;def",
    "abc&#x202E", "abc&#00000000000000000000008238;def",
    "abc&ZeroWidthSpace;def", "abc&#0;def", "abc&#11;def",
    r"abc\u202edef", r"abc\U0000202Edef", r"abc\udb40\udc61def",
    "abc%E2%80%AEdef", "abc%e2%80%aedef", "%FF%E2%80%AE",
    "abc&amp;#x202E;def", "abc&amp;amp;#8238;def", "%26%23x202E%3B",
    r"\u0026#x202E;", r"%5Cu202E", r"\u0025E2%80%AE",
])
@pytest.mark.parametrize("policy", ["preserve", "balanced_chat", "strict_exec", "code_mode"])
def test_encoded_risk_is_observed_without_decoding_output(payload: str, policy: str) -> None:
    clean, report, decision = sanitize_and_decide(payload, sanitize_policy=policy)
    assert clean == payload
    assert report["changed"] is False
    assert report["removed_counts"] == {}
    assert report["flagged_counts"]["encoded_risky_unicode"] >= 1
    assert report["reason_codes"]["IH033_ENCODED_RISKY_UNICODE"] >= 1
    assert decision["action"] != "allow"
    assert report["stats"]["encoded_unicode_limit"] is None


@pytest.mark.parametrize("payload", [
    "Tom &amp; Jerry", "&lt;script&gt;", "caf&#233;", "100% complete",
    "%E6%97%A5%E6%9C%AC", r"\u65e5\u672c", r"\ud83d\ude00",
    "&unknown;", "&#x;", "%GG", r"\uZZZZ", "&#99999999;",
    "https://example.com/a%20b?q=a+b", "cafÃ©", "“hello”",
])
def test_benign_entities_escapes_and_mojibake_are_preserved(payload: str) -> None:
    clean, report = sanitize(payload, policy="preserve")
    assert clean == payload
    assert "encoded_risky_unicode" not in report["flagged_counts"]
    assert "encoded_unicode_inspection_limit" not in report["flagged_counts"]


@pytest.mark.parametrize("payload", ["&lrm;", "&rlm;", "&zwj;", "&zwnj;", r"\uFE0F"])
def test_contextual_chat_characters_follow_policy(payload: str) -> None:
    assert "encoded_risky_unicode" not in sanitize(payload)[1]["flagged_counts"]
    assert sanitize(payload, policy="strict_exec")[1]["flagged_counts"]["encoded_risky_unicode"]


def test_unpaired_surrogate_is_reported_without_pyo3_conversion() -> None:
    report = sanitize(r"\uD800")[1]
    assert report["stats"]["encoded_unicode_samples"][0]["reasons"] == ["invalid_unicode_scalar"]


def test_sample_offsets_trace_mixed_nested_encodings_and_unicode_prefix() -> None:
    payload = "😀 &amp; ordinary %26amp%3B%23x202E%3B then &#8238;"
    _, report = sanitize(payload)
    samples = report["stats"]["encoded_unicode_samples"]
    spans = {payload[s["start"]:s["end"]]: s for s in samples}
    nested = spans["%26amp%3B%23x202E%3B"]
    assert nested["encodings"] == ["html_entity", "percent_utf8"]
    assert nested["decode_depth"] == 3
    assert nested["source"] == "input"
    assert "&#8238;" in spans


@pytest.mark.parametrize("payload,policy", [
    ("&\u200b#x202E;", "balanced_chat"),
    ("＆＃ｘ２０２Ｅ；", "strict_exec"),
    ("＼u202e", "strict_exec"),
])
def test_inspects_escapes_assembled_by_sanitization(payload: str, policy: str) -> None:
    clean, report, decision = sanitize_and_decide(payload, sanitize_policy=policy)
    assert report["flagged_counts"]["encoded_risky_unicode"]
    sample = next(s for s in report["stats"]["encoded_unicode_samples"] if s["source"] == "sanitized")
    assert clean[sample["start"]:sample["end"]] in ("&#x202E;", r"\u202e")
    assert decision["action"] != "allow"


def test_sampling_is_bounded_but_counts_are_not_truncated() -> None:
    report = sanitize("&#8238; " * 30)[1]
    assert report["flagged_counts"]["encoded_risky_unicode"] == 30
    assert len(report["stats"]["encoded_unicode_samples"]) == inspection.MAX_SAMPLES


@pytest.mark.parametrize("setting,value,payload,reason", [
    ("MAX_CANDIDATES", 2, "&amp; &amp; &#8238;", "candidates"),
    ("MAX_CANDIDATE_CHARS", 8, "&#0000000000008238;", "candidate_chars"),
    ("MAX_DECODE_DEPTH", 1, "&amp;#8238;", "decode_depth"),
])
def test_incomplete_inspection_is_never_silently_allowed(monkeypatch, setting, value, payload, reason) -> None:
    monkeypatch.setattr(inspection, setting, value)
    clean, report, decision = sanitize_and_decide(payload)
    assert clean == payload
    assert report["stats"]["encoded_unicode_limit"] == reason
    assert report["reason_codes"]["IH034_ENCODED_UNICODE_INSPECTION_LIMIT"] == 1
    assert decision["action"] == "quarantine"


def test_depth_budget_allows_a_finished_third_layer() -> None:
    assert sanitize("&amp;amp;#8238;")[1]["stats"]["encoded_unicode_limit"] is None
    assert sanitize("&amp;amp;amp;#8238;")[1]["stats"]["encoded_unicode_limit"] == "decode_depth"


def test_callers_can_change_encoded_signal_severity() -> None:
    report = sanitize("&#8238;")[1]
    assert decide_enforcement(report)["action"] == "quarantine"
    assert decide_enforcement(report, policy=EnforcementPolicy(
        reject_flags=frozenset({"encoded_risky_unicode"}),
    ))["action"] == "reject"
    assert decide_enforcement(report, policy=EnforcementPolicy(
        quarantine_flags=frozenset(),
    ))["action"] == "allow"


def test_json_keeps_per_field_encoded_evidence() -> None:
    payload = {"prompt": "< abc&#x202E;def", "amount": 123}
    clean, report = sanitize_json(payload, return_spans=True)
    assert clean == payload
    assert decide_enforcement(report)["action"] == "quarantine"
    leaf = next(r for r in report["stats"]["json_path_reports"] if r["path"] == "prompt")
    sample = leaf["encoded_unicode_samples"][0]
    assert payload["prompt"][sample["start"]:sample["end"]] == "&#x202E;"
    assert report["spans"] == []


def test_cli_applies_encoded_inspection_without_an_extra() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "llm_input_hardening.cli", "decide", "--text", "< abc&#8238;def"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["decision"]["action"] == "quarantine"


def test_large_adversarial_candidates_have_a_work_limit() -> None:
    result = subprocess.run([sys.executable, "-c", """
from llm_input_hardening import sanitize_and_decide
for text in ['&#' + '0' * 900000 + '8238;', '%41' * 300000, '&amp;' * 180000]:
    clean, report, decision = sanitize_and_decide(text)
    assert clean == text
    assert report['flagged_counts']['encoded_unicode_inspection_limit']
    assert decision['action'] != 'allow'
"""], check=True, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0


def test_removed_repair_option_errors_instead_of_silently_ignoring_it() -> None:
    with pytest.raises(TypeError, match="use_ftfy"):
        sanitize("text", use_ftfy=True)
