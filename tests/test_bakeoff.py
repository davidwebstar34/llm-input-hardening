from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path


def _run_bakeoff(out_path: Path) -> dict:
    subprocess.run(
        [
            sys.executable,
            "bench/run_bakeoff.py",
            "--out",
            str(out_path),
        ],
        check=True,
        text=True,
    )
    return json.loads(out_path.read_text(encoding="utf-8"))


def _without_timing(payload: dict) -> dict:
    out = copy.deepcopy(payload)
    out.pop("generated_at_utc", None)
    if "env" in out and isinstance(out["env"], dict):
        out["env"].pop("timestamp_utc", None)
    for engine in out.get("engines", []):
        summary = engine.get("summary", {})
        summary.pop("processing_time_ms_p50", None)
        summary.pop("processing_time_ms_p95", None)
        for detail in engine.get("details", []):
            detail.pop("duration_ms", None)
    return out


def test_bakeoff_is_deterministic(tmp_path: Path) -> None:
    first = _run_bakeoff(tmp_path / "first.json")
    second = _run_bakeoff(tmp_path / "second.json")
    assert _without_timing(first) == _without_timing(second)


def test_bakeoff_contains_all_engines_and_regression_floor(tmp_path: Path) -> None:
    result = _run_bakeoff(tmp_path / "bakeoff.json")
    by_engine = {engine["engine"]: engine for engine in result["engines"]}

    assert "llm-input-hardening" in by_engine
    assert "llm-guard:InvisibleText" in by_engine
    assert "confusable-homoglyphs" in by_engine
    assert result["tokenizer"]["backend"] == "heuristic"
    assert result["tokenizer"]["resolved"] == "heuristic:chunk_estimate"

    ours = by_engine["llm-input-hardening"]["summary"]
    assert "micro_precision" in ours
    assert "micro_recall" in ours
    assert "postcondition_pass_rate" in ours
    assert "benign_changed_rate" in ours
    assert "token_delta" in ours
    assert "invariance" in ours
    assert "wilson_lo" in ours["micro_precision_ci"]
    assert "wilson_hi" in ours["micro_precision_ci"]
    assert "wilson_lo" in ours["micro_recall_ci"]
    assert "wilson_hi" in ours["micro_recall_ci"]
    assert "wilson_lo" in ours["postcondition_pass_rate_ci"]
    assert "wilson_hi" in ours["postcondition_pass_rate_ci"]

    details_by_case = {
        row["case"]: row for row in by_engine["llm-input-hardening"]["details"]
    }
    for case_name in (
        "long_invisible_suffix_vs16_run",
        "long_invisible_suffix_extended_vs_run",
        "long_invisible_suffix_tag_run",
        "long_invisible_suffix_zwj_run",
    ):
        assert details_by_case[case_name]["postcondition_passed"] is True

    support = result["corpus"]["label_support"]
    for label, count in support.items():
        assert count >= 10, f"{label} support is below floor: {count}"

    invalid = by_engine["llm-input-hardening"]["per_label"]["invalid_variation_selector"]
    assert invalid["supported"] is True
    assert invalid["positives"] == invalid["detected"] == 16
    assert invalid["false_positives"] == 0
    assert "invalid_variation_selector" in details_by_case["invalid_selector_distributed_payload"]["detected_labels"]
    for name in ("benign_emoji_registered_variation", "benign_mongolian_registered_variation", "benign_han_ideographic_variation"):
        assert "invalid_variation_selector" not in details_by_case[name]["detected_labels"]
        assert details_by_case[name]["changed"] is False
