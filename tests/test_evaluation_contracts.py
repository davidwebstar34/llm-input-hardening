from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from bench.enforcement_eval import evaluate_enforcement
from bench.generate_mutation_corpus import _mutate_bidi_weave, _mutate_homoglyph
from bench.run_bakeoff import _common_label_comparisons, _compute_summary
from bench.run_benchmarks import run_case
from bench.run_microbench import CASES


def test_classifier_lift_uses_current_corpus_and_rejects_empty_support(tmp_path: Path) -> None:
    output = tmp_path / "lift.json"
    subprocess.run([sys.executable, "bench/run_classifier_lift.py", "--out", str(output)], check=True)
    corpus = json.loads(Path("bench/obfuscation_corpus/cases.json").read_text(encoding="utf-8"))
    expected_support = sum(case["kind"] == "attack" and bool(case["expected"]["must_detect"]) for case in corpus)
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["obfuscated_cases"] == expected_support > 0
    assert result["after_detection_rate"] > 0

    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    proc = subprocess.run([sys.executable, "bench/run_classifier_lift.py", "--corpus", str(empty), "--out", str(output)], text=True, capture_output=True)
    assert proc.returncode != 0
    assert "No labeled attack cases" in proc.stderr


def test_enforcement_preserves_benign_friction_in_metrics() -> None:
    result = evaluate_enforcement(Path("bench/enforcement_corpus.json"))
    for summary in result["by_policy"].values():
        assert summary["benign_cases"] >= 9
        assert summary["decision_mismatches"] == 0
        assert summary["benign_quarantine_rate"] > 0
        assert summary["unexpected_quarantine_rate"] == 0
    hash_rows = [row for row in result["details"] if row["case"] == "benign_complete_sha256"]
    assert len(hash_rows) == 4
    assert all(row["kind"] == "benign" and row["decision"] == "quarantine" for row in hash_rows)
    for name in ("benign_emoji_registered_variation", "benign_mongolian_registered_variation", "benign_han_ideographic_variation"):
        rows = [row for row in result["details"] if row["case"] == name]
        assert len(rows) == 4
        for row in rows:
            assert row["kind"] == "benign"
            assert not row["flagged_counts"].get("invalid_variation_selector")
            assert row["decision"] == ("allow" if row["policy"] in {"preserve", "balanced_chat"} else "quarantine")


def test_enforcement_corpus_requires_every_policy(tmp_path: Path) -> None:
    corpus = tmp_path / "invalid.json"
    corpus.write_text(json.dumps([{"name": "sample", "kind": "benign", "text": "hello", "expected_decisions": {"balanced_chat": "allow"}}]), encoding="utf-8")
    with pytest.raises(ValueError, match="all four policies"):
        evaluate_enforcement(corpus)


def test_comparisons_exclude_unsupported_capabilities() -> None:
    row = {"expected_labels": ["bidi_control", "hex_blob"], "detected_labels": ["bidi_control"], "postcondition_applicable": False}
    other = _compute_summary(engine_name="llm-guard:InvisibleText", details=[row], available=True, error=None, version="test")
    assert other["summary"]["micro_recall"] == 1.0
    assert other["per_label"]["hex_blob"]["supported"] is False
    assert other["per_label"]["hex_blob"]["positives"] == 0
    assert other["summary"]["postcondition_pass_rate_ci"]["support"] == 0
    ours = _compute_summary(engine_name="llm-input-hardening", details=[row], available=True, error=None, version="test")
    assert ours["summary"]["micro_recall"] == 0.5
    comparison = _common_label_comparisons([ours, other])[0]
    assert comparison["labels"] == ["bidi_control", "junk_invisible"]
    assert all(metrics["recall"] == 1.0 for metrics in comparison["engines"].values())


def test_timing_retains_individual_slow_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([0, 1, 1, 2, 2, 102])
    monkeypatch.setattr("bench.run_benchmarks.time.perf_counter", lambda: next(ticks))
    monkeypatch.setattr("bench.run_benchmarks.sanitize", lambda *args, **kwargs: None)
    assert run_case("sample", "balanced_chat", loops=3) == [1, 1, 100]
    attack = next(case.text for case in CASES if case.name == "unicode_attackish")
    assert "\u202e" in attack
    assert "\\u202E" not in attack


def test_mutation_contract_gate_rejects_missing_detection(tmp_path: Path) -> None:
    result = tmp_path / "mutation.json"
    subprocess.run([sys.executable, "bench/run_bakeoff.py", "--out", str(result)], check=True)
    payload = json.loads(result.read_text(encoding="utf-8"))
    engine = next(entry for entry in payload["engines"] if entry["engine"] == "llm-input-hardening")
    missed = next(row for row in engine["details"] if "bidi_control" in row["expected_labels"])
    missed["detected_labels"].remove("bidi_control")
    # Keep all aggregate evidence honest so failure comes from the missing
    # detection contract, not malformed schema or a stale summary.
    engine.update(_compute_summary(engine_name=engine["engine"], details=engine["details"],
                                   available=True, error=None, version=engine["version"]))
    result.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run([sys.executable, "bench/assert_case_contracts.py", "--in", str(result)], text=True, capture_output=True)
    assert proc.returncode != 0
    assert "Case contract failures" in proc.stderr
    assert missed["case"] in proc.stderr
    assert "bidi_control" in proc.stderr


def test_random_noop_mutations_still_satisfy_their_labels(monkeypatch: pytest.MonkeyPatch) -> None:
    rng = random.Random(1)
    monkeypatch.setattr(rng, "random", lambda: 1.0)
    text = "review payment account status"
    assert _mutate_bidi_weave(text, rng) != text
    homoglyph = _mutate_homoglyph(text, rng)
    assert any(any(ch.isascii() for ch in word) and any(not ch.isascii() for ch in word) for word in homoglyph.split())
