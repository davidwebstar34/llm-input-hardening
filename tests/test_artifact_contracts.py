from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bench.artifact_contracts import file_fingerprint, fingerprint, load_json, runtime_provenance, validate_result
from bench.assert_audit_scope import assert_audit_scope
from bench.assert_bakeoff_diff import validate_diff
from bench.bakeoff_diff import ALL_METRICS, _compare_engine
from bench.composition_eval import CASES, CHANGE_MODES, POLICIES, SEPARATORS, evaluate_composition
from bench.run_bakeoff import LABELS, _compute_summary, _load_corpus


@pytest.fixture
def artifact() -> dict:
    """Synthetic evidence for gate tests; this is never a runtime baseline."""
    row = {"case": "sample", "case_fingerprint": fingerprint("sample"), "kind": "attack",
           "policy": "balanced_chat", "expected_labels": ["bidi_control"],
           "detected_labels": ["bidi_control"], "expected_action": "remove", "changed": True,
           "postcondition_applicable": True, "postcondition_passed": True,
           "postcondition_failures": []}
    engine = _compute_summary(engine_name="llm-input-hardening", details=[row],
                              available=True, error=None, version="synthetic")
    enforcement = [{"case": "benign", "case_fingerprint": fingerprint(policy), "kind": "benign",
                    "policy": policy, "decision": "allow", "expected_decision": "allow",
                    "matches_expectation": True} for policy in POLICIES]
    provenance = {key: "0" * 64 for key in ("python_source_sha256", "core_binary_sha256",
                  "policy_registry_sha256", "effective_signals_sha256", "local_build_inputs_sha256")}
    provenance.update(git_dirty=True, python_unicode_version="synthetic")
    result = {"schema_version": 4, "generated_at_utc": "synthetic", "labels": LABELS,
              "corpus": {"path": "synthetic", "fingerprint": fingerprint("corpus"), "size": 1,
                         "attack_cases": 1, "benign_cases": 0,
                         "label_support": {label: int(label == "bidi_control") for label in LABELS}},
              "tokenizer": {"backend": "synthetic", "resolved": "synthetic"},
              "env": {"git_sha": None, "python_version": "synthetic", "platform": "synthetic",
                      "provenance": provenance,
                      "dependencies": {name: None for name in ("llm-input-hardening", "llm-guard", "confusable-homoglyphs")}},
              "engines": [engine], "common_label_comparisons": [],
              "composition": {"fingerprint": fingerprint("composition"), "case_count": 1,
                              "checks": 1, "failures": 0, "failure_details": []},
              "enforcement": {"path": "synthetic", "fingerprint": fingerprint("enforcement"),
                              "details": enforcement,
                              "by_policy": {policy: {"cases": 1, "benign_cases": 1,
                                "decision_mismatches": 0, "benign_quarantine_rate": 0,
                                "benign_reject_rate": 0} for policy in POLICIES}}}
    validate_result(result)
    return result


@pytest.mark.parametrize("encoded", ['{"metric":NaN}', '{"metric":Infinity}',
                                     '{"metric":1e999}', '{"metric":1,"metric":0}'])
def test_strict_artifacts_reject_ambiguous_or_nonfinite_json(tmp_path: Path, encoded: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(encoded)
    with pytest.raises(ValueError, match="Invalid artifact"):
        load_json(path)


def test_fingerprints_cover_content_policy_and_expectations() -> None:
    contract = {"text": "abc", "policy": "preserve", "expected": {"must_detect": []}}
    assert fingerprint(contract) == fingerprint(dict(reversed(list(contract.items()))))
    for key, value in (("text", "abd"), ("policy", "strict_exec"), ("expected", {"must_detect": ["hex_blob"]})):
        changed = {**contract, key: value}
        assert fingerprint(contract) != fingerprint(changed)


def test_audit_requires_nonempty_supported_runtime_scope(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    for incomplete in ("", "# export\n", "unrelated==1.0.0\n"):
        requirements.write_text(incomplete)
        with pytest.raises(ValueError):
            assert_audit_scope(requirements, ["confusable-homoglyphs"])
    requirements.write_text("confusable_homoglyphs==3.3.1\n    --hash=sha256:abc\n")
    assert assert_audit_scope(requirements, ["confusable-homoglyphs"]) == {"confusable-homoglyphs"}



@pytest.mark.parametrize("mutation", ["empty", "duplicate", "summary", "support", "enforcement", "composition"])
def test_result_gate_rejects_missing_or_forged_evidence(artifact: dict, mutation: str) -> None:
    engine = artifact["engines"][0]
    if mutation == "empty":
        engine["details"] = []
    elif mutation == "duplicate":
        engine["details"] *= 2
    elif mutation == "summary":
        engine["summary"]["micro_recall"] = 0.5
    elif mutation == "support":
        engine["per_label"]["bidi_control"]["positives"] = 10
    elif mutation == "enforcement":
        artifact["enforcement"]["details"][0]["decision"] = "quarantine"
    else:
        artifact["composition"]["failures"] = 1
        artifact["composition"]["failure_details"] = [{"case": "broken"}]
    with pytest.raises(ValueError):
        validate_result(artifact)


@pytest.mark.parametrize("mutation", ["changed", "missing", "duplicate", "disjoint"])
def test_pairing_refuses_nonidentical_case_contracts(artifact: dict, mutation: str) -> None:
    baseline = artifact["engines"][0]
    current = copy.deepcopy(baseline)
    row = current["details"][0]
    if mutation == "changed":
        row["case_fingerprint"] = fingerprint("new content same name")
    elif mutation == "missing":
        row.pop("case_fingerprint")
    elif mutation == "duplicate":
        current["details"] *= 2
    else:
        row["case"] = "other"
    with pytest.raises(ValueError):
        _compare_engine(baseline_engine=baseline, current_engine=current, labels=LABELS,
                        bootstrap_samples=4, seed=1, regression_epsilon=0)


def test_duplicate_corpus_names_rejected(tmp_path: Path) -> None:
    case = load_json(Path("bench/obfuscation_corpus/cases.json"))[0]
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps([case, case]))
    with pytest.raises(ValueError, match="Duplicate"):
        _load_corpus(str(path))


def test_diff_gate_recomputes_regressions_instead_of_trusting_flags() -> None:
    metrics = {metric: {"baseline": 1, "current": 1, "delta": 0,
                       "bootstrap_ci": {"lo": 0, "hi": 0}} for metric in ALL_METRICS}
    engine = {"engine": "test", "shared_case_count": 1, "metrics": metrics,
              "regressions": [], "regression_detected": False}
    report = {"comparison_status": "comparable", "regression_epsilon": 0,
              "engines": [engine], "regression_detected": False}
    assert validate_diff(report) == []
    metrics["micro_recall"].update(current=0.5, delta=-0.5)
    with pytest.raises(ValueError, match="flag disagrees"):
        validate_diff(report)
    engine.update(regression_detected=True, regressions=["micro_recall"])
    report["regression_detected"] = True
    assert validate_diff(report) == ["test: micro_recall"]
    engine["shared_case_count"] = 0
    with pytest.raises(ValueError, match="no paired case support"):
        validate_diff(report)


def test_diff_skip_needs_explicit_baseline_transition(tmp_path: Path) -> None:
    path = tmp_path / "diff.json"
    path.write_text(json.dumps({"comparison_status": "not_comparable", "reason": "first schema4 run"}))
    command = [sys.executable, "bench/assert_bakeoff_diff.py", "--in", str(path)]
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert subprocess.run([*command, "--allow-no-baseline"], capture_output=True).returncode == 0
    path.write_text("{}")
    assert subprocess.run([*command, "--allow-no-baseline"], capture_output=True).returncode != 0


def test_empty_threshold_configuration_cannot_disable_gate(artifact: dict, tmp_path: Path) -> None:
    result, thresholds = tmp_path / "result.json", tmp_path / "thresholds.json"
    result.write_text(json.dumps(artifact))
    thresholds.write_text("{}")
    proc = subprocess.run([sys.executable, "bench/assert_bakeoff.py", "--in", str(result),
                           "--thresholds", str(thresholds)], capture_output=True, text=True)
    assert proc.returncode != 0
    assert "thresholds.schema.json" in proc.stderr


def test_complete_assembly_matches_direct_sanitization_at_every_boundary() -> None:
    result = evaluate_composition()
    expected_checks = sum(len(case["text"]) + 1 for case in CASES) * len(POLICIES) * len(SEPARATORS) * len(CHANGE_MODES)
    assert result["checks"] == expected_checks > 4000
    assert result["failures"] == 0, result["failure_details"]


@pytest.mark.parametrize("mutation,message", [
    ("fingerprint", "Case contracts changed"), ("engine_set", "Engine sets changed"),
    ("availability", "Engine availability changed"), ("empty", "No available engines"),
    ("schema", "requires schema 4"), ("composition", "evaluation contract changed"),
])
def test_diff_cli_refuses_incomparable_evidence(artifact: dict, tmp_path: Path, mutation: str, message: str) -> None:
    # Include an optional unavailable adapter in both artifacts to exercise scope
    # and availability changes independently of the local engine's corpus counts.
    artifact["engines"].append(_compute_summary(engine_name="confusable-homoglyphs", details=[],
        available=False, error="not installed", version=None))
    baseline, current = copy.deepcopy(artifact), copy.deepcopy(artifact)
    if mutation == "fingerprint":
        current["engines"][0]["details"][0]["case_fingerprint"] = fingerprint("changed")
    elif mutation == "engine_set":
        current["engines"].pop()
    elif mutation == "availability":
        row = copy.deepcopy(current["engines"][0]["details"][0])
        row.update(expected_labels=[], detected_labels=[], postcondition_applicable=False,
                   postcondition_passed=None)
        current["engines"][1] = _compute_summary(engine_name="confusable-homoglyphs", details=[row],
                                                available=True, error=None, version="synthetic")
    elif mutation == "empty":
        baseline["engines"].pop(0)
        current["engines"].pop(0)
    elif mutation == "schema":
        current["schema_version"] = 3
    else:
        current["composition"]["fingerprint"] = fingerprint("different partitions")
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(json.dumps(baseline))
    new.write_text(json.dumps(current))
    proc = subprocess.run([sys.executable, "bench/bakeoff_diff.py", "--baseline", str(old),
                           "--current", str(new), "--out-json", str(tmp_path / "diff.json"),
                           "--out-md", str(tmp_path / "diff.md")], capture_output=True, text=True)
    assert proc.returncode != 0
    assert message in proc.stderr


def test_provenance_identifies_loaded_core_separately_from_checkout(tmp_path: Path) -> None:
    from llm_input_hardening import _core

    source = tmp_path / "src"
    source.mkdir()
    rust = source / "lib.rs"
    rust.write_text("// first source snapshot\n")
    before = runtime_provenance(tmp_path)
    rust.write_text("// different source; same loaded binary\n")
    after = runtime_provenance(tmp_path)
    assert before["core_binary_sha256"] == after["core_binary_sha256"] == file_fingerprint(Path(_core.__file__))
    assert before["local_build_inputs_sha256"] != after["local_build_inputs_sha256"]
    assert before["python_source_sha256"] == after["python_source_sha256"]
    assert before["git_dirty"] is None
