"""Strict artifact parsing, content identity, and reproducible runtime evidence."""
from __future__ import annotations

import hashlib
import json
import math
import subprocess
import unicodedata
from pathlib import Path
from typing import Any

RESULT_SCHEMA_VERSION = 4


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"Non-finite number in JSON: {value}")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), parse_float=_finite_float,
                          parse_constant=_invalid_constant, object_pairs_hook=_unique_object)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Invalid artifact {path}: {exc}") from exc


def fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_provenance(root: Path) -> dict[str, Any]:
    import llm_input_hardening
    from llm_input_hardening import _core
    from llm_input_hardening.policies import signal_thresholds

    package = Path(llm_input_hardening.__file__).resolve().parent
    python_sources = {path.name: file_fingerprint(path) for path in sorted(package.glob("*.py"))}
    local_sources = [*root.glob("src/**/*.rs"), root / "Cargo.toml", root / "Cargo.lock", root / "pyproject.toml"]
    local_hashes = {str(path.relative_to(root)): file_fingerprint(path)
                    for path in sorted(local_sources) if path.is_file()}
    evaluation_sources = {path.name: file_fingerprint(path)
                          for path in sorted(Path(__file__).resolve().parent.glob("*.py"))}
    try:
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"],
                                         cwd=root, stderr=subprocess.DEVNULL)
        dirty: bool | None = bool(status)
    except (OSError, subprocess.CalledProcessError):
        dirty = None
    return {
        "git_dirty": dirty,
        "python_source_sha256": fingerprint(python_sources),
        "python_source_files": python_sources,
        "core_binary_sha256": file_fingerprint(Path(_core.__file__)),
        "policy_registry_sha256": file_fingerprint(package / "policy_registry.json"),
        "effective_signals_sha256": fingerprint(dict(signal_thresholds())),
        "local_build_inputs_sha256": fingerprint(local_hashes),
        "local_build_input_files": local_hashes,
        "evaluation_harness_sha256": fingerprint(evaluation_sources),
        "evaluation_harness_files": evaluation_sources,
        "python_unicode_version": unicodedata.unidata_version,
        # Source inputs are a checkout snapshot, not an assertion that the loaded
        # native binary was built from them. Its separate digest identifies it.
    }


def unique_rows(rows: Any, *, key: str, context: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError(f"{context} must be a list")
    indexed = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get(key), str) or not row[key]:
            raise ValueError(f"Malformed {context} entry: missing {key}")
        if row[key] in indexed:
            raise ValueError(f"Duplicate {context} {key}: {row[key]}")
        indexed[row[key]] = row
    return indexed


def validate_schema(payload: Any, schema_name: str) -> None:
    from jsonschema import Draft202012Validator

    schema = load_json(Path(__file__).with_name("schema") / schema_name)
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda error: str(list(error.path)))
    if errors:
        raise ValueError(f"Malformed {schema_name} input at {list(errors[0].path)}: {errors[0].message}")


def validate_result(result: Any) -> None:
    """Validate every gate input even when no separate schema command was run."""
    validate_schema(result, "bakeoff_results.schema.json")
    engines = unique_rows(result["engines"], key="engine", context="engines")
    composition = result["composition"]
    if composition["failures"] != len(composition["failure_details"]):
        raise ValueError("Composition failure count disagrees with its evidence")
    if composition["failures"]:
        raise ValueError("Final-assembly composition invariants failed")
    for name, engine in engines.items():
        rows = unique_rows(engine["details"], key="case", context=f"{name} cases")
        if engine["available"] and not rows:
            raise ValueError(f"Available engine {name} has no case results")
        if not engine["available"] and rows:
            raise ValueError(f"Unavailable engine {name} has case results")
        supported = set(engine["supported_labels"])
        if not supported or not supported.issubset(result["labels"]):
            raise ValueError(f"Invalid supported-label scope for {name}")
        tp = fp = fn = benign = changed = post_total = post_pass = 0
        for row in rows.values():
            expected, detected = set(row["expected_labels"]), set(row["detected_labels"])
            if not (expected | detected).issubset(supported):
                raise ValueError(f"{name}/{row['case']} contains labels outside its supported scope")
            tp += len(expected & detected)
            fp += len(detected - expected)
            fn += len(expected - detected)
            benign += row["kind"] == "benign"
            changed += row["kind"] == "benign" and row["changed"]
            if row["postcondition_applicable"]:
                if not isinstance(row["postcondition_passed"], bool):
                    raise ValueError(f"{name}/{row['case']} has no applicable postcondition result")
                post_total += 1
                post_pass += row["postcondition_passed"]
            elif row["postcondition_passed"] is not None:
                raise ValueError(f"{name}/{row['case']} reports unsupported postconditions as evaluated")
        expected_summary = {
            "cases": len(rows), "true_positive_labels": tp, "false_positive_labels": fp,
            "false_negative_labels": fn,
            "micro_precision": tp / (tp + fp) if tp + fp else 0.0,
            "micro_recall": tp / (tp + fn) if tp + fn else 0.0,
            "benign_changed_rate": changed / benign if benign else 0.0,
            "postcondition_pass_rate": post_pass / post_total if post_total else 0.0,
        }
        _check_summary(engine["summary"], expected_summary, name)
        if set(engine["per_label"]) != set(result["labels"]):
            raise ValueError(f"{name} per-label results do not cover the declared label set")
        for label, stats in engine["per_label"].items():
            if stats["supported"] != (label in supported):
                raise ValueError(f"{name}/{label} has inconsistent capability metadata")
            expected_stats = {
                "positives": sum(label in row["expected_labels"] for row in rows.values()),
                "predicted": sum(label in row["detected_labels"] for row in rows.values()),
                "detected": sum(label in row["expected_labels"] and label in row["detected_labels"] for row in rows.values()),
                "false_positives": sum(label not in row["expected_labels"] and label in row["detected_labels"] for row in rows.values()),
            }
            _check_summary(stats, expected_stats, f"{name}/{label}")
        if name == "llm-input-hardening" and engine["available"]:
            _check_summary(result["corpus"], {"size": len(rows), "benign_cases": benign,
                                            "attack_cases": len(rows) - benign}, "corpus")
            expected_support = {label: sum(label in row["expected_labels"] for row in rows.values()) for label in result["labels"]}
            _check_summary(result["corpus"]["label_support"], expected_support, "corpus/label_support")
    enforcement_rows = result["enforcement"]["details"]
    identities = {(row["case"], row["policy"]) for row in enforcement_rows}
    if len(identities) != len(enforcement_rows):
        raise ValueError("Duplicate enforcement case/policy result")
    for row in enforcement_rows:
        if row["matches_expectation"] != (row["decision"] == row["expected_decision"]):
            raise ValueError(f"Incorrect enforcement match flag for {row['case']}")
    for policy, summary in result["enforcement"]["by_policy"].items():
        selected = [row for row in enforcement_rows if row["policy"] == policy]
        benign_rows = [row for row in selected if row["kind"] == "benign"]
        if not benign_rows:
            raise ValueError(f"No benign enforcement rows for {policy}")
        expected_summary = {
            "cases": len(selected), "benign_cases": len(benign_rows),
            "decision_mismatches": sum(not row["matches_expectation"] for row in selected),
            "benign_quarantine_rate": sum(row["decision"] == "quarantine" for row in benign_rows) / len(benign_rows),
            "benign_reject_rate": sum(row["decision"] == "reject" for row in benign_rows) / len(benign_rows),
        }
        _check_summary(summary, expected_summary, f"enforcement/{policy}")
        if expected_summary["decision_mismatches"]:
            raise ValueError(f"Enforcement invariants failed for {policy}")


def _check_summary(actual: dict[str, Any], expected: dict[str, Any], context: str) -> None:
    for key, value in expected.items():
        observed = actual.get(key)
        if isinstance(observed, bool) or not isinstance(observed, (int, float)) or not math.isclose(observed, value, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError(f"{context} summary.{key} disagrees with case evidence")
