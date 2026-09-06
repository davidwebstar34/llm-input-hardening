from __future__ import annotations

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


def test_lint_corpus_passes_for_repo_corpus() -> None:
    subprocess.run(
        [
            sys.executable,
            "bench/lint_corpus.py",
            "--corpus",
            "bench/obfuscation_corpus/cases.json",
            "--thresholds",
            "bench/bakeoff_thresholds.json",
        ],
        check=True,
        text=True,
    )


def test_validate_json_schemas_pass_for_repo_payloads(tmp_path: Path) -> None:
    bakeoff_path = tmp_path / "bakeoff.json"
    _run_bakeoff(bakeoff_path)
    subprocess.run(
        [
            sys.executable,
            "bench/validate_json.py",
            "--schema-dir",
            "bench/schema",
            "--corpus",
            "bench/obfuscation_corpus/cases.json",
            "--thresholds",
            "bench/bakeoff_thresholds.json",
            "--results",
            str(bakeoff_path),
        ],
        check=True,
        text=True,
    )


def test_smoke_assertion_passes_for_local_engine_only(tmp_path: Path) -> None:
    bakeoff_path = tmp_path / "bakeoff.json"
    _run_bakeoff(bakeoff_path)
    subprocess.run(
        [
            sys.executable,
            "bench/assert_bakeoff.py",
            "--in",
            str(bakeoff_path),
            "--thresholds",
            "bench/bakeoff_thresholds.json",
            "--engine-mode",
            "smoke",
        ],
        check=True,
        text=True,
    )


def test_generate_mutation_corpus_is_schema_valid(tmp_path: Path) -> None:
    corpus_path = tmp_path / "nightly_mutations.json"
    subprocess.run(
        [
            sys.executable,
            "bench/generate_mutation_corpus.py",
            "--out",
            str(corpus_path),
            "--count-per-operator",
            "2",
            "--seed",
            "42",
        ],
        check=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            "bench/validate_json.py",
            "--schema-dir",
            "bench/schema",
            "--corpus",
            str(corpus_path),
            "--thresholds",
            "bench/bakeoff_thresholds.json",
        ],
        check=True,
        text=True,
    )


def test_probe_unicode_survivors_passes() -> None:
    subprocess.run(
        [sys.executable, "bench/probe_unicode_survivors.py"],
        check=True,
        text=True,
    )


def test_bakeoff_diff_emits_json_and_markdown(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    _run_bakeoff(baseline_path)
    _run_bakeoff(current_path)

    out_json = tmp_path / "diff.json"
    out_md = tmp_path / "diff.md"

    subprocess.run(
        [
            sys.executable,
            "bench/bakeoff_diff.py",
            "--baseline",
            str(baseline_path),
            "--current",
            str(current_path),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
            "--bootstrap-samples",
            "128",
            "--seed",
            "42",
        ],
        check=True,
        text=True,
    )

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert isinstance(payload.get("regression_detected"), bool)
    assert len(payload.get("engines", [])) >= 1
    for engine in payload["engines"]:
        assert "metrics" in engine
        assert "micro_precision" in engine["metrics"]
        assert "macro_recall_excluding_zero_support" in engine["metrics"]

    rendered = out_md.read_text(encoding="utf-8")
    assert rendered.startswith("# Bake-off Diff Report")

    subprocess.run(
        [
            sys.executable,
            "bench/assert_bakeoff_diff.py",
            "--in",
            str(out_json),
        ],
        check=True,
        text=True,
    )
