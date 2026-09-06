from __future__ import annotations

import json
import os
import subprocess
import sys


def _run_cli(args: list[str], stdin: str = "") -> subprocess.CompletedProcess[str]:
    raw = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "llm_input_hardening.cli", *args],
        input=stdin.encode("utf-8"),
        text=False,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    return subprocess.CompletedProcess(
        args=raw.args,
        returncode=raw.returncode,
        stdout=raw.stdout.decode("utf-8"),
        stderr=raw.stderr.decode("utf-8"),
    )


def test_cli_sanitize_stdin_output_schema() -> None:
    proc = _run_cli(["sanitize", "--policy", "balanced"], stdin="abc\u202Edef")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["sanitized_text"] == "abcdef"
    assert "report" in payload
    assert "timing_ms" in payload


def test_cli_inspect_outputs_summary() -> None:
    proc = _run_cli(["inspect", "--text", "hello"])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert "summary" in payload
    assert set(payload["summary"]) == {"changed", "removed_total", "flagged_total"}


def test_cli_inspect_compact_output() -> None:
    proc = _run_cli(["inspect", "--compact", "--text", "abc\u202Edef"])
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["changed"] is True
    assert payload["removed"] == {"bidi_control": 1}
    assert payload["flagged"] == {}
    assert "report" not in payload


def test_cli_decide_confusable_quarantines_under_chat_default() -> None:
    # Enforcement strictness is coupled to the sanitize policy: under the chat
    # default, a mixed-script confusable quarantines (exit 2) rather than hard
    # rejecting, since benign multilingual text can legitimately mix scripts.
    proc = _run_cli(["decide", "--text", "раypal"])
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["decision"]["action"] == "quarantine"


def test_cli_decide_confusable_rejects_under_strict_exec() -> None:
    proc = _run_cli(["decide", "--policy", "strict_exec", "--text", "раypal"])
    assert proc.returncode == 3
    payload = json.loads(proc.stdout)
    assert payload["decision"]["action"] == "reject"


def test_cli_decide_compact_keeps_exit_code() -> None:
    proc = _run_cli(["decide", "--compact", "--text", "раypal"])
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["decision"] == "quarantine"
    assert payload["flagged"].get("mixed_script_word", 0) == 1


def test_cli_accepts_code_mode_policy_alias() -> None:
    proc = _run_cli(["sanitize", "--policy", "code"], stdin="x\u200dy")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["sanitized_text"] == "xy"


def test_cli_can_force_tidy_whitespace_off() -> None:
    proc = _run_cli(["sanitize", "--no-tidy-whitespace"], stdin="a  b")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["sanitized_text"] == "a  b"
