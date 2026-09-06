"""Partition-invariance checks at the complete untrusted-text boundary."""
from __future__ import annotations

from typing import Any

from llm_input_hardening import sanitize_and_decide, sanitize_assembled

from .artifact_contracts import fingerprint

CASES = (
    {"name": "canonical_composition", "text": "e\u0301"},
    {"name": "hangul_composition", "text": "\u1100\u1161"},
    {"name": "hex_run", "text": "ab" * 20 + "cd" * 20, "signal": "hex_blob"},
    {"name": "combining_stack", "text": "x" + "\u0338" * 12, "signal": "excessive_combining_stack"},
    {"name": "selector_adjacency", "text": "a\ufe0f\u200b\U000e0100\u200b\U000e0101"},
    {"name": "bidi_and_encoded_run", "text": "ab" * 20 + "\u202e" + "cd" * 20, "signal": "bidi_control"},
    {"name": "whole_script_spelling", "text": "раураӏ"},
    {"name": "styled_normalization", "text": "ＡＢＣ１２３"},
)
POLICIES = ("preserve", "balanced_chat", "strict_exec", "code_mode")
SEPARATORS = ("", " ", "\u200b")
CHANGE_MODES = (False, True)


def evaluate_composition() -> dict[str, Any]:
    failures = []
    checks = 0
    for case in CASES:
        text = case["text"]
        for policy in POLICIES:
            for offset in range(len(text) + 1):
                for separator in SEPARATORS:
                    for reject_on_change in CHANGE_MODES:
                        parts = (text[:offset], text[offset:])
                        joined = separator.join(parts)
                        options = {"sanitize_policy": policy, "return_spans": True,
                                   "reject_on_change": reject_on_change}
                        direct = sanitize_and_decide(joined, **options)
                        assembled = sanitize_assembled(iter(parts), separator=separator, **options)
                        parts_count = assembled[1]["stats"].pop("assembly_parts")
                        checks += 1
                        expected_signal = case.get("signal") if not separator else None
                        signals = set(direct[1]["flagged_counts"]) | set(direct[1]["removed_counts"])
                        if parts_count != 2 or assembled != direct or (expected_signal and expected_signal not in signals):
                            failures.append({"case": case["name"], "policy": policy,
                                             "offset": offset, "separator": ascii(separator),
                                             "reject_on_change": reject_on_change})
    contract = {"cases": CASES, "policies": POLICIES, "separators": SEPARATORS,
                "reject_on_change": CHANGE_MODES, "return_spans": True,
                "partition": "every Unicode scalar boundary including endpoints"}
    return {"fingerprint": fingerprint(contract), "case_count": len(CASES),
            "checks": checks, "failures": len(failures), "failure_details": failures}
