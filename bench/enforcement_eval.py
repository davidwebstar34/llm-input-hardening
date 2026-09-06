"""Measure policy decisions separately from text-shape detection accuracy."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from llm_input_hardening import sanitize_and_decide
from .artifact_contracts import fingerprint, load_json

POLICIES = ("preserve", "balanced_chat", "strict_exec", "code_mode")
ACTIONS = {"allow", "quarantine", "reject"}


def evaluate_enforcement(path: Path) -> dict[str, Any]:
    cases = load_json(path)
    if not isinstance(cases, list) or not cases:
        raise ValueError("Enforcement corpus must be a nonempty list")
    names: set[str] = set()
    rows = []
    for case in cases:
        if case.get("kind") not in {"benign", "attack"}:
            raise ValueError("Enforcement cases need kind='benign' or kind='attack'")
        name = case.get("name")
        expected = case.get("expected_decisions", {})
        if not isinstance(name, str) or not name or name in names:
            raise ValueError(f"Missing or duplicate enforcement case name: {name!r}")
        names.add(name)
        if not isinstance(case.get("text"), str) or set(expected) != set(POLICIES):
            raise ValueError(f"{name}: text and expectations for all four policies are required")
        if any(action not in ACTIONS for action in expected.values()):
            raise ValueError(f"{name}: invalid expected decision")
        for policy in POLICIES:
            clean, report, decision = sanitize_and_decide(case["text"], sanitize_policy=policy)
            rows.append({
                "case": name, "kind": case["kind"], "policy": policy,
                "case_fingerprint": fingerprint({"case": case, "policy": policy}),
                "expected_decision": expected[policy], "decision": decision["action"],
                "matches_expectation": decision["action"] == expected[policy],
                "changed": clean != case["text"],
                "flagged_counts": report["flagged_counts"],
                "removed_counts": report["removed_counts"],
            })
    by_policy = {}
    for policy in POLICIES:
        policy_rows = [row for row in rows if row["policy"] == policy]
        benign = [row for row in policy_rows if row["kind"] == "benign"]
        if not benign:
            raise ValueError(f"No benign support for policy {policy}")
        by_policy[policy] = {
            "cases": len(policy_rows), "benign_cases": len(benign),
            "benign_quarantine_rate": sum(row["decision"] == "quarantine" for row in benign) / len(benign),
            "benign_reject_rate": sum(row["decision"] == "reject" for row in benign) / len(benign),
            "unexpected_quarantine_rate": sum(row["decision"] == "quarantine" and not row["matches_expectation"] for row in benign) / len(benign),
            "unexpected_reject_rate": sum(row["decision"] == "reject" and not row["matches_expectation"] for row in benign) / len(benign),
            "decision_mismatches": sum(not row["matches_expectation"] for row in policy_rows),
        }
    return {"path": str(path), "fingerprint": fingerprint(cases), "by_policy": by_policy, "details": rows}
