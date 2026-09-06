from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from llm_input_hardening import sanitize_and_decide


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        print("Usage: python classify_overlap.py <cases.json> [--fail-on-miss]", file=sys.stderr)
        return 2

    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    results = classify_cases(payload["cases"])
    print(render_markdown(results))
    if len(sys.argv) == 3 and sys.argv[2] != "--fail-on-miss":
        print(f"Unknown option: {sys.argv[2]}", file=sys.stderr)
        return 2
    missed = [row for row in results if row["result"] == "missed"]
    return 1 if missed and "--fail-on-miss" in sys.argv else 0


def classify_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        strategy = str(case["strategy"])
        text = _decode_generated_text(str(case["transformed"]))
        clean, report, decision = sanitize_and_decide(text, sanitize_policy=_policy_for(strategy))
        caught, evidence = _is_caught(strategy, clean, report, decision)
        rows.append(
            {
                "strategy": strategy,
                "result": "caught" if caught else "missed",
                "evidence": evidence,
                "decision": decision["action"],
                "removed_counts": report.get("removed_counts", {}),
                "flagged_counts": report.get("flagged_counts", {}),
            }
        )
    return rows


def render_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Promptfoo Static Obfuscation Strategy Overlap",
        "",
        "| Strategy | Result | Evidence |",
        "| --- | --- | --- |",
    ]
    for row in rows:
        lines.append(f"| `{row['strategy']}` | {row['result']} | {row['evidence']} |")
    lines.append("")
    return "\n".join(lines)


def _decode_generated_text(value: str) -> str:
    # The generator ASCII-escapes non-ASCII text for reviewability.
    decoded = value.encode("utf-8").decode("unicode_escape")
    return decoded.encode("utf-16", "surrogatepass").decode("utf-16")


def _policy_for(strategy: str) -> str:
    if strategy in {"emoji", "hex"}:
        return "strict_exec"
    if strategy == "homoglyph":
        return "code_mode"
    return "balanced_chat"


def _is_caught(
    strategy: str,
    clean: str,
    report: dict[str, Any],
    decision: dict[str, Any],
) -> tuple[bool, str]:
    removed = report.get("removed_counts", {})
    flagged = report.get("flagged_counts", {})

    if strategy == "base64":
        count = int(flagged.get("base64ish_blob", 0))
        return count > 0, f"base64ish_blob={count}"

    if strategy == "homoglyph":
        count = int(flagged.get("confusable_mixed_script", 0))
        return count > 0 or decision["action"] != "allow", (
            f"confusable_mixed_script={count}, decision={decision['action']}"
        )

    if strategy == "emoji":
        count = int(removed.get("default_ignorable", 0))
        return count > 0, f"default_ignorable_removed={count}"

    if strategy == "hex":
        count = int(flagged.get("hex_blob", 0))
        return count > 0, f"hex_blob={count}; sanitized_changed={clean != '' and report.get('changed')}"

    return False, "no configured overlap check"


if __name__ == "__main__":
    raise SystemExit(main())
