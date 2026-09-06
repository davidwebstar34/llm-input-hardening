from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from llm_input_hardening import sanitize


KEYWORD_PATTERNS = [
    re.compile(r"\badmin\b", re.IGNORECASE),
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\bsecret(s)?\b", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
]


def _classifier_detects(text: str) -> bool:
    return any(pattern.search(text) for pattern in KEYWORD_PATTERNS)


def _load_cases(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Corpus must be a list")
    return raw


def _is_obfuscated_case(case: dict[str, Any]) -> bool:
    """Select labeled text-integrity attacks, rather than a retired schema field."""
    return case.get("kind") == "attack" and bool(
        case.get("expected", {}).get("must_detect", [])
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus",
        default="bench/obfuscation_corpus/cases.json",
        help="Path to corpus JSON",
    )
    parser.add_argument(
        "--policy",
        default="balanced_chat",
        help="Sanitize policy to run before post-classifier pass",
    )
    parser.add_argument(
        "--out",
        default="bench/results/classifier_lift.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    cases = _load_cases(Path(args.corpus))
    if not any(_is_obfuscated_case(case) for case in cases):
        raise SystemExit("No labeled attack cases in corpus; classifier lift cannot be measured.")
    details: list[dict[str, Any]] = []

    before_hits = 0
    after_hits = 0
    obfuscated = 0

    for case in cases:
        text = str(case["text"])
        clean, _ = sanitize(text, policy=args.policy)
        before = _classifier_detects(text)
        after = _classifier_detects(clean)
        if _is_obfuscated_case(case):
            obfuscated += 1
            before_hits += int(before)
            after_hits += int(after)
        details.append(
            {
                "case": case["name"],
                "obfuscated": _is_obfuscated_case(case),
                "before_detected": before,
                "after_detected": after,
            }
        )

    before_rate = (before_hits / obfuscated) if obfuscated else 0.0
    after_rate = (after_hits / obfuscated) if obfuscated else 0.0
    output = {
        "policy": args.policy,
        "obfuscated_cases": obfuscated,
        "before_detection_rate": before_rate,
        "after_detection_rate": after_rate,
        "delta_detection_rate": after_rate - before_rate,
        "details": details,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote classifier lift results: {out_path}")


if __name__ == "__main__":
    main()
