"""Gate discovery corpora on expected detections without requiring support floors."""
from __future__ import annotations

import argparse
from pathlib import Path

if __package__:
    from .artifact_contracts import load_json, validate_result
else:
    from artifact_contracts import load_json, validate_result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", required=True)
    args = parser.parse_args()
    try:
        result = load_json(Path(args.in_path))
        validate_result(result)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    engine = next((entry for entry in result["engines"] if entry["engine"] == "llm-input-hardening"), None)
    if not engine or not engine["available"] or not engine["details"]:
        raise SystemExit("No available llm-input-hardening case results")
    failures = []
    for row in engine["details"]:
        missing = set(row["expected_labels"]) - set(row["detected_labels"])
        if missing or row["postcondition_passed"] is not True:
            failures.append(f"{row['case']}: missing={sorted(missing)}, postconditions={row['postcondition_failures']}")
    if failures:
        raise SystemExit("Case contract failures:\n" + "\n".join(failures))
    if any(summary["decision_mismatches"] for summary in result["enforcement"]["by_policy"].values()):
        raise SystemExit("Unexpected enforcement decisions in mutation evaluation")
    print(f"All {len(engine['details'])} case contracts passed")


if __name__ == "__main__":
    main()
