from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .artifact_contracts import load_json, unique_rows
    from .bakeoff_diff import ALL_METRICS, METRICS_HIGHER_BETTER, METRICS_LOWER_BETTER
else:
    from artifact_contracts import load_json, unique_rows
    from bakeoff_diff import ALL_METRICS, METRICS_HIGHER_BETTER, METRICS_LOWER_BETTER


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = load_json(path)
    except Exception as exc:
        raise SystemExit(f"Failed to load diff JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Diff JSON root must be object: {path}")
    return payload


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("Diff metrics must be finite numbers")
    return float(value)


def validate_diff(payload: dict[str, Any]) -> list[str]:
    if payload.get("comparison_status") != "comparable":
        raise ValueError("Diff has no comparable evidence")
    engines = unique_rows(payload.get("engines"), key="engine", context="diff engines")
    if not engines:
        raise ValueError("Diff has no evaluated engines")
    epsilon = _number(payload.get("regression_epsilon"))
    if epsilon < 0:
        raise ValueError("Diff regression tolerance must be nonnegative")
    failing = []
    for name, engine in engines.items():
        support = engine.get("shared_case_count")
        if isinstance(support, bool) or not isinstance(support, int) or support < 1:
            raise ValueError(f"{name} has no paired case support")
        metrics = engine.get("metrics")
        if not isinstance(metrics, dict) or set(metrics) != set(ALL_METRICS):
            raise ValueError(f"{name} has missing or unexpected metrics")
        regressions = []
        for metric, values in metrics.items():
            baseline, current, delta = (_number(values.get(key)) for key in ("baseline", "current", "delta"))
            if not math.isclose(delta, current - baseline, rel_tol=1e-12, abs_tol=1e-12):
                raise ValueError(f"{name}/{metric} delta disagrees with metric values")
            ci = values.get("bootstrap_ci", {})
            if _number(ci.get("lo")) > _number(ci.get("hi")):
                raise ValueError(f"{name}/{metric} confidence interval is reversed")
            if (metric in METRICS_HIGHER_BETTER and delta < -epsilon) or (metric in METRICS_LOWER_BETTER and delta > epsilon):
                regressions.append(metric)
        if engine.get("regression_detected") is not bool(regressions) or engine.get("regressions") != sorted(regressions):
            raise ValueError(f"{name} regression flag disagrees with its metrics")
        if regressions:
            failing.append(f"{name}: {', '.join(sorted(regressions))}")
    if payload.get("regression_detected") is not bool(failing):
        raise ValueError("Overall regression flag disagrees with engine evidence")
    return failing


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail when bake-off diff report contains regressions."
    )
    parser.add_argument(
        "--allow-no-baseline",
        action="store_true",
        help="Explicitly permit an initial/schema-transition run with no comparison conclusion.",
    )
    parser.add_argument(
        "--in",
        dest="input_path",
        default="bench/results/bakeoff_diff_latest.json",
        help="Bake-off diff JSON path.",
    )
    args = parser.parse_args()

    path = Path(args.input_path)
    if not path.exists():
        raise SystemExit(f"Missing diff JSON: {path}")

    payload = _load(path)
    if payload.get("comparison_status") == "not_comparable":
        if not args.allow_no_baseline or not isinstance(payload.get("reason"), str) or not payload["reason"]:
            raise SystemExit("No comparable baseline; gate cannot pass without explicit --allow-no-baseline")
        print("Bake-off comparison skipped: no comparable baseline; no regression conclusion available.")
        return
    try:
        failing = validate_diff(payload)
    except (ValueError, TypeError, AttributeError) as exc:
        raise SystemExit(f"Malformed diff evidence: {exc}") from exc

    if failing or bool(payload.get("regression_detected", False)):
        print("Bake-off regression gate failed:", file=sys.stderr)
        for item in failing or ["regression_detected=true"]:
            print(f"  - {item}", file=sys.stderr)
        raise SystemExit(1)

    print("Bake-off regression gate passed (no bootstrap metric regressions).")


if __name__ == "__main__":
    main()
