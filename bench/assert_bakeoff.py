from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

if __package__:
    from .artifact_contracts import load_json, validate_result, validate_schema
else:
    from artifact_contracts import load_json, validate_result, validate_schema


def _metric_or_fail(summary: dict[str, Any], key: str, engine_name: str) -> float:
    value = summary.get(key)
    if value is None:
        raise SystemExit(f"Missing metric '{key}' in engine summary: {engine_name}")
    return float(value)


def _label_recall(engine: dict[str, Any], label: str) -> float | None:
    stats = engine.get("per_label", {}).get(label)
    if not isinstance(stats, dict):
        return None
    positives = int(stats.get("positives", 0))
    detected = int(stats.get("detected", 0))
    if positives <= 0:
        return None
    return detected / positives


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--in",
        dest="in_path",
        default="bench/results/bakeoff_latest.json",
        help="Bake-off JSON path.",
    )
    parser.add_argument(
        "--thresholds",
        default="bench/bakeoff_thresholds.json",
        help="Threshold configuration JSON path.",
    )
    parser.add_argument(
        "--engine-mode",
        choices=["full", "smoke"],
        default="full",
        help=(
            "Use 'full' for cross-engine comparisons and 'smoke' for a fast local "
            "check that only requires llm-input-hardening."
        ),
    )
    args = parser.parse_args()

    result_path = Path(args.in_path)
    if not result_path.exists():
        raise SystemExit(f"Missing bake-off result: {result_path}")

    threshold_path = Path(args.thresholds)
    if not threshold_path.exists():
        raise SystemExit(f"Missing thresholds file: {threshold_path}")

    try:
        data = load_json(result_path)
        thresholds = load_json(threshold_path)
        validate_result(data)
        validate_schema(thresholds, "thresholds.schema.json")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    enforcement = data.get("enforcement", {}).get("by_policy", {})
    if set(enforcement) != {"preserve", "balanced_chat", "strict_exec", "code_mode"}:
        raise SystemExit("Missing enforcement evaluation for all four policies; rerun the bakeoff")
    for policy, summary in enforcement.items():
        if summary.get("benign_cases", 0) < 1:
            raise SystemExit(f"No benign enforcement support for {policy}")
        if summary.get("decision_mismatches", 0):
            raise SystemExit(f"Unexpected enforcement decisions for {policy}: {summary['decision_mismatches']}")

    by_engine = {e["engine"]: e for e in data.get("engines", [])}

    configured_required_engines = thresholds.get("required_engines", {})
    if args.engine_mode == "smoke":
        required_engines = {
            "llm-input-hardening": configured_required_engines.get(
                "llm-input-hardening",
                {
                    "must_be_available": True,
                    "require_version": True,
                },
            )
        }
    else:
        required_engines = configured_required_engines
    missing = sorted(set(required_engines) - set(by_engine))
    if missing:
        raise SystemExit(f"Missing engines in bake-off result: {missing}")

    for engine_name, req in required_engines.items():
        engine = by_engine[engine_name]
        must_be_available = bool(req.get("must_be_available", False))
        require_version = bool(req.get("require_version", False))

        if must_be_available and not bool(engine.get("available", False)):
            raise SystemExit(
                f"Required engine unavailable: {engine_name}. Error={engine.get('error')!r}"
            )
        if require_version and not engine.get("version"):
            raise SystemExit(f"Required engine version missing: {engine_name}")

    corpus_cfg = thresholds.get("corpus", {})
    label_support = data.get("corpus", {}).get("label_support", {})
    min_support = int(corpus_cfg.get("label_min_support", 0))
    critical_labels = list(corpus_cfg.get("critical_labels", []))
    max_zero_support_critical = int(corpus_cfg.get("max_zero_support_critical_labels", 0))

    if min_support > 0:
        for label, support in label_support.items():
            if int(support) < min_support:
                raise SystemExit(
                    f"Label support below floor: label={label}, support={support}, floor={min_support}"
                )

    zero_support_critical = [label for label in critical_labels if int(label_support.get(label, 0)) == 0]
    if len(zero_support_critical) > max_zero_support_critical:
        raise SystemExit(
            "Too many zero-support critical labels: "
            f"{zero_support_critical} (max={max_zero_support_critical})"
        )

    for engine_name, cfg in thresholds.get("engines", {}).items():
        if engine_name not in by_engine:
            raise SystemExit(f"Thresholds specify unknown engine: {engine_name}")
        engine = by_engine[engine_name]
        summary = engine.get("summary", {})

        if "min_micro_precision" in cfg:
            precision = _metric_or_fail(summary, "micro_precision", engine_name)
            floor = float(cfg["min_micro_precision"])
            if precision < floor:
                raise SystemExit(
                    f"{engine_name} micro_precision below floor: {precision:.4f} < {floor:.4f}"
                )
        if "min_micro_recall" in cfg:
            recall = _metric_or_fail(summary, "micro_recall", engine_name)
            floor = float(cfg["min_micro_recall"])
            if recall < floor:
                raise SystemExit(
                    f"{engine_name} micro_recall below floor: {recall:.4f} < {floor:.4f}"
                )
        if "min_postcondition_pass_rate" in cfg:
            post = _metric_or_fail(summary, "postcondition_pass_rate", engine_name)
            floor = float(cfg["min_postcondition_pass_rate"])
            if post < floor:
                raise SystemExit(
                    f"{engine_name} postcondition_pass_rate below floor: {post:.4f} < {floor:.4f}"
                )
        if "max_benign_changed_rate" in cfg:
            benign = _metric_or_fail(summary, "benign_changed_rate", engine_name)
            ceiling = float(cfg["max_benign_changed_rate"])
            if benign > ceiling:
                raise SystemExit(
                    f"{engine_name} benign_changed_rate above limit: {benign:.4f} > {ceiling:.4f}"
                )

        label_floors = cfg.get("label_min_recall", {})
        for label, floor_value in label_floors.items():
            recall = _label_recall(engine, label)
            if recall is None:
                raise SystemExit(
                    f"{engine_name} label recall unavailable for {label}; support is zero"
                )
            floor = float(floor_value)
            if recall < floor:
                raise SystemExit(
                    f"{engine_name} recall below floor for {label}: {recall:.4f} < {floor:.4f}"
                )

    warnings = []
    warning_cfg = thresholds.get("warnings", {})
    for engine_name, engine in by_engine.items():
        summary = engine.get("summary", {})
        token_delta = summary.get("token_delta", {})
        invariance = summary.get("invariance", {})
        if "max_large_token_delta_rate" in warning_cfg:
            rate = float(token_delta.get("large_divergence_rate", 0.0))
            max_rate = float(warning_cfg["max_large_token_delta_rate"])
            if rate > max_rate:
                warnings.append(
                    f"{engine_name} large token delta rate is high: {rate:.2%} > {max_rate:.2%}"
                )
        if "max_unstable_invariance_rate" in warning_cfg:
            rate = float(invariance.get("unstable_rate", 0.0))
            max_rate = float(warning_cfg["max_unstable_invariance_rate"])
            if rate > max_rate:
                warnings.append(
                    f"{engine_name} invariance unstable rate is high: {rate:.2%} > {max_rate:.2%}"
                )

    for warning in warnings:
        print(f"::warning::{warning}")

    print(
        "Bake-off assertions passed: "
        f"validated {len(required_engines)} required engines and "
        f"{len(thresholds.get('engines', {}))} threshold profiles."
    )


if __name__ == "__main__":
    main()
