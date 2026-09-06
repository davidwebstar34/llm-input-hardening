from __future__ import annotations

import argparse
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from .artifact_contracts import RESULT_SCHEMA_VERSION, load_json, unique_rows, validate_result
else:
    from artifact_contracts import RESULT_SCHEMA_VERSION, load_json, unique_rows, validate_result


METRICS_HIGHER_BETTER = {
    "micro_precision",
    "micro_recall",
    "postcondition_pass_rate",
    "macro_precision_excluding_zero_support",
    "macro_recall_excluding_zero_support",
}
METRICS_LOWER_BETTER = {"benign_changed_rate"}
ALL_METRICS = sorted(METRICS_HIGHER_BETTER | METRICS_LOWER_BETTER)


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if q <= 0:
        return ordered[0]
    if q >= 1:
        return ordered[-1]
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


def _compute_metrics(rows: list[dict[str, Any]], labels: list[str]) -> dict[str, float]:
    tp = 0
    fp = 0
    fn = 0
    benign_cases = 0
    benign_changed = 0
    post_total = 0
    post_pass = 0

    per_label: dict[str, dict[str, int]] = {
        label: {"positives": 0, "predicted": 0, "detected": 0}
        for label in labels
    }

    for row in rows:
        expected = set(row.get("expected_labels", [])) & set(labels)
        detected = set(row.get("detected_labels", [])) & set(labels)
        tp += len(expected & detected)
        fp += len(detected - expected)
        fn += len(expected - detected)

        if row.get("kind") == "benign":
            benign_cases += 1
            if bool(row.get("changed", False)):
                benign_changed += 1

        if row.get("postcondition_applicable", True):
            post_total += 1
            if bool(row.get("postcondition_passed", False)):
                post_pass += 1

        for label in labels:
            if label in expected:
                per_label[label]["positives"] += 1
            if label in detected:
                per_label[label]["predicted"] += 1
            if label in expected and label in detected:
                per_label[label]["detected"] += 1

    micro_precision = tp / (tp + fp) if (tp + fp) else 0.0
    micro_recall = tp / (tp + fn) if (tp + fn) else 0.0
    postcondition_pass_rate = post_pass / post_total if post_total else 0.0
    benign_changed_rate = benign_changed / benign_cases if benign_cases else 0.0

    label_precision_values: list[float] = []
    label_recall_values: list[float] = []
    for label in labels:
        positives = per_label[label]["positives"]
        predicted = per_label[label]["predicted"]
        detected = per_label[label]["detected"]
        if positives > 0:
            label_recall_values.append(detected / positives)
        if predicted > 0:
            label_precision_values.append(detected / predicted)

    return {
        "micro_precision": micro_precision,
        "micro_recall": micro_recall,
        "postcondition_pass_rate": postcondition_pass_rate,
        "benign_changed_rate": benign_changed_rate,
        "macro_precision_excluding_zero_support": (
            sum(label_precision_values) / len(label_precision_values)
            if label_precision_values
            else 0.0
        ),
        "macro_recall_excluding_zero_support": (
            sum(label_recall_values) / len(label_recall_values)
            if label_recall_values
            else 0.0
        ),
    }


def _bootstrap_delta(
    *,
    baseline_by_case: dict[str, dict[str, Any]],
    current_by_case: dict[str, dict[str, Any]],
    labels: list[str],
    samples: int,
    seed: int,
) -> dict[str, tuple[float, float]]:
    names = sorted(set(baseline_by_case) & set(current_by_case))
    if not names:
        return {metric: (0.0, 0.0) for metric in ALL_METRICS}

    rng = random.Random(seed)
    deltas: dict[str, list[float]] = {metric: [] for metric in ALL_METRICS}
    n = len(names)

    for _ in range(samples):
        sampled = [names[rng.randrange(0, n)] for _ in range(n)]
        base_rows = [baseline_by_case[name] for name in sampled]
        cur_rows = [current_by_case[name] for name in sampled]
        base_metrics = _compute_metrics(base_rows, labels)
        cur_metrics = _compute_metrics(cur_rows, labels)
        for metric in ALL_METRICS:
            deltas[metric].append(cur_metrics[metric] - base_metrics[metric])

    return {
        metric: (_quantile(values, 0.025), _quantile(values, 0.975))
        for metric, values in deltas.items()
    }


def _compare_engine(
    *,
    baseline_engine: dict[str, Any],
    current_engine: dict[str, Any],
    labels: list[str],
    bootstrap_samples: int,
    seed: int,
    regression_epsilon: float,
) -> dict[str, Any]:
    base_rows = unique_rows(baseline_engine["details"], key="case", context="baseline cases")
    cur_rows = unique_rows(current_engine["details"], key="case", context="current cases")
    shared_names = sorted(set(base_rows) & set(cur_rows))
    if not shared_names:
        raise ValueError(f"No identical cases to compare for {current_engine['engine']}")
    changed = [name for name in shared_names
               if not base_rows[name].get("case_fingerprint")
               or base_rows[name]["case_fingerprint"] != cur_rows[name].get("case_fingerprint")]
    if changed:
        raise ValueError(f"Case contracts changed under existing names; cannot pair results: {changed}")

    base_shared = [base_rows[name] for name in shared_names]
    cur_shared = [cur_rows[name] for name in shared_names]
    base_metrics = _compute_metrics(base_shared, labels)
    cur_metrics = _compute_metrics(cur_shared, labels)
    ci = _bootstrap_delta(
        baseline_by_case=base_rows,
        current_by_case=cur_rows,
        labels=labels,
        samples=bootstrap_samples,
        seed=seed,
    )

    metrics: dict[str, Any] = {}
    regressions: list[str] = []
    for metric in ALL_METRICS:
        delta = cur_metrics[metric] - base_metrics[metric]
        lo, hi = ci[metric]
        metrics[metric] = {
            "baseline": base_metrics[metric],
            "current": cur_metrics[metric],
            "delta": delta,
            "bootstrap_ci": {"lo": lo, "hi": hi},
        }

        if metric in METRICS_HIGHER_BETTER and delta < -regression_epsilon:
            regressions.append(metric)
        if metric in METRICS_LOWER_BETTER and delta > regression_epsilon:
            regressions.append(metric)

    return {
        "engine": current_engine.get("engine"),
        "shared_case_count": len(shared_names),
        "baseline_only_cases": sorted(set(base_rows) - set(cur_rows)),
        "current_only_cases": sorted(set(cur_rows) - set(base_rows)),
        "metrics": metrics,
        "regressions": sorted(set(regressions)),
        "regression_detected": bool(regressions),
    }


def _render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Bake-off Diff Report",
        "",
        f"- Baseline: `{report['baseline']}`",
        f"- Current: `{report['current']}`",
        f"- Bootstrap samples: `{report['bootstrap_samples']}`",
        f"- Seed: `{report['seed']}`",
        "",
    ]

    for engine in report["engines"]:
        lines.extend(
            [
                f"## {engine['engine']}",
                "",
                f"- Shared cases: `{engine['shared_case_count']}`",
                f"- Regression detected: `{'yes' if engine['regression_detected'] else 'no'}`",
                "",
                "| Metric | Baseline | Current | Delta | Bootstrap CI (95%) |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for metric in ALL_METRICS:
            payload = engine["metrics"][metric]
            ci = payload["bootstrap_ci"]
            lines.append(
                "| {metric} | {base:.4f} | {cur:.4f} | {delta:.4f} | [{lo:.4f}, {hi:.4f}] |".format(
                    metric=metric,
                    base=payload["baseline"],
                    cur=payload["current"],
                    delta=payload["delta"],
                    lo=ci["lo"],
                    hi=ci["hi"],
                )
            )
        if engine["regressions"]:
            lines.extend(
                [
                    "",
                    "Regressed metrics:",
                    *[f"- `{metric}`" for metric in engine["regressions"]],
                ]
            )
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Diff two bake-off runs with bootstrap CIs.")
    parser.add_argument("--baseline", required=True, help="Baseline bake-off JSON path.")
    parser.add_argument("--current", required=True, help="Current bake-off JSON path.")
    parser.add_argument(
        "--out-json",
        default="bench/results/bakeoff_diff_latest.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--out-md",
        default="bench/results/bakeoff_diff_latest.md",
        help="Output markdown path.",
    )
    parser.add_argument(
        "--bootstrap-samples",
        type=int,
        default=2000,
        help="Bootstrap samples per engine.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="PRNG seed for reproducible bootstrap resampling.",
    )
    parser.add_argument(
        "--regression-epsilon",
        type=float,
        default=0.0,
        help="Tolerance margin before marking a metric regression.",
    )
    args = parser.parse_args()
    if args.bootstrap_samples < 1:
        parser.error("--bootstrap-samples must be positive")
    if not math.isfinite(args.regression_epsilon) or args.regression_epsilon < 0:
        parser.error("--regression-epsilon must be finite and nonnegative")

    baseline_path = Path(args.baseline)
    current_path = Path(args.current)
    if not baseline_path.exists():
        raise SystemExit(f"Missing baseline JSON: {baseline_path}")
    if not current_path.exists():
        raise SystemExit(f"Missing current JSON: {current_path}")

    try:
        baseline, current = load_json(baseline_path), load_json(current_path)
        if any(not isinstance(artifact, dict) or artifact.get("schema_version") != RESULT_SCHEMA_VERSION for artifact in (baseline, current)):
            raise ValueError(f"Bakeoff diff requires schema {RESULT_SCHEMA_VERSION}; record a reviewed baseline with case fingerprints")
        validate_result(baseline)
        validate_result(current)
        for evaluation in ("enforcement", "composition"):
            if baseline[evaluation]["fingerprint"] != current[evaluation]["fingerprint"]:
                raise ValueError(f"{evaluation} evaluation contract changed; record a reviewed baseline")
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    labels = list(current.get("labels", baseline.get("labels", [])))
    by_engine_base = unique_rows(baseline["engines"], key="engine", context="baseline engines")
    by_engine_cur = unique_rows(current["engines"], key="engine", context="current engines")
    if set(by_engine_base) != set(by_engine_cur):
        raise SystemExit("Engine sets changed; cannot compare the same evaluation scope")
    shared_engines = []
    skipped_engines = []
    for name in sorted(by_engine_base):
        old, new = by_engine_base[name], by_engine_cur[name]
        if old["available"] != new["available"]:
            raise SystemExit(f"Engine availability changed: {name}; no comparable evidence")
        if set(old["supported_labels"]) != set(new["supported_labels"]):
            raise SystemExit(f"Engine capability scope changed: {name}")
        (shared_engines if new["available"] else skipped_engines).append(name)
    if not shared_engines:
        raise SystemExit("No available engines with comparable evidence")

    try:
        engine_reports = [
            _compare_engine(
                baseline_engine=by_engine_base[name],
                current_engine=by_engine_cur[name],
                labels=by_engine_cur[name].get("supported_labels", labels),
                bootstrap_samples=args.bootstrap_samples,
                seed=args.seed,
                regression_epsilon=args.regression_epsilon,
            )
            for name in shared_engines
        ]
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    report = {
        "comparison_status": "comparable",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline": str(baseline_path),
        "current": str(current_path),
        "bootstrap_samples": int(args.bootstrap_samples),
        "seed": int(args.seed),
        "regression_epsilon": float(args.regression_epsilon),
        "engines": engine_reports,
        "skipped_unavailable_engines": skipped_engines,
        "baseline_provenance": baseline["env"]["provenance"],
        "current_provenance": current["env"]["provenance"],
        "regression_detected": any(e["regression_detected"] for e in engine_reports),
    }

    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote bake-off diff JSON: {out_json}")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(_render_md(report), encoding="utf-8")
    print(f"Wrote bake-off diff markdown: {out_md}")


if __name__ == "__main__":
    main()
