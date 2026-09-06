from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

if __package__:
    from .artifact_contracts import load_json, unique_rows
else:
    from artifact_contracts import load_json, unique_rows


def _pct_change(new: float, old: float) -> float:
    if old == 0:
        return float("inf") if new > 0 else 0.0
    return (new - old) / old * 100.0


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two benchmark JSON result files.")
    ap.add_argument("--baseline", required=True, help="Baseline benchmark JSON (older)")
    ap.add_argument("--current", required=True, help="Current benchmark JSON (newer)")
    ap.add_argument("--warn-latency-p95-pct", type=float, default=10.0, help="Warn if p95 latency increases by this percent")
    ap.add_argument("--warn-throughput-p50-pct", type=float, default=10.0, help="Warn if p50 throughput decreases by this percent")
    args = ap.parse_args()

    try:
        base: dict[str, Any] = load_json(Path(args.baseline))
        cur: dict[str, Any] = load_json(Path(args.current))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if base.get("env", {}).get("latency_sampling") != cur.get("env", {}).get("latency_sampling"):
        raise SystemExit("Latency sampling methods differ; record a new baseline on the same hardware")

    base_cases = unique_rows(base.get("cases"), key="name", context="baseline timing cases")
    cur_cases = unique_rows(cur.get("cases"), key="name", context="current timing cases")

    names = sorted(set(base_cases) & set(cur_cases))
    if not names:
        raise SystemExit("No overlapping timing cases to compare")
    for name in names:
        if not base_cases[name].get("case_fingerprint") or base_cases[name]["case_fingerprint"] != cur_cases[name].get("case_fingerprint"):
            raise SystemExit(f"Timing case contract changed or is unidentified: {name}; record a reviewed baseline")

    print("Benchmark comparison (baseline -> current)")
    print()
    print("| case | p95 latency (µs) | Δ% | p50 throughput (MiB/s) | Δ% |")
    print("|---|---:|---:|---:|---:|")

    warnings: list[str] = []

    for name in names:
        b = base_cases[name]
        c = cur_cases[name]

        b_lat_p95 = float(b["time_per_call_s"]["p95"]) * 1e6
        c_lat_p95 = float(c["time_per_call_s"]["p95"]) * 1e6
        lat_delta = _pct_change(c_lat_p95, b_lat_p95)

        b_thr_p50 = float(b["throughput_mb_s"]["p50"])
        c_thr_p50 = float(c["throughput_mb_s"]["p50"])
        if any(not math.isfinite(value) or value <= 0 for value in (b_lat_p95, c_lat_p95, b_thr_p50, c_thr_p50)):
            raise SystemExit(f"Timing case {name} has invalid measurements")
        thr_delta = _pct_change(c_thr_p50, b_thr_p50)

        print(
            f"| {name} | {b_lat_p95:.1f} → {c_lat_p95:.1f} | {lat_delta:+.1f}% | "
            f"{b_thr_p50:.1f} → {c_thr_p50:.1f} | {thr_delta:+.1f}% |"
        )

        if lat_delta >= args.warn_latency_p95_pct:
            warnings.append(f"p95 latency regressed for `{name}`: {lat_delta:+.1f}%")
        if thr_delta <= -args.warn_throughput_p50_pct:
            warnings.append(f"p50 throughput regressed for `{name}`: {thr_delta:+.1f}%")

    if warnings:
        print()
        print("Warnings (non-gating):")
        for w in warnings:
            print("-", w)


if __name__ == "__main__":
    main()
