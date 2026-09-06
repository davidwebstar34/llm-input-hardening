from __future__ import annotations

import argparse
import base64
import json
import re
import statistics
import subprocess
import sys
import time
import tracemalloc
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from llm_input_hardening import sanitize


@dataclass(frozen=True)
class BenchCase:
    name: str
    text: str
    policy: str = "balanced_chat"


CASES = [
    BenchCase(
        name="short_ascii",
        text="Please summarize this request in three bullets.",
    ),
    BenchCase(
        name="multilingual_benign",
        text="\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645 \u0627\u06cc\u0646 \u067e\u06cc\u0627\u0645 \u0631\u0627 \u062e\u0644\u0627\u0635\u0647 \u06a9\u0646\u0645. \u05e9\u05dc\u05d5\u05dd \u05e2\u05d5\u05dc\u05dd. Bonjour le monde.",
    ),
    BenchCase(
        name="unicode_attackish",
        text=(
            "USER:\n```json\n{\"a\":1}\n```\u202E "
            "token=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
        ),
    ),
]

_MEAN_RE = re.compile(r"Mean \+\- std dev: ([0-9]+(?:\.[0-9]+)?)\s*(ns|us|ms|sec|s)")


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
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


def _latency_samples(case: BenchCase, iterations: int) -> list[float]:
    samples_ms: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        sanitize(case.text, policy=case.policy)
        samples_ms.append((time.perf_counter() - t0) * 1000.0)
    return samples_ms


def _peak_memory_bytes(case: BenchCase) -> int:
    tracemalloc.start()
    sanitize(case.text, policy=case.policy)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return int(peak)


def _unit_to_seconds(value: float, unit: str) -> float:
    if unit == "ns":
        return value / 1_000_000_000.0
    if unit == "us":
        return value / 1_000_000.0
    if unit == "ms":
        return value / 1_000.0
    return value


def _parse_mean_seconds(output: str) -> float | None:
    match = _MEAN_RE.search(output)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2)
    return _unit_to_seconds(value, unit)


def _compact_error(output: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:300]
    return "pyperf invocation failed"


def _run_pyperf_timeit(
    case: BenchCase,
    *,
    out_dir: Path,
    values: int,
    warmups: int,
    loops: int,
    min_time: float,
) -> tuple[float | None, Path, str | None]:
    payload = base64.b64encode(case.text.encode("utf-8")).decode("ascii")
    case_out = out_dir / f"{case.name}.pyperf.json"
    setup = (
        "import base64;"
        "from llm_input_hardening import sanitize;"
        f"text=base64.b64decode('{payload}').decode('utf-8')"
    )
    stmt = f"sanitize(text, policy='{case.policy}')"
    cmd = [
        sys.executable,
        "-m",
        "pyperf",
        "timeit",
        "--processes",
        "1",
        "--values",
        str(values),
        "--warmups",
        str(warmups),
        "--loops",
        str(loops),
        "--min-time",
        str(min_time),
        "--output",
        str(case_out),
        "-s",
        setup,
        stmt,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return None, case_out, _compact_error(combined)

    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    mean_seconds = _parse_mean_seconds(combined)
    return mean_seconds, case_out, None


def main() -> None:
    parser = argparse.ArgumentParser(description="pyperf microbench for sanitize().")
    parser.add_argument(
        "--out",
        default="bench/results/microbench_latest.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=400,
        help="Manual latency sample count per case.",
    )
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Track peak memory via tracemalloc (optional).",
    )
    parser.add_argument(
        "--pyperf-values",
        type=int,
        default=8,
        help="pyperf values per benchmark run.",
    )
    parser.add_argument(
        "--pyperf-warmups",
        type=int,
        default=2,
        help="pyperf warmup rounds.",
    )
    parser.add_argument(
        "--pyperf-loops",
        type=int,
        default=64,
        help="Fixed loop count passed to pyperf timeit.",
    )
    parser.add_argument(
        "--pyperf-min-time",
        type=float,
        default=0.05,
        help="Minimum run time passed to pyperf timeit.",
    )
    args = parser.parse_args()

    # Fail early with a clear message if pyperf is not installed.
    pyperf_check = subprocess.run(
        [sys.executable, "-m", "pyperf", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if pyperf_check.returncode != 0:
        raise SystemExit(
            "pyperf is required for microbenchmarks. "
            "Run with: uv run --with pyperf python bench/run_microbench.py ..."
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pyperf_dir = out_path.parent / "microbench_pyperf"
    pyperf_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for case in CASES:
        latencies_ms = _latency_samples(case, max(20, int(args.iterations)))
        manual_mean_seconds = statistics.fmean(latencies_ms) / 1000.0

        pyperf_mean_seconds, pyperf_file, pyperf_error = _run_pyperf_timeit(
            case,
            out_dir=pyperf_dir,
            values=max(1, int(args.pyperf_values)),
            warmups=max(0, int(args.pyperf_warmups)),
            loops=max(1, int(args.pyperf_loops)),
            min_time=max(0.001, float(args.pyperf_min_time)),
        )

        mean_seconds = (
            float(pyperf_mean_seconds)
            if pyperf_mean_seconds is not None
            else float(manual_mean_seconds)
        )
        chars = len(case.text)
        throughput = chars / mean_seconds if mean_seconds > 0 else 0.0

        payload: dict[str, Any] = {
            "name": case.name,
            "policy": case.policy,
            "chars": chars,
            "pyperf_mean_seconds": pyperf_mean_seconds,
            "manual_mean_seconds": manual_mean_seconds,
            "throughput_chars_per_sec": throughput,
            "latency_ms_p50": _quantile(latencies_ms, 0.50),
            "latency_ms_p95": _quantile(latencies_ms, 0.95),
            "latency_ms_mean": statistics.fmean(latencies_ms),
            "pyperf_result": str(pyperf_file),
        }
        if pyperf_error is not None:
            payload["pyperf_error"] = pyperf_error
        if args.memory:
            payload["peak_memory_bytes"] = _peak_memory_bytes(case)
        results.append(payload)

    out: dict[str, Any] = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cases": results,
        "summary": {
            "sanitize_throughput_chars_per_sec": statistics.fmean(
                [float(case["throughput_chars_per_sec"]) for case in results]
            ),
            "latency_ms_p50": _quantile(
                [float(case["latency_ms_p50"]) for case in results], 0.50
            ),
            "latency_ms_p95": _quantile(
                [float(case["latency_ms_p95"]) for case in results], 0.95
            ),
        },
    }
    if args.memory:
        out["summary"]["peak_memory_bytes_max"] = max(
            int(case.get("peak_memory_bytes", 0)) for case in results
        )

    out_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote microbench JSON: {out_path}")


if __name__ == "__main__":
    main()
