from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from bench.cases import default_cases  # noqa: E402
from bench.artifact_contracts import fingerprint, runtime_provenance  # noqa: E402
from pathlib import Path  # noqa: E402

try:
    from llm_input_hardening import sanitize  # type: ignore
except Exception as e:  # pragma: no cover
    raise SystemExit(
        "Failed to import llm_input_hardening.sanitize.\n"
        f"Import error: {e}"
    )


def _git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return None


def _package_version() -> str | None:
    try:
        import importlib.metadata as md
        return md.version("llm-input-hardening")
    except Exception:
        pass
    try:
        with open("pyproject.toml", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("version"):
                    # version = "0.1.0"
                    _, raw = line.split("=", 1)
                    return raw.strip().strip('"').strip("'")
    except Exception:
        return None
    return None


def _cpu_model() -> str | None:
    if sys.platform == "darwin":
        for key in ("machdep.cpu.brand_string", "hw.model"):
            try:
                out = subprocess.check_output(
                    ["sysctl", "-n", key],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
                if out:
                    return out
            except Exception:
                continue
        return None
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        _, val = line.split(":", 1)
                        val = val.strip()
                        if val:
                            return val
        except Exception:
            return None
        return None
    return platform.processor() or None


def run_case(case_text: str, policy: str, *, loops: int) -> list[float]:
    """Return individual call durations, including Python API and timing overhead."""
    samples = []
    for _ in range(loops):
        t0 = time.perf_counter()
        sanitize(case_text, policy=policy)
        samples.append(time.perf_counter() - t0)
    return samples


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Path to write benchmark JSON results")
    ap.add_argument("--repeats", type=int, default=15, help="Number of timing repeats per case")
    ap.add_argument("--warmup", type=int, default=3, help="Number of warmup repeats per case")
    ap.add_argument("--loops", type=int, default=200, help="sanitize() calls per timing repeat")
    args = ap.parse_args()
    if args.loops < 1 or args.repeats < 1 or args.warmup < 0:
        ap.error("loops and repeats must be positive; warmup must be nonnegative")

    cases = [c for c in default_cases() if c.enabled]

    results: dict[str, Any] = {}
    results["units"] = {
        "input_bytes": "bytes",
        "time_total_s": "seconds",
        "time_per_call_s": "seconds_per_call",
        "throughput_mb_s": "mebibytes_per_second",
    }
    env = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python_executable": sys.executable,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "git_sha": _git_sha(),
        "package_version": _package_version(),
        "repeats": args.repeats,
        "warmup": args.warmup,
        "loops": args.loops,
        "latency_sampling": "individual_calls",
        "provenance": runtime_provenance(Path(ROOT)),
    }
    results["env"] = env
    results["cases"] = []

    def quantile(vals_sorted: list[float], q: float) -> float:
        if not vals_sorted:
            raise ValueError("quantile() requires at least one value")
        if q <= 0:
            return vals_sorted[0]
        if q >= 1:
            return vals_sorted[-1]
        if len(vals_sorted) == 1:
            return vals_sorted[0]
        pos = (len(vals_sorted) - 1) * q
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            return vals_sorted[lo]
        frac = pos - lo
        return vals_sorted[lo] + (vals_sorted[hi] - vals_sorted[lo]) * frac

    for case in cases:
        # Warmup
        for _ in range(args.warmup):
            run_case(case.text, case.policy, loops=args.loops)

        times = []
        per_call = []
        for _ in range(args.repeats):
            samples = run_case(case.text, case.policy, loops=args.loops)
            times.append(sum(samples))
            per_call.extend(samples)

        bytes_len = len(case.text.encode("utf-8"))
        per_call_sorted = sorted(per_call)
        p50 = quantile(per_call_sorted, 0.50)
        p95 = quantile(per_call_sorted, 0.95)

        case_result = {
            "name": case.name,
            "case_fingerprint": fingerprint({"name": case.name, "text": case.text, "policy": case.policy}),
            "policy": case.policy,
            "input_bytes": bytes_len,
            "loops": args.loops,
            "repeats": args.repeats,
            "time_total_s": {
                "min": min(times),
                "max": max(times),
                "mean": statistics.fmean(times),
            },
            "time_per_call_s": {
                "min": min(per_call),
                "p50": p50,
                "p95": p95,
                "mean": statistics.fmean(per_call),
                "stdev": statistics.pstdev(per_call) if len(per_call) > 1 else 0.0,
            },
            "throughput_mb_s": {
                # MiB/s per call based on p50
                "p50": (bytes_len / (1024 * 1024)) / p50,
                "at_p95_latency": (bytes_len / (1024 * 1024)) / p95,
            },
        }
        results["cases"].append(case_result)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    print(f"Wrote benchmark results: {args.out}")


if __name__ == "__main__":
    main()
