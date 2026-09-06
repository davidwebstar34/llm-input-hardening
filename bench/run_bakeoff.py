from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import math
import os
import platform
import re
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from llm_input_hardening import sanitize  # noqa: E402
from bench.artifact_contracts import (  # noqa: E402
    RESULT_SCHEMA_VERSION, fingerprint, load_json, runtime_provenance, unique_rows,
)


LABELS = [
    "bidi_control",
    "junk_invisible",
    "default_ignorable",
    "tag_char",
    "variation_selector_excess",
    "invalid_variation_selector",
    "control_or_format",
    "line_separator",
    "normalization_amplified",
    "base64ish_blob",
    "hex_blob",
    "encoded_blob",
    "high_entropy",
    "high_combining_ratio",
    "excessive_combining_stack",
    "confusable_mixed_script",
    "whole_script_confusable",
    "confusable_styled",
]

REMOVE_REQUIRED_LABELS = {
    "bidi_control",
    "junk_invisible",
    "default_ignorable",
    "tag_char",
    "variation_selector_excess",
    "control_or_format",
    "line_separator",
}

BIDI_CODEPOINTS = {
    0x061C,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}
JUNK_INVISIBLES = {0x200B, 0x2060, 0xFEFF}
LINE_SEPARATORS = {0x2028, 0x2029}
DEFAULT_IGNORABLE_MONITORED_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    # Full tag blocks and all standardized/ideographic variation selectors.
    (0xE0000, 0xE00FF),
    (0xE0100, 0xE01EF),
)
ALLOWED_CONTROLS = {0x0009, 0x000A, 0x000D}


@dataclass(frozen=True)
class EngineDetection:
    detected_labels: set[str]
    changed: bool
    output_text: str
    score: float


@dataclass(frozen=True)
class Engine:
    name: str
    available: bool
    version: str | None
    detect: Callable[[str, str], EngineDetection]
    error: str | None = None


ENGINE_LABELS: dict[str, frozenset[str]] = {
    "llm-input-hardening": frozenset(LABELS),
    "llm-guard:InvisibleText": frozenset({"bidi_control", "junk_invisible"}),
    "confusable-homoglyphs": frozenset({"confusable_mixed_script"}),
}


@dataclass(frozen=True)
class TokenCounter:
    backend: str
    resolved: str
    count: Callable[[str], int]


def _contains_any_codepoint(text: str, cps: set[int]) -> bool:
    return any(ord(ch) in cps for ch in text)


def _is_default_ignorable_monitored(cp: int) -> bool:
    return any(start <= cp <= end for start, end in DEFAULT_IGNORABLE_MONITORED_RANGES)


def _contains_default_ignorables(text: str) -> bool:
    return any(_is_default_ignorable_monitored(ord(ch)) for ch in text)


def _contains_disallowed_control_or_format(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        category = unicodedata.category(ch)
        if category not in {"Cc", "Cf"}:
            continue
        if cp in ALLOWED_CONTROLS:
            continue
        if cp in {0x200C, 0x200D, 0xFE0E, 0xFE0F}:
            continue
        return True
    return False


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE00FF


def _is_variation_selector(cp: int) -> bool:
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF)


def _contains_tag_char(text: str) -> bool:
    return any(_is_tag_char(ord(ch)) for ch in text)


def _contains_variation_selector_excess(text: str) -> bool:
    # True if any base character carries a run of more than one variation
    # selector — the steganographic shape. A single presentation selector is
    # legitimate and does not count.
    run = 0
    for ch in text:
        if _is_variation_selector(ord(ch)):
            run += 1
            if run > 1:
                return True
        else:
            run = 0
    return False


def _contains_group(text: str, group: str) -> bool:
    if group == "bidi_control":
        return _contains_any_codepoint(text, BIDI_CODEPOINTS)
    if group == "junk_invisible":
        return _contains_any_codepoint(text, JUNK_INVISIBLES)
    if group == "default_ignorable":
        return _contains_default_ignorables(text)
    if group == "tag_char":
        return _contains_tag_char(text)
    if group == "variation_selector_excess":
        return _contains_variation_selector_excess(text)
    if group == "control_or_format":
        return _contains_disallowed_control_or_format(text)
    if group == "line_separator":
        return _contains_any_codepoint(text, LINE_SEPARATORS)
    raise ValueError(f"Unknown codepoint group in postcondition: {group}")


def _token_estimate(text: str) -> int:
    if not text:
        return 0
    chunks = re.findall(r"[A-Za-z0-9]+|[^ \t\r\nA-Za-z0-9]+", text)
    return max(1, int(len(chunks) * 0.9))


def _build_token_counter(*, backend: str, model: str | None) -> TokenCounter:
    if backend == "heuristic":
        return TokenCounter(
            backend="heuristic",
            resolved="heuristic:chunk_estimate",
            count=_token_estimate,
        )
    if backend != "tiktoken":
        raise ValueError(f"Unknown tokenizer backend: {backend}")

    try:
        import tiktoken  # type: ignore
    except Exception as exc:
        raise SystemExit(
            "Tokenizer backend 'tiktoken' requested but tiktoken is not installed. "
            "Install with project optional deps (tokens) or use --tokenizer heuristic."
        ) from exc

    encoding_name = model or "o200k_base"
    if model:
        try:
            enc = tiktoken.encoding_for_model(model)
            resolved = f"tiktoken:model:{model}"
        except Exception:
            enc = tiktoken.get_encoding(model)
            resolved = f"tiktoken:encoding:{model}"
    else:
        enc = tiktoken.get_encoding(encoding_name)
        resolved = f"tiktoken:encoding:{encoding_name}"

    return TokenCounter(
        backend="tiktoken",
        resolved=resolved,
        count=lambda text: len(enc.encode(text)),
    )


def _quantile(vals: list[float], q: float) -> float:
    if not vals:
        return 0.0
    ordered = sorted(vals)
    if len(ordered) == 1:
        return ordered[0]
    if q <= 0:
        return ordered[0]
    if q >= 1:
        return ordered[-1]
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


def _wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total)
    return max(0.0, center - margin), min(1.0, center + margin)


def _git_sha() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
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


def _package_version(name: str) -> str | None:
    try:
        return md.version(name)
    except Exception:
        if name != "llm-input-hardening":
            return None
    try:
        pyproject = Path(ROOT) / "pyproject.toml"
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("version"):
                _, raw = line.split("=", 1)
                return raw.strip().strip('"').strip("'")
    except Exception:
        return None
    return None


def _env_metadata() -> dict[str, Any]:
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": _git_sha(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "os": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "dependencies": {
            "llm-input-hardening": _package_version("llm-input-hardening"),
            "llm-guard": _package_version("llm-guard"),
            "confusable-homoglyphs": _package_version("confusable-homoglyphs"),
        },
        "provenance": runtime_provenance(Path(ROOT)),
    }


def _load_corpus(path: str) -> list[dict[str, Any]]:
    raw = load_json(Path(path))
    if not isinstance(raw, list) or not raw:
        raise ValueError("Corpus must be a nonempty JSON list.")
    cases = [_normalize_case(case) for case in raw]
    unique_rows(cases, key="name", context="corpus cases")
    return cases


def _normalize_case(case: dict[str, Any]) -> dict[str, Any]:
    if "name" not in case or "text" not in case:
        raise ValueError(f"Corpus case must include name/text. Got: {case}")

    labels = [str(label) for label in case.get("labels", [])]
    expected = case.get("expected", {})
    if not expected:
        expected = {
            "must_detect": labels,
            "expected_action": (
                "remove"
                if any(label in REMOVE_REQUIRED_LABELS for label in labels)
                else ("preserve" if not labels else "flag_only")
            ),
            "postconditions": {
                "must_not_contain_codepoints": [
                    label for label in labels if label in REMOVE_REQUIRED_LABELS
                ]
            },
        }

    must_detect = sorted({str(label) for label in expected.get("must_detect", [])})
    for label in must_detect:
        if label not in LABELS:
            raise ValueError(f"Unknown label in must_detect for case {case['name']}: {label}")

    expected_action = str(expected.get("expected_action", "flag_only"))
    if expected_action not in {"remove", "flag_only", "preserve"}:
        raise ValueError(
            f"Invalid expected_action for case {case['name']}: {expected_action}. "
            "Allowed: remove, flag_only, preserve."
        )

    postconditions = expected.get("postconditions", {}) or {}
    not_groups = [str(group) for group in postconditions.get("must_not_contain_codepoints", [])]
    for group in not_groups:
        if group not in {
            "bidi_control",
            "junk_invisible",
            "default_ignorable",
            "tag_char",
            "variation_selector_excess",
            "control_or_format",
            "line_separator",
        }:
            raise ValueError(f"Unknown codepoint group in case {case['name']}: {group}")

    kind = str(case.get("kind", "attack" if (must_detect or case.get("obfuscated", False)) else "benign"))
    if kind not in {"attack", "benign"}:
        raise ValueError(f"Invalid kind for case {case['name']}: {kind}")

    policy = str(case.get("policy", "balanced_chat"))

    return {
        "name": str(case["name"]),
        "text": str(case["text"]),
        "kind": kind,
        "policy": policy,
        "expected": {
            "must_detect": must_detect,
            "expected_action": expected_action,
            "postconditions": {
                "must_not_contain_codepoints": not_groups,
            },
        },
    }


def _evaluate_postconditions(
    *,
    case: dict[str, Any],
    output_text: str,
    changed: bool,
    detected_labels: set[str],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    expected = case["expected"]
    action = str(expected["expected_action"])
    must_detect = set(expected["must_detect"])
    postconditions = expected["postconditions"]
    must_not_contain = list(postconditions.get("must_not_contain_codepoints", []))

    if action == "remove" and not changed:
        reasons.append("expected removal action but output was unchanged")
    if action == "preserve" and changed:
        reasons.append("expected preserve action but output changed")
    if action == "flag_only" and not must_detect.issubset(detected_labels):
        missing = sorted(must_detect - detected_labels)
        reasons.append(f"flag_only case missing expected labels: {missing}")

    for group in must_not_contain:
        if _contains_group(output_text, group):
            reasons.append(f"output still contains forbidden codepoint group: {group}")

    return not reasons, reasons


def _engine_llm_input_hardening(version: str | None) -> Engine:
    def detect(text: str, policy: str) -> EngineDetection:
        clean, rep = sanitize(
            text,
            policy=policy,
            confusables_backend="confusable_homoglyphs",
        )
        merged = {**rep.get("removed_counts", {}), **rep.get("flagged_counts", {})}
        detections = {
            key
            for key, count in merged.items()
            if key in LABELS and int(count) > 0
        }
        score = float(sum(int(merged.get(label, 0)) for label in LABELS))
        return EngineDetection(
            detected_labels=detections,
            changed=(clean != text),
            output_text=clean,
            score=score,
        )

    return Engine(
        name="llm-input-hardening",
        available=True,
        version=version,
        detect=detect,
    )


def _engine_llm_guard_invisible(version: str | None) -> Engine:
    try:
        from llm_guard.input_scanners import InvisibleText
    except Exception as exc:
        return Engine(
            name="llm-guard:InvisibleText",
            available=False,
            version=version,
            detect=lambda text, _policy: EngineDetection(
                detected_labels=set(),
                changed=False,
                output_text=text,
                score=0.0,
            ),
            error=str(exc),
        )

    scanner = InvisibleText()

    def detect(text: str, _policy: str) -> EngineDetection:
        cleaned, _is_valid, _score = scanner.scan(text)
        detections: set[str] = set()
        if cleaned != text and _contains_any_codepoint(text, BIDI_CODEPOINTS):
            detections.add("bidi_control")
        if cleaned != text and _contains_any_codepoint(text, JUNK_INVISIBLES):
            detections.add("junk_invisible")
        return EngineDetection(
            detected_labels=detections,
            changed=(cleaned != text),
            output_text=cleaned,
            score=float(len(detections)),
        )

    return Engine(
        name="llm-guard:InvisibleText",
        available=True,
        version=version,
        detect=detect,
    )


def _engine_confusable_homoglyphs(version: str | None) -> Engine:
    try:
        from confusable_homoglyphs import confusables
    except Exception as exc:
        return Engine(
            name="confusable-homoglyphs",
            available=False,
            version=version,
            detect=lambda text, _policy: EngineDetection(
                detected_labels=set(),
                changed=False,
                output_text=text,
                score=0.0,
            ),
            error=str(exc),
        )

    def detect(text: str, _policy: str) -> EngineDetection:
        detections: set[str] = set()
        if confusables.is_dangerous(text, preferred_aliases=["LATIN"]):
            detections.add("confusable_mixed_script")
        return EngineDetection(
            detected_labels=detections,
            changed=False,
            output_text=text,
            score=float(len(detections)),
        )

    return Engine(
        name="confusable-homoglyphs",
        available=True,
        version=version,
        detect=detect,
    )


def _compute_summary(
    *,
    engine_name: str,
    details: list[dict[str, Any]],
    available: bool,
    error: str | None,
    version: str | None,
) -> dict[str, Any]:
    supported_labels = ENGINE_LABELS[engine_name]
    true_positive = 0
    false_positive = 0
    false_negative = 0
    exact_match = 0
    latencies_ms: list[float] = []
    token_deltas: list[int] = []
    invariance_ratios: list[float] = []

    benign_cases = 0
    benign_changed = 0
    postcondition_total = 0
    postcondition_passed = 0
    invariance_unstable = 0
    large_token_delta_cases = 0

    per_label: dict[str, dict[str, int]] = {
        label: {"positives": 0, "detected": 0, "false_positives": 0, "predicted": 0,
                "supported": label in supported_labels}
        for label in LABELS
    }

    for row in details:
        expected = set(row["expected_labels"]) & supported_labels
        detected = set(row["detected_labels"]) & supported_labels

        if expected == detected:
            exact_match += 1
        latencies_ms.append(float(row.get("duration_ms", 0.0)))
        token_deltas.append(int(row.get("token_delta", 0)))
        invariance_ratios.append(float(row.get("invariance_ratio", 1.0)))

        if row.get("kind") == "benign":
            benign_cases += 1
            if bool(row.get("changed", False)):
                benign_changed += 1

        if row.get("postcondition_applicable", True):
            postcondition_total += 1
            if bool(row.get("postcondition_passed")):
                postcondition_passed += 1

        if bool(row.get("invariance_unstable")):
            invariance_unstable += 1
        if bool(row.get("large_token_delta")):
            large_token_delta_cases += 1

        for label in LABELS:
            if label in expected:
                per_label[label]["positives"] += 1
            if label in detected:
                per_label[label]["predicted"] += 1
            if label in expected and label in detected:
                per_label[label]["detected"] += 1
            if label not in expected and label in detected:
                per_label[label]["false_positives"] += 1

        true_positive += len(expected & detected)
        false_positive += len(detected - expected)
        false_negative += len(expected - detected)

    precision_support = true_positive + false_positive
    recall_support = true_positive + false_negative
    post_support = postcondition_total

    micro_precision = (true_positive / precision_support) if precision_support else 0.0
    micro_recall = (true_positive / recall_support) if recall_support else 0.0
    postcondition_pass_rate = (postcondition_passed / post_support) if post_support else 0.0
    benign_changed_rate = (benign_changed / benign_cases) if benign_cases else 0.0

    precision_ci = _wilson_interval(true_positive, precision_support)
    recall_ci = _wilson_interval(true_positive, recall_support)
    post_ci = _wilson_interval(postcondition_passed, post_support)

    label_recalls: list[float] = []
    label_precisions: list[float] = []
    for label in LABELS:
        stats = per_label[label]
        positives = stats["positives"]
        predicted = stats["predicted"]
        if positives > 0:
            label_recalls.append(stats["detected"] / positives)
        if predicted > 0:
            label_precisions.append(
                (stats["detected"] / predicted) if predicted else 0.0
            )

    summary = {
        "cases": len(details),
        "exact_label_match_cases": exact_match,
        "true_positive_labels": true_positive,
        "false_positive_labels": false_positive,
        "false_negative_labels": false_negative,
        "micro_precision": micro_precision,
        "micro_recall": micro_recall,
        "postcondition_pass_rate": postcondition_pass_rate,
        "benign_changed_rate": benign_changed_rate,
        "macro_recall_excluding_zero_support": (
            sum(label_recalls) / len(label_recalls) if label_recalls else None
        ),
        "macro_precision_excluding_zero_support": (
            sum(label_precisions) / len(label_precisions) if label_precisions else None
        ),
        "micro_precision_ci": {
            "support": precision_support,
            "successes": true_positive,
            "wilson_lo": precision_ci[0],
            "wilson_hi": precision_ci[1],
        },
        "micro_recall_ci": {
            "support": recall_support,
            "successes": true_positive,
            "wilson_lo": recall_ci[0],
            "wilson_hi": recall_ci[1],
        },
        "postcondition_pass_rate_ci": {
            "support": post_support,
            "successes": postcondition_passed,
            "wilson_lo": post_ci[0],
            "wilson_hi": post_ci[1],
        },
        "processing_time_ms_p50": _quantile(latencies_ms, 0.50),
        "processing_time_ms_p95": _quantile(latencies_ms, 0.95),
        "token_delta": {
            "p50": _quantile([float(abs(v)) for v in token_deltas], 0.50),
            "p95": _quantile([float(abs(v)) for v in token_deltas], 0.95),
            "max_abs": max((abs(v) for v in token_deltas), default=0),
            "large_divergence_cases": large_token_delta_cases,
            "large_divergence_rate": (
                large_token_delta_cases / len(details) if details else 0.0
            ),
        },
        "invariance": {
            "ratio_p50": _quantile(invariance_ratios, 0.50),
            "ratio_p95": _quantile(invariance_ratios, 0.95),
            "unstable_cases": invariance_unstable,
            "unstable_rate": (invariance_unstable / len(details)) if details else 0.0,
        },
    }

    return {
        "engine": engine_name,
        "available": available,
        "version": version,
        "error": error,
        "supported_labels": sorted(supported_labels),
        "summary": summary,
        "per_label": per_label,
        "details": details,
    }


def _render_metric(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.2f}"


def _render_markdown(results: dict[str, Any]) -> str:
    lines = [
        "# Bake-off Results",
        "",
        "> Auto-generated by `bench/run_bakeoff.py`. Do not edit manually.",
        "",
        "## Contract Snapshot",
        "",
        f"- Corpus path: `{results['corpus']['path']}`",
        f"- Corpus size: `{results['corpus']['size']}`",
        f"- Attack cases: `{results['corpus']['attack_cases']}`",
        f"- Benign cases: `{results['corpus']['benign_cases']}`",
        f"- Token counter: `{results['tokenizer']['resolved']}`",
        "",
        "## Engine Summary",
        "",
        "Each engine is scored only on its declared adapter capabilities. These aggregate scores cover different labels and must not be ranked against each other; use the common-label comparisons below.",
        "",
        "| Engine | Available | Version | Micro Precision | Micro Recall | Postcondition Pass | Benign Changed | p50 ms | p95 ms |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|",
    ]
    for engine in results["engines"]:
        summary = engine["summary"]
        lines.append(
            "| {engine} | {available} | {version} | {precision} | {recall} | {post} | {benign} | {p50} | {p95} |".format(
                engine=engine["engine"],
                available="yes" if engine["available"] else "no",
                version=engine.get("version") or "N/A",
                precision=_render_metric(summary["micro_precision"] if engine["available"] else None),
                recall=_render_metric(summary["micro_recall"] if engine["available"] else None),
                post=_render_metric(summary["postcondition_pass_rate"] if engine["available"] and summary["postcondition_pass_rate_ci"]["support"] else None),
                benign=f"{summary['benign_changed_rate']:.2%}" if engine["available"] else "N/A",
                p50=_render_metric(summary["processing_time_ms_p50"] if engine["available"] else None),
                p95=_render_metric(summary["processing_time_ms_p95"] if engine["available"] else None),
            )
        )

    lines.extend(
        [
            "",
            "## Confidence Intervals (Wilson, 95%)",
            "",
            "| Engine | Metric | Support | Value | wilson_lo | wilson_hi |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    ci_keys = [
        ("micro_precision", "micro_precision_ci"),
        ("micro_recall", "micro_recall_ci"),
        ("postcondition_pass_rate", "postcondition_pass_rate_ci"),
    ]
    for engine in results["engines"]:
        for metric_name, ci_key in ci_keys:
            ci = engine["summary"][ci_key]
            lines.append(
                "| {engine} | {metric} | {support} | {value:.2f} | {lo} | {hi} |".format(
                    engine=engine["engine"],
                    metric=metric_name,
                    support=ci["support"],
                    value=engine["summary"][metric_name],
                    lo=_render_metric(ci["wilson_lo"]),
                    hi=_render_metric(ci["wilson_hi"]),
                )
            )

    lines.extend(
        [
            "",
            "## Per-label Recall",
            "",
            "_Macro averages exclude labels with zero support._",
            "",
            "| Engine | Label | Support | Detected | Recall |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for engine in results["engines"]:
        for label in LABELS:
            stats = engine["per_label"][label]
            support = int(stats["positives"])
            detected = int(stats["detected"])
            recall = (detected / support) if support and stats["supported"] and engine["available"] else None
            lines.append(
                "| {engine} | {label} | {support} | {detected} | {recall} |".format(
                    engine=engine["engine"],
                    label=label,
                    support=support,
                    detected=detected if stats["supported"] and engine["available"] else "N/A",
                    recall=_render_metric(recall),
                )
            )

    lines.extend(
        [
            "",
            "## Stability Signals",
            "",
            "| Engine | token_delta p95 | large token delta rate | invariance ratio p50 | invariance unstable rate |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for engine in results["engines"]:
        token_delta = engine["summary"]["token_delta"]
        invariance = engine["summary"]["invariance"]
        lines.append(
            "| {engine} | {token_p95:.2f} | {token_rate:.2%} | {inv_p50:.2f} | {inv_rate:.2%} |".format(
                engine=engine["engine"],
                token_p95=token_delta["p95"],
                token_rate=token_delta["large_divergence_rate"],
                inv_p50=invariance["ratio_p50"],
                inv_rate=invariance["unstable_rate"],
            )
        )

    lines.extend(["", "## Common-label Comparisons", "",
                  "Both engines are scored on the same corpus and label subset. N/A means the engine is unavailable.", "",
                  "| Labels | Engine | Precision | Recall |",
                  "|---|---|---:|---:|"])
    for comparison in results["common_label_comparisons"]:
        for name, metrics in comparison["engines"].items():
            lines.append(f"| {', '.join(comparison['labels'])} | {name} | "
                         f"{_render_metric(metrics['precision'])} | {_render_metric(metrics['recall'])} |")
    lines.extend(["", "## Enforcement on Benign Application Text", "",
                  "All rates below include legitimate text with suspicious shapes. Expected quarantine is still counted as benign friction; it is not reported as a detection success.", "",
                  "| Policy | Benign cases | Quarantine | Reject | Unexpected quarantine | Unexpected reject | Decision mismatches |",
                  "|---|---:|---:|---:|---:|---:|---:|"])
    for policy, summary in results["enforcement"]["by_policy"].items():
        lines.append(f"| {policy} | {summary['benign_cases']} | {summary['benign_quarantine_rate']:.1%} | "
                     f"{summary['benign_reject_rate']:.1%} | {summary['unexpected_quarantine_rate']:.1%} | "
                     f"{summary['unexpected_reject_rate']:.1%} | {summary['decision_mismatches']} |")
    return "\n".join(lines) + "\n"


def _common_label_comparisons(engines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compare each adapter to this library on exactly its supported labels."""
    ours = next(engine for engine in engines if engine["engine"] == "llm-input-hardening")
    comparisons = []
    for other in engines:
        if other is ours:
            continue
        labels = set(ours["supported_labels"]) & set(other["supported_labels"])
        metrics = {}
        for engine in (ours, other):
            tp = fp = fn = 0
            for row in engine["details"]:
                expected = set(row["expected_labels"]) & labels
                detected = set(row["detected_labels"]) & labels
                tp += len(expected & detected)
                fp += len(detected - expected)
                fn += len(expected - detected)
            metrics[engine["engine"]] = {
                "precision": tp / (tp + fp) if engine["available"] and tp + fp else None,
                "recall": tp / (tp + fn) if engine["available"] and tp + fn else None,
                "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            }
        comparisons.append({"labels": sorted(labels), "engines": metrics})
    return comparisons


def _corpus_metadata(path: str, corpus: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = sum(1 for case in corpus if case["kind"] == "attack")
    benign = sum(1 for case in corpus if case["kind"] == "benign")
    label_support = {
        label: sum(1 for case in corpus if label in set(case["expected"]["must_detect"]))
        for label in LABELS
    }
    return {
        "path": path,
        "fingerprint": fingerprint(corpus),
        "size": len(corpus),
        "attack_cases": attacks,
        "benign_cases": benign,
        "label_support": label_support,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus",
        default="bench/obfuscation_corpus/cases.json",
        help="Path to corpus JSON",
    )
    parser.add_argument(
        "--enforcement-corpus",
        default="bench/enforcement_corpus.json",
        help="Benign application text with explicit expected decisions per policy.",
    )
    parser.add_argument(
        "--out",
        default="bench/results/bakeoff_latest.json",
        help="Path to output JSON results",
    )
    parser.add_argument(
        "--md-out",
        default=None,
        help="Optional path to write a markdown summary",
    )
    parser.add_argument(
        "--token-delta-threshold",
        type=float,
        default=0.20,
        help="Absolute token delta ratio threshold to mark large divergence",
    )
    parser.add_argument(
        "--invariance-threshold",
        type=float,
        default=0.50,
        help="Minimum score invariance ratio before a case is flagged unstable",
    )
    parser.add_argument(
        "--tokenizer",
        choices=["heuristic", "tiktoken"],
        default="heuristic",
        help="Token counting backend for stability metrics.",
    )
    parser.add_argument(
        "--tokenizer-model",
        default=None,
        help=(
            "Tokenizer model/encoding name for tiktoken backend "
            "(for example: gpt-4o-mini or o200k_base)."
        ),
    )
    args = parser.parse_args()

    corpus = _load_corpus(args.corpus)
    token_counter = _build_token_counter(
        backend=args.tokenizer,
        model=args.tokenizer_model,
    )

    environment = _env_metadata()
    dependency_versions = environment["dependencies"]
    engines = [
        _engine_llm_input_hardening(dependency_versions.get("llm-input-hardening")),
        _engine_llm_guard_invisible(dependency_versions.get("llm-guard")),
        _engine_confusable_homoglyphs(dependency_versions.get("confusable-homoglyphs")),
    ]

    engine_results: list[dict[str, Any]] = []
    for engine in engines:
        details: list[dict[str, Any]] = []
        if not engine.available:
            engine_results.append(
                _compute_summary(
                    engine_name=engine.name,
                    details=details,
                    available=False,
                    error=engine.error,
                    version=engine.version,
                )
            )
            continue

        for case in corpus:
            text = str(case["text"])
            policy = str(case["policy"])
            supported = ENGINE_LABELS[engine.name]
            all_expected = set(case["expected"]["must_detect"])
            expected_labels = sorted(all_expected & supported)

            t0 = time.perf_counter()
            raw_detection = engine.detect(text, policy)
            duration_ms = (time.perf_counter() - t0) * 1000.0

            shadow_text = unicodedata.normalize("NFKC", text)
            shadow_detection = engine.detect(shadow_text, policy)

            raw_tokens = token_counter.count(text)
            shadow_tokens = token_counter.count(shadow_text)
            token_delta = shadow_tokens - raw_tokens
            token_delta_ratio = abs(token_delta) / max(raw_tokens, 1)

            max_score = max(raw_detection.score, shadow_detection.score)
            min_score = min(raw_detection.score, shadow_detection.score)
            invariance_ratio = (min_score + 1.0) / (max_score + 1.0)

            post_ok, post_reasons = _evaluate_postconditions(
                case=case,
                output_text=raw_detection.output_text,
                changed=raw_detection.changed,
                detected_labels=raw_detection.detected_labels,
            )
            post_applicable = all_expected.issubset(supported) and (
                engine.name != "confusable-homoglyphs"
                or case["expected"]["expected_action"] == "flag_only"
            )

            details.append(
                {
                    "case": case["name"],
                    "case_fingerprint": fingerprint(case),
                    "kind": case["kind"],
                    "policy": policy,
                    "expected_labels": expected_labels,
                    "unsupported_expected_labels": sorted(all_expected - supported),
                    "detected_labels": sorted(raw_detection.detected_labels),
                    "expected_action": case["expected"]["expected_action"],
                    "changed": raw_detection.changed,
                    "duration_ms": round(duration_ms, 3),
                    "postcondition_applicable": post_applicable,
                    "postcondition_passed": post_ok if post_applicable else None,
                    "postcondition_failures": post_reasons if post_applicable else [],
                    "token_count_raw": raw_tokens,
                    "token_count_shadow": shadow_tokens,
                    "token_delta": token_delta,
                    "token_delta_ratio": round(token_delta_ratio, 6),
                    "large_token_delta": token_delta_ratio >= args.token_delta_threshold,
                    "invariance_ratio": round(invariance_ratio, 6),
                    "invariance_unstable": invariance_ratio < args.invariance_threshold,
                    "raw_score": raw_detection.score,
                    "shadow_score": shadow_detection.score,
                    "tokenizer_backend": token_counter.backend,
                }
            )

        engine_results.append(
            _compute_summary(
                engine_name=engine.name,
                details=details,
                available=True,
                error=None,
                version=engine.version,
            )
        )

    from bench.enforcement_eval import evaluate_enforcement
    from bench.composition_eval import evaluate_composition

    output = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "labels": LABELS,
        "corpus": _corpus_metadata(args.corpus, corpus),
        "tokenizer": {
            "backend": token_counter.backend,
            "model": args.tokenizer_model,
            "resolved": token_counter.resolved,
        },
        "env": environment,
        "engines": engine_results,
        "common_label_comparisons": _common_label_comparisons(engine_results),
        "enforcement": evaluate_enforcement(Path(args.enforcement_corpus)),
        "composition": evaluate_composition(),
    }

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    print(f"Wrote bake-off JSON: {args.out}")

    if args.md_out:
        md_dir = os.path.dirname(args.md_out)
        if md_dir:
            os.makedirs(md_dir, exist_ok=True)
        markdown = _render_markdown(output)
        with open(args.md_out, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"Wrote bake-off markdown: {args.md_out}")


if __name__ == "__main__":
    main()
