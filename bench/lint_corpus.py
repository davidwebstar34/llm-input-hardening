from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


LABELS = {
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
}
CODEPOINT_GROUPS = {
    "bidi_control",
    "junk_invisible",
    "default_ignorable",
    "tag_char",
    "variation_selector_excess",
    "control_or_format",
    "line_separator",
}
POLICIES = {
    "preserve",
    "balanced_chat",
    "strict_exec",
    "code_mode",
    "balanced",
    "strict",
    "code",
}
EXPECTED_ACTIONS = {"remove", "flag_only", "preserve"}

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
DEFAULT_IGNORABLE_RANGES = (
    (0x200C, 0x200D),
    (0xFE00, 0xFE0F),
    (0xE0000, 0xE00FF),
    (0xE0100, 0xE01EF),
)
ALLOWED_CONTROLS = {0x0009, 0x000A, 0x000D}
ALLOWED_FORMATS = {0x200C, 0x200D, 0xFE0E, 0xFE0F}

BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/]{80,}={0,2}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{64,}$")


def _contains_any_codepoint(text: str, cps: set[int]) -> bool:
    return any(ord(ch) in cps for ch in text)


def _is_default_ignorable(cp: int) -> bool:
    return any(start <= cp <= end for start, end in DEFAULT_IGNORABLE_RANGES)


def _contains_default_ignorables(text: str) -> bool:
    return any(_is_default_ignorable(ord(ch)) for ch in text)


def _contains_disallowed_controls(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        if cp in ALLOWED_CONTROLS:
            continue
        if cp in ALLOWED_FORMATS:
            continue
        cat = unicodedata.category(ch)
        if cat in {"Cc", "Cf"}:
            return True
    return False


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse JSON: {path}: {exc}") from exc


def _lint_case(case: Any, idx: int, names_seen: set[str], errors: list[str], warnings: list[str]) -> None:
    if not isinstance(case, dict):
        errors.append(f"case[{idx}] must be an object")
        return

    name = case.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"case[{idx}] missing non-empty 'name'")
        name = f"<case-{idx}>"
    elif name in names_seen:
        warnings.append(f"duplicate case name: {name}")
    else:
        names_seen.add(name)

    text = case.get("text")
    if not isinstance(text, str):
        errors.append(f"{name}: 'text' must be a string")
        text = ""

    kind = case.get("kind")
    if kind not in {"attack", "benign"}:
        errors.append(f"{name}: 'kind' must be 'attack' or 'benign'")

    policy = case.get("policy")
    if not isinstance(policy, str) or policy not in POLICIES:
        errors.append(f"{name}: invalid 'policy' ({policy!r})")

    expected = case.get("expected")
    if not isinstance(expected, dict):
        errors.append(f"{name}: missing object 'expected'")
        return

    must_detect = expected.get("must_detect")
    if not isinstance(must_detect, list) or any(not isinstance(v, str) for v in must_detect):
        errors.append(f"{name}: expected.must_detect must be a list[str]")
        must_detect = []
    for label in must_detect:
        if label not in LABELS:
            errors.append(f"{name}: unknown label in expected.must_detect: {label}")

    expected_action = expected.get("expected_action")
    if expected_action not in EXPECTED_ACTIONS:
        errors.append(
            f"{name}: expected.expected_action must be one of {sorted(EXPECTED_ACTIONS)}"
        )

    post = expected.get("postconditions")
    if not isinstance(post, dict):
        errors.append(f"{name}: expected.postconditions must be an object")
        post = {}

    must_not = post.get("must_not_contain_codepoints", [])
    if not isinstance(must_not, list) or any(not isinstance(v, str) for v in must_not):
        errors.append(f"{name}: postconditions.must_not_contain_codepoints must be list[str]")
        must_not = []
    for group in must_not:
        if group not in CODEPOINT_GROUPS:
            errors.append(f"{name}: unknown codepoint group in postconditions: {group}")

    if (
        expected_action == "remove"
        and not must_not
        and "normalization_amplified" not in must_detect
    ):
        warnings.append(f"{name}: remove action without must_not_contain_codepoints constraint")

    # Kind describes intent; benign text may legitimately carry observable
    # Unicode or encoding shapes. Decision expectations are evaluated separately.

    # Suspicious accidental payload warnings.
    if kind == "benign":
        if _contains_any_codepoint(text, BIDI_CODEPOINTS):
            warnings.append(f"{name}: benign text contains bidi control characters")
        if _contains_any_codepoint(text, JUNK_INVISIBLES):
            warnings.append(f"{name}: benign text contains junk invisibles")
        if _contains_disallowed_controls(text):
            warnings.append(f"{name}: benign text contains disallowed controls/formats")
        if _contains_any_codepoint(text, LINE_SEPARATORS):
            warnings.append(f"{name}: benign text contains Unicode line/paragraph separators")
        if len(text) > 120 and BASE64ISH_RE.fullmatch(text.strip()):
            warnings.append(f"{name}: benign text looks base64-like; verify case classification")
        if len(text) > 80 and HEX_RE.fullmatch(text.strip()):
            warnings.append(f"{name}: benign text looks hex-like; verify case classification")

    if kind == "attack":
        label_set = set(must_detect)
        stripped = text.strip()
        if len(stripped) > 120 and BASE64ISH_RE.fullmatch(stripped) and "base64ish_blob" not in label_set:
            warnings.append(f"{name}: attack text looks base64-like but lacks base64ish_blob label")
        if len(stripped) > 80 and HEX_RE.fullmatch(stripped) and "hex_blob" not in label_set:
            warnings.append(f"{name}: attack text looks hex-like but lacks hex_blob label")
        if _contains_default_ignorables(text) and "default_ignorable" not in label_set and policy == "strict_exec":
            warnings.append(
                f"{name}: strict_exec attack contains default-ignorables but lacks default_ignorable label"
            )


def _validate_support(
    corpus: list[dict[str, Any]],
    *,
    thresholds: dict[str, Any],
    errors: list[str],
) -> None:
    support = {label: 0 for label in LABELS}
    for case in corpus:
        expected = case.get("expected", {})
        for label in expected.get("must_detect", []):
            if label in support:
                support[label] += 1

    corpus_cfg = thresholds.get("corpus", {})
    min_support = int(corpus_cfg.get("label_min_support", 0))
    if min_support > 0:
        for label, count in sorted(support.items()):
            if count < min_support:
                errors.append(
                    f"label support below threshold: {label}={count} < min_support={min_support}"
                )

    critical = list(corpus_cfg.get("critical_labels", []))
    max_zero = int(corpus_cfg.get("max_zero_support_critical_labels", 0))
    zero_support = [label for label in critical if support.get(label, 0) == 0]
    if len(zero_support) > max_zero:
        errors.append(
            "too many zero-support critical labels: "
            f"{zero_support} (max={max_zero})"
        )

    families = corpus_cfg.get("major_label_families", {})
    if isinstance(families, dict):
        benign_cases = [case for case in corpus if case.get("kind") == "benign"]
        for family_name, cfg in sorted(families.items()):
            if not isinstance(cfg, dict):
                errors.append(f"major_label_families.{family_name} must be an object")
                continue
            min_benign = int(cfg.get("min_benign_counterexamples", 0))
            prefixes = cfg.get("benign_case_name_prefixes", [])
            if min_benign <= 0:
                continue
            if not isinstance(prefixes, list) or not all(isinstance(p, str) for p in prefixes):
                errors.append(
                    f"major_label_families.{family_name}.benign_case_name_prefixes must be list[str]"
                )
                continue
            matched = sum(
                1
                for case in benign_cases
                if any(str(case.get("name", "")).startswith(prefix) for prefix in prefixes)
            )
            if matched < min_benign:
                errors.append(
                    f"major label family benign support below threshold: "
                    f"{family_name}={matched} < min_benign_counterexamples={min_benign}"
                )


def main() -> None:
    parser = argparse.ArgumentParser(description="Lint bake-off corpus schema and support policy.")
    parser.add_argument(
        "--corpus",
        default="bench/obfuscation_corpus/cases.json",
        help="Path to corpus JSON",
    )
    parser.add_argument(
        "--thresholds",
        default="bench/bakeoff_thresholds.json",
        help="Path to threshold policy JSON",
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Fail when warnings are present.",
    )
    args = parser.parse_args()

    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        raise SystemExit(f"Missing corpus file: {corpus_path}")
    threshold_path = Path(args.thresholds)
    if not threshold_path.exists():
        raise SystemExit(f"Missing thresholds file: {threshold_path}")

    raw = _load_json(corpus_path)
    if not isinstance(raw, list):
        raise SystemExit("Corpus must be a JSON list.")
    thresholds = _load_json(threshold_path)
    if not isinstance(thresholds, dict):
        raise SystemExit("Threshold file must be a JSON object.")

    errors: list[str] = []
    warnings: list[str] = []
    names_seen: set[str] = set()
    for idx, case in enumerate(raw):
        _lint_case(case, idx, names_seen, errors, warnings)

    # Only check support if schema-level parsing had no fatal blockers.
    if not errors:
        _validate_support(raw, thresholds=thresholds, errors=errors)

    for item in warnings:
        print(f"WARNING: {item}", file=sys.stderr)
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)

    print(
        f"Linted corpus: cases={len(raw)}, warnings={len(warnings)}, errors={len(errors)}"
    )

    if errors:
        raise SystemExit(1)
    if args.strict_warnings and warnings:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
