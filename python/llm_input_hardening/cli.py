from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from ._service import sanitize_text
from .enforcement import sanitize_and_decide
from .policies import cli_policy_choices
from .reporting import compact_report


def _read_text(text_arg: str | None) -> str:
    if text_arg is not None:
        return text_arg
    return sys.stdin.read()


def _print_json(payload: dict[str, Any]) -> None:
    # Keep CLI JSON ASCII-safe so piped output works on non-UTF-8 Windows code pages.
    print(json.dumps(payload, ensure_ascii=True))


def _shared_sanitize_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--text", default=None, help="Input text. If omitted, read stdin.")
    parser.add_argument(
        "--policy",
        default="balanced_chat",
        choices=cli_policy_choices(),
    )
    parser.add_argument("--normalization", default=None, choices=["NFC", "NFKC"])
    tidy = parser.add_mutually_exclusive_group()
    tidy.add_argument(
        "--tidy-whitespace",
        dest="tidy_whitespace",
        action="store_true",
        default=None,
        help="Force whitespace tidying on.",
    )
    tidy.add_argument(
        "--no-tidy-whitespace",
        dest="tidy_whitespace",
        action="store_false",
        help="Force whitespace tidying off.",
    )
    parser.add_argument("--return-spans", action="store_true")
    parser.add_argument(
        "--confusables-backend",
        default=None,
        help="heuristic or confusable_homoglyphs",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-input-hardening")
    sub = parser.add_subparsers(dest="command", required=True)

    sanitize_cmd = sub.add_parser("sanitize", help="Sanitize text.")
    _shared_sanitize_args(sanitize_cmd)

    inspect_cmd = sub.add_parser("inspect", help="Sanitize and print full report.")
    _shared_sanitize_args(inspect_cmd)
    inspect_cmd.add_argument(
        "--compact",
        action="store_true",
        help="Print a compact demo-friendly report instead of the full report.",
    )

    decide_cmd = sub.add_parser("decide", help="Sanitize and return enforcement decision.")
    _shared_sanitize_args(decide_cmd)
    decide_cmd.add_argument(
        "--compact",
        action="store_true",
        help="Print a compact demo-friendly report instead of the full report.",
    )

    return parser


def _sanitize_payload(args: argparse.Namespace) -> dict[str, Any]:
    text = _read_text(args.text)
    start = time.perf_counter()
    clean, report = sanitize_text(
        text,
        policy=args.policy,
        normalization=args.normalization,
        tidy_whitespace=args.tidy_whitespace,
        return_spans=bool(args.return_spans),
        confusables_backend=args.confusables_backend,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "sanitized_text": clean,
        "report": report,
        "timing_ms": round(elapsed_ms, 3),
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sanitize":
        payload = _sanitize_payload(args)
        _print_json(payload)
        return 0

    if args.command == "inspect":
        payload = _sanitize_payload(args)
        if args.compact:
            _print_json(
                compact_report(
                    payload["report"],
                    sanitized_text=payload["sanitized_text"],
                    timing_ms=payload["timing_ms"],
                )
            )
            return 0
        payload["summary"] = {
            "changed": payload["report"].get("changed", False),
            "removed_total": sum(payload["report"].get("removed_counts", {}).values()),
            "flagged_total": sum(payload["report"].get("flagged_counts", {}).values()),
        }
        _print_json(payload)
        return 0

    if args.command == "decide":
        text = _read_text(args.text)
        start = time.perf_counter()
        clean, report, decision = sanitize_and_decide(
            text,
            sanitize_policy=args.policy,
            normalization=args.normalization,
            tidy_whitespace=args.tidy_whitespace,
            return_spans=bool(args.return_spans),
            confusables_backend=args.confusables_backend,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        payload = {
            "sanitized_text": clean,
            "report": report,
            "decision": decision,
            "timing_ms": round(elapsed_ms, 3),
        }
        if args.compact:
            _print_json(
                compact_report(
                    report,
                    sanitized_text=clean,
                    decision=decision,
                    timing_ms=payload["timing_ms"],
                )
            )
            action = decision.get("action")
            if action == "allow":
                return 0
            if action == "quarantine":
                return 2
            return 3
        _print_json(payload)
        action = decision.get("action")
        if action == "allow":
            return 0
        if action == "quarantine":
            return 2
        return 3

    parser.error("unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
