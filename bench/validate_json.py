from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

if __package__:
    from .artifact_contracts import load_json, validate_result
else:
    from artifact_contracts import load_json, validate_result


try:
    from jsonschema import Draft202012Validator
except Exception as exc:  # pragma: no cover - import-time guard
    raise SystemExit(
        "jsonschema is required for bench/validate_json.py. "
        "Run with: uv run --with jsonschema python bench/validate_json.py ..."
    ) from exc


def _load_json(path: Path) -> Any:
    try:
        return load_json(path)
    except FileNotFoundError as exc:
        raise SystemExit(f"Missing file: {path}") from exc
    except Exception as exc:
        raise SystemExit(f"Failed to parse JSON: {path}: {exc}") from exc


def _format_path(path_parts: list[Any]) -> str:
    if not path_parts:
        return "$"
    out = "$"
    for part in path_parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}"
    return out


def _validate_payload(
    *,
    payload_path: Path,
    schema_path: Path,
    errors: list[str],
) -> None:
    schema = _load_json(schema_path)
    payload = _load_json(payload_path)
    validator = Draft202012Validator(schema)
    validation_errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
    if not validation_errors:
        print(f"OK: {payload_path} matches {schema_path}")
        return

    for err in validation_errors:
        where = _format_path(list(err.path))
        errors.append(f"{payload_path} {where}: {err.message}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate bake-off JSON artifacts against schemas.")
    parser.add_argument(
        "--schema-dir",
        default="bench/schema",
        help="Schema directory path.",
    )
    parser.add_argument(
        "--corpus",
        default="bench/obfuscation_corpus/cases.json",
        help="Corpus JSON path.",
    )
    parser.add_argument(
        "--thresholds",
        default="bench/bakeoff_thresholds.json",
        help="Threshold policy JSON path.",
    )
    parser.add_argument(
        "--results",
        default=None,
        help="Optional bake-off results JSON path.",
    )
    parser.add_argument(
        "--strict-results",
        action="store_true",
        help="Require --results and fail if not provided.",
    )
    args = parser.parse_args()

    schema_dir = Path(args.schema_dir)
    corpus_schema = schema_dir / "corpus.schema.json"
    results_schema = schema_dir / "bakeoff_results.schema.json"
    thresholds_schema = schema_dir / "thresholds.schema.json"

    errors: list[str] = []
    _validate_payload(
        payload_path=Path(args.corpus),
        schema_path=corpus_schema,
        errors=errors,
    )
    _validate_payload(
        payload_path=Path(args.thresholds),
        schema_path=thresholds_schema,
        errors=errors,
    )

    if args.results is not None:
        _validate_payload(
            payload_path=Path(args.results),
            schema_path=results_schema,
            errors=errors,
        )
        if not errors:
            try:
                validate_result(_load_json(Path(args.results)))
            except ValueError as exc:
                errors.append(str(exc))
    elif args.strict_results:
        errors.append("--strict-results was set but --results was not provided")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

    print("JSON schema validation passed.")


if __name__ == "__main__":
    main()
