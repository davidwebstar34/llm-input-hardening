from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from json import JSONEncoder
from typing import Any, cast

from ._service import sanitize_text
from .policies import policy_preset, resolve_policy_name
from .reason_codes import reason_code_counts
from .types import SanitizeReport


@dataclass(slots=True)
class _TraversalFrame:
    entries: Iterator[tuple[Any, Any]]
    output: Any
    parent: Any
    slot: Any
    depth: int
    is_tuple: bool = False
    source_keys: dict[Any, Any] | None = None


def _bump_counts(target: dict[str, int], source: Mapping[str, int]) -> None:
    for key, raw_count in source.items():
        count = int(raw_count)
        if count <= 0:
            continue
        target[key] = target.get(key, 0) + count


def _format_path(parts: list[str | int]) -> str:
    if not parts:
        return "$"
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        elif not out and part.isascii() and part.isidentifier():
            out = part
        elif part.isascii() and part.isidentifier():
            out += f".{part}"
        else:
            out += "[" + repr(part) + "]"
    return out


def sanitize_json(
    obj: Any,
    *,
    policy: str = "balanced_chat",
    return_spans: bool = False,
    normalization: str | None = None,
    tidy_whitespace: bool | None = None,
    confusables_backend: str | None = None,
    max_depth: int = 1000,
    max_nodes: int = 100_000,
    max_total_chars: int = 4 * 1024 * 1024,
    max_path_reports: int = 10_000,
    max_report_chars: int = 4 * 1024 * 1024,
) -> tuple[Any, SanitizeReport]:
    """Sanitize all string keys and leaves in a JSON-like payload.

    The object shape is preserved and non-string values are returned unchanged.
    If two mapping keys collapse to the same sanitized key, fail closed with a
    ``ValueError`` rather than silently overwriting either value.

    Resource budgets bound tree nodes (including mapping keys), total input and
    output string characters, and per-string reports. Exceeding any budget raises
    ``ValueError``; a partially sanitized object is never returned. Per-string
    spans, when requested, are attached to the corresponding path report.
    """

    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise TypeError("max_depth must be an integer")
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    for name, value in (
        ("max_nodes", max_nodes),
        ("max_total_chars", max_total_chars),
        ("max_path_reports", max_path_reports),
        ("max_report_chars", max_report_chars),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        if value < 0:
            raise ValueError(f"{name} must be >= 0")

    canonical_policy = resolve_policy_name(policy)
    preset = policy_preset(canonical_policy)

    removed_counts: dict[str, int] = {}
    flagged_counts: dict[str, int] = {}
    path_reports: list[dict[str, Any]] = []
    string_leaf_count = 0
    changed_string_leaves = 0
    string_key_count = 0
    changed_string_keys = 0
    total_chars = 0
    output_chars = 0
    nodes_scheduled = 0
    whole_script_actionable = False
    report_chars = 0
    report_encoder = JSONEncoder(ensure_ascii=True)

    def reserve_nodes(count: int) -> None:
        nonlocal nodes_scheduled
        if nodes_scheduled + count > max_nodes:
            raise ValueError(f"sanitize_json max_nodes exceeded: {max_nodes}")
        nodes_scheduled += count

    def sanitize_string(node: str, *, report_path: str, is_key: bool) -> str:
        nonlocal string_leaf_count, changed_string_leaves
        nonlocal string_key_count, changed_string_keys
        nonlocal total_chars, output_chars, whole_script_actionable
        nonlocal report_chars

        if len(path_reports) >= max_path_reports:
            raise ValueError(
                f"sanitize_json max_path_reports exceeded: {max_path_reports}"
            )
        if total_chars + len(node) > max_total_chars:
            raise ValueError(
                f"sanitize_json max_total_chars exceeded: {max_total_chars}"
            )
        total_chars += len(node)

        if is_key:
            string_key_count += 1
        else:
            string_leaf_count += 1

        clean, rep = sanitize_text(
            node,
            policy=canonical_policy,
            return_spans=return_spans,
            normalization=normalization,
            tidy_whitespace=tidy_whitespace,
            confusables_backend=confusables_backend,
        )
        output_chars += len(clean)
        if output_chars > max_total_chars:
            raise ValueError(
                f"sanitize_json output max_total_chars exceeded: {max_total_chars}"
            )
        if rep.get("flagged_counts", {}).get("whole_script_confusable", 0):
            whole_script_actionable |= (
                rep.get("stats", {}).get("whole_script_confusable_actionable")
                is not False
            )
        if clean != node:
            if is_key:
                changed_string_keys += 1
            else:
                changed_string_leaves += 1
        _bump_counts(removed_counts, rep.get("removed_counts", {}))
        _bump_counts(flagged_counts, rep.get("flagged_counts", {}))
        path_report: dict[str, Any] = {
            "path": report_path,
            "changed": clean != node,
            "removed_counts": {
                key: int(value)
                for key, value in sorted(rep.get("removed_counts", {}).items())
                if int(value) > 0
            },
            "flagged_counts": {
                key: int(value)
                for key, value in sorted(rep.get("flagged_counts", {}).items())
                if int(value) > 0
            },
        }
        if is_key:
            path_report["location"] = "key"
        encoded_samples = rep["stats"].get("encoded_unicode_samples", [])
        if encoded_samples:
            path_report["encoded_unicode_samples"] = encoded_samples
        encoded_limit = rep["stats"].get("encoded_unicode_limit")
        if encoded_limit:
            path_report["encoded_unicode_limit"] = encoded_limit
        if return_spans:
            path_report["spans"] = rep.get("spans", [])
        # Count the serialized report incrementally: deep paths and span details
        # must not bypass the report-count budget or require a second large copy.
        for chunk in report_encoder.iterencode(path_report):
            report_chars += len(chunk)
            if report_chars > max_report_chars:
                raise ValueError(
                    f"sanitize_json max_report_chars exceeded: {max_report_chars}"
                )
        path_reports.append(path_report)
        return clean

    # Each frame retains an iterator, not a job and copied path for every sibling.
    # Traversal state stays proportional to depth even for deep, wide payloads.
    root: list[Any] = [None]
    reserve_nodes(1)
    frames: list[_TraversalFrame] = []
    path: list[str | int] = []
    node, depth, parent, slot = obj, 0, root, 0
    while True:
        if depth > max_depth:
            raise ValueError(f"sanitize_json max_depth exceeded: {max_depth}")

        if isinstance(node, str):
            parent[slot] = sanitize_string(
                node,
                report_path=_format_path(path),
                is_key=False,
            )
        elif isinstance(node, (list, tuple)):
            reserve_nodes(len(node))
            output_list: list[Any] = [None] * len(node)
            parent[slot] = output_list
            frames.append(
                _TraversalFrame(
                    iter(enumerate(node)),
                    output_list,
                    parent,
                    slot,
                    depth,
                    is_tuple=isinstance(node, tuple),
                )
            )
        elif isinstance(node, Mapping):
            reserve_nodes(2 * len(node))
            output_mapping: dict[Any, Any] = {}
            parent[slot] = output_mapping
            frames.append(
                _TraversalFrame(
                    iter(node.items()),
                    output_mapping,
                    parent,
                    slot,
                    depth,
                    source_keys={},
                )
            )
        else:
            parent[slot] = node

        while frames:
            frame = frames[-1]
            try:
                key, child = next(frame.entries)
            except StopIteration:
                frames.pop()
                if frame.is_tuple:
                    frame.parent[frame.slot] = tuple(frame.output)
                continue

            del path[frame.depth :]
            if frame.source_keys is not None:
                original_key = key
                clean_key = original_key
                if isinstance(original_key, str):
                    if total_chars + len(original_key) > max_total_chars:
                        raise ValueError(
                            f"sanitize_json max_total_chars exceeded: {max_total_chars}"
                        )
                    key_path = f"{_format_path([*path, original_key])}<key>"
                    clean_key = sanitize_string(
                        original_key,
                        report_path=key_path,
                        is_key=True,
                    )
                if clean_key in frame.output:
                    raise ValueError(
                        f"sanitize_json key collision at {_format_path(path)}: "
                        f"{frame.source_keys[clean_key]!r} and {original_key!r} both "
                        f"sanitize to {clean_key!r}"
                    )
                frame.source_keys[clean_key] = original_key
                key = clean_key
                path.append(str(key))
            else:
                path.append(key)
            node, depth, parent, slot = child, frame.depth + 1, frame.output, key
            break
        else:
            break

    clean_obj = root[0]

    if normalization is not None:
        norm = normalization
    else:
        norm = preset.normalization

    report: SanitizeReport = {
        "report_version": 1,
        "policy": canonical_policy,
        "normalization": norm,
        "changed": changed_string_leaves > 0 or changed_string_keys > 0,
        "removed_counts": {k: removed_counts[k] for k in sorted(removed_counts)},
        "flagged_counts": {k: flagged_counts[k] for k in sorted(flagged_counts)},
        "reason_codes": reason_code_counts(removed_counts, flagged_counts),
        "spans": [],
        "stats": {
            "json_string_leaf_count": string_leaf_count,
            "json_changed_string_leaves": changed_string_leaves,
            "json_string_key_count": string_key_count,
            "json_changed_string_keys": changed_string_keys,
            "json_max_depth": max_depth,
            "json_node_count": nodes_scheduled,
            "json_total_chars": total_chars,
            "json_output_chars": output_chars,
            "json_path_reports": path_reports,
            "whole_script_confusable_actionable": whole_script_actionable,
        },
    }
    return clean_obj, cast(SanitizeReport, report)
