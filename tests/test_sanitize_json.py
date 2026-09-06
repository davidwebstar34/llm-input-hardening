from __future__ import annotations

import pytest
import tracemalloc

from llm_input_hardening import sanitize_json


def test_chat_message_array() -> None:
    payload = [
        {"role": "system", "content": "Be safe"},
        {"role": "user", "content": "abc\u202edef"},
    ]
    clean, rep = sanitize_json(payload, policy="balanced_chat")
    assert clean[1]["content"] == "abcdef"
    assert rep["changed"] is True
    assert rep["removed_counts"].get("bidi_control", 0) == 1


def test_nested_tool_argument_dict() -> None:
    payload = {
        "tool": "run",
        "args": {"path": "a\u200bb", "command": "echo ok"},
    }
    clean, rep = sanitize_json(payload, policy="balanced_chat")
    assert clean["args"]["path"] == "ab"
    assert rep["removed_counts"].get("junk_invisible", 0) == 1


def test_deeply_nested_json() -> None:
    payload = {"a": {"b": {"c": {"d": "x\u202ey"}}}}
    clean, rep = sanitize_json(payload, policy="balanced_chat")
    assert clean["a"]["b"]["c"]["d"] == "xy"
    assert rep["changed"] is True
    assert rep["stats"]["json_max_depth"] == 1000


def test_mixed_list_dict_payload_preserves_non_string_types() -> None:
    payload = {"items": [1, None, True, {"v": "A\u200bB"}, 3.14]}
    clean, rep = sanitize_json(payload, policy="balanced_chat")
    assert clean["items"][0] == 1
    assert clean["items"][1] is None
    assert clean["items"][2] is True
    assert clean["items"][4] == 3.14
    assert clean["items"][3]["v"] == "AB"
    assert rep["stats"]["json_string_leaf_count"] >= 1


def test_max_depth_blocks_deep_json() -> None:
    payload: object = "x\u202ey"
    for _ in range(8):
        payload = [payload]

    with pytest.raises(ValueError, match="max_depth exceeded"):
        sanitize_json(payload, policy="balanced_chat", max_depth=4)


@pytest.mark.parametrize("max_depth", [True, 1.5, "4", None])
def test_max_depth_requires_an_integer(max_depth: object) -> None:
    with pytest.raises(TypeError, match="must be an integer"):
        sanitize_json("x", max_depth=max_depth)  # type: ignore[arg-type]


def test_max_depth_allows_root_string_at_zero() -> None:
    clean, rep = sanitize_json("x\u202ey", policy="balanced_chat", max_depth=0)
    assert clean == "xy"
    assert rep["removed_counts"].get("bidi_control", 0) == 1


def test_sanitize_json_reports_paths_for_string_leaves() -> None:
    payload = {"messages": [{"content": "ok"}, {"content": "abc\u202edef"}]}
    clean, report = sanitize_json(payload, policy="balanced_chat")
    assert clean["messages"][1]["content"] == "abcdef"
    changed = [
        entry for entry in report["stats"]["json_path_reports"] if entry["changed"]
    ]
    assert changed == [
        {
            "path": "messages[1].content",
            "changed": True,
            "removed_counts": {"bidi_control": 1},
            "flagged_counts": {},
        }
    ]


def test_sanitize_json_sanitizes_mapping_keys() -> None:
    payload = {"a\u202eb": "value"}
    clean, report = sanitize_json(payload, policy="strict_exec")
    assert clean == {"ab": "value"}
    assert report["removed_counts"].get("bidi_control", 0) == 1
    assert report["stats"]["json_changed_string_keys"] == 1
    changed = [
        entry for entry in report["stats"]["json_path_reports"] if entry["changed"]
    ]
    assert changed == [
        {
            "path": "['a\\u202eb']<key>",
            "location": "key",
            "changed": True,
            "removed_counts": {"bidi_control": 1},
            "flagged_counts": {},
        }
    ]


def test_sanitize_json_rejects_sanitized_key_collisions() -> None:
    payload = {"ab": 1, "a\u202eb": 2}
    with pytest.raises(ValueError, match=r"key collision at \$"):
        sanitize_json(payload, policy="strict_exec")


def test_sanitize_json_default_depth_guard_does_not_hit_python_recursion() -> None:
    allowed: object = "x"
    for _ in range(900):
        allowed = [allowed]
    clean, _ = sanitize_json(allowed)
    assert isinstance(clean, list)

    blocked: object = "x"
    for _ in range(1100):
        blocked = [blocked]
    with pytest.raises(ValueError, match="max_depth exceeded"):
        sanitize_json(blocked)


def test_json_budget_counts_keys_containers_and_leaves() -> None:
    clean, report = sanitize_json({"a": ["x"]}, max_nodes=4, max_total_chars=2)
    assert clean == {"a": ["x"]}
    assert report["stats"]["json_node_count"] == 4
    assert report["stats"]["json_total_chars"] == 2
    assert report["stats"]["json_output_chars"] == 2
    with pytest.raises(ValueError, match="max_nodes"):
        sanitize_json({"a": ["x"]}, max_nodes=3)


def test_wide_payload_rejected_before_sanitizing_children(monkeypatch) -> None:
    import importlib

    module = importlib.import_module("llm_input_hardening.json_sanitize")

    def unexpected_sanitize(*args, **kwargs):
        pytest.fail("the node budget should reject before traversing children")

    monkeypatch.setattr(module, "sanitize_text", unexpected_sanitize)
    with pytest.raises(ValueError, match="max_nodes"):
        sanitize_json(["x"] * 1000, max_nodes=10)


def test_total_character_budget_counts_input_and_normalized_output() -> None:
    with pytest.raises(ValueError, match="max_total_chars"):
        sanitize_json(["abc", "def"], max_total_chars=5)
    with pytest.raises(ValueError, match="output max_total_chars"):
        sanitize_json("\ufb03", policy="strict_exec", max_total_chars=2)


def test_report_budget_does_not_return_or_mutate_partial_input() -> None:
    original = {"a": "x\u202ey"}
    with pytest.raises(ValueError, match="max_path_reports"):
        sanitize_json(original, max_path_reports=1)
    assert original == {"a": "x\u202ey"}


def test_report_size_budget_bounds_deep_paths() -> None:
    original: object = "value"
    for _ in range(50):
        original = {"long_key_name": original}
    with pytest.raises(ValueError, match="max_report_chars"):
        sanitize_json(original, max_report_chars=5000)


def test_path_reports_keep_requested_spans() -> None:
    _, report = sanitize_json({"a": "x\u202ey"}, return_spans=True)
    leaf = next(
        item for item in report["stats"]["json_path_reports"] if item["path"] == "a"
    )
    assert any(span["reason"] == "bidi_control" for span in leaf["spans"])
    assert report["spans"] == []  # offsets belong to individual JSON strings



@pytest.mark.parametrize(
    "budget", ["max_nodes", "max_total_chars", "max_path_reports", "max_report_chars"]
)
@pytest.mark.parametrize("value", [True, 1.5, -1])
def test_json_budgets_validate_configuration(budget: str, value) -> None:
    with pytest.raises((TypeError, ValueError), match=budget):
        sanitize_json("x", **{budget: value})


def test_shared_subtrees_cannot_expand_past_node_budget() -> None:
    payload: object = "x"
    for _ in range(30):
        payload = [payload, payload]
    with pytest.raises(ValueError, match="max_nodes"):
        sanitize_json(payload, max_nodes=100)


@pytest.mark.parametrize("container", [list, tuple])
def test_deep_wide_traversal_does_not_copy_a_path_for_every_sibling(container) -> None:
    payload = container([None] * 10_000)
    for _ in range(300):
        payload = container([payload])
    already_tracing = tracemalloc.is_tracing()
    tracemalloc.start()
    tracemalloc.reset_peak()
    initial, _ = tracemalloc.get_traced_memory()
    try:
        clean, report = sanitize_json(payload, max_path_reports=0, max_report_chars=0)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not already_tracing:
            tracemalloc.stop()
    assert report["stats"]["json_node_count"] == 10_301
    assert report["stats"]["json_total_chars"] == 0
    # The previous traversal allocated over 28 MiB for this pattern. This generous
    # ceiling allows interpreter variance while detecting depth × width state.
    assert peak - initial < 4 * 1024 * 1024
    for _ in range(300):
        assert isinstance(clean, container)
        clean = clean[0]
    assert isinstance(clean, container)
    assert clean == container([None] * 10_000)


def test_iterative_frames_preserve_mixed_container_order_and_local_paths() -> None:
    payload = {"first": ({"a\u200bb": "x\u202ey"}, []), "second": [1, {"c": "ok"}]}
    clean, report = sanitize_json(payload, return_spans=True)
    assert clean == {"first": ({"ab": "xy"}, []), "second": [1, {"c": "ok"}]}
    assert list(clean) == ["first", "second"]
    changed = [
        entry for entry in report["stats"]["json_path_reports"] if entry["changed"]
    ]
    assert [entry["path"] for entry in changed] == [
        "first[0]['a\\u200bb']<key>",
        "first[0].ab",
    ]
    assert changed[1]["spans"]


@pytest.mark.parametrize("mapping", [False, True])
def test_cycles_still_fail_with_a_bounded_depth_error(mapping) -> None:
    payload = {} if mapping else []
    if mapping:
        payload["self"] = payload
    else:
        payload.append(payload)
    with pytest.raises(ValueError, match="max_depth"):
        sanitize_json(payload, max_depth=20)
