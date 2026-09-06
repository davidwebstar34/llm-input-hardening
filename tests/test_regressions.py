from __future__ import annotations

import json
from pathlib import Path

import pytest

from llm_input_hardening import sanitize


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "regressions.json"
CASES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_regression_cases(case: dict[str, object]) -> None:
    kwargs: dict[str, object] = {}
    if "confusables_backend" in case:
        kwargs["confusables_backend"] = case["confusables_backend"]

    clean, rep = sanitize(case["input"], policy=case["policy"], **kwargs)  # type: ignore[arg-type]
    assert clean == case["expected_clean"]

    for key, expected in case.get("removed_counts", {}).items():  # type: ignore[union-attr]
        assert rep["removed_counts"].get(key, 0) == expected

    for key, expected in case.get("flagged_counts", {}).items():  # type: ignore[union-attr]
        assert rep["flagged_counts"].get(key, 0) == expected
