from __future__ import annotations

import subprocess
import sys

import pytest

from llm_input_hardening import sanitize_and_decide
from llm_input_hardening.enforcement import (
    ENFORCEMENT_BY_SANITIZE_POLICY,
    EnforcementPolicy,
    decide_enforcement,
)
from llm_input_hardening.policies import signal_thresholds
from llm_input_hardening.reason_codes import DECISION_REASON_CODES, REASON_CODE_REGISTRY


def test_threshold_inspection_cannot_change_enforcement() -> None:
    text = " ".join(["ab"] * 32)
    before = sanitize_and_decide(text)[2]
    assert before["action"] == "quarantine"
    thresholds = signal_thresholds()
    with pytest.raises(TypeError):
        thresholds["hex_min_bytes"] = 1000
    assert sanitize_and_decide(text)[2] == before


@pytest.mark.parametrize("mapping,key,value", [
    (REASON_CODE_REGISTRY, "bidi_control", "changed"),
    (DECISION_REASON_CODES, "input_transformed", "changed"),
    (ENFORCEMENT_BY_SANITIZE_POLICY, "strict_exec", EnforcementPolicy()),
])
def test_public_configuration_registries_are_immutable(mapping, key, value) -> None:
    with pytest.raises(TypeError):
        mapping[key] = value


def test_custom_policy_snapshots_mutable_collections() -> None:
    reject_flags = {"hex_blob"}
    policy = EnforcementPolicy(reject_flags=reject_flags)
    _, report, _ = sanitize_and_decide("ab" * 40)
    assert decide_enforcement(report, policy=policy)["action"] == "reject"
    reject_flags.clear()
    assert decide_enforcement(report, policy=policy)["action"] == "reject"
    assert policy.reject_flags == frozenset({"hex_blob"})


@pytest.mark.parametrize("value", ["hex_blob", [123]])
def test_custom_policy_rejects_invalid_signal_collections(value) -> None:
    with pytest.raises(TypeError, match="reject_flags"):
        EnforcementPolicy(reject_flags=value)


@pytest.mark.parametrize("value", [[], {}, "false", 1, None])
def test_native_prose_policy_requires_an_immutable_boolean(value) -> None:
    with pytest.raises(TypeError, match="allow_native_whole_script must be a bool"):
        EnforcementPolicy(allow_native_whole_script=value)



def test_long_out_of_order_marks_do_not_enter_quadratic_python_normalization() -> None:
    # Run separately with a hard deadline: this 262K-character sequence fits
    # the public input budget but previously spent tens of seconds in NFC.
    result = subprocess.run(
        [sys.executable, "-c", """
from llm_input_hardening import sanitize_and_decide
text = 'x' + '\\u0315' * 131072 + '\\u0300' * 131072
clean, report, decision = sanitize_and_decide(text)
assert decision['action'] != 'allow'
assert report['flagged_counts']['excessive_combining_stack']
assert isinstance(clean, str)
"""],
        check=True,
        timeout=10,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
