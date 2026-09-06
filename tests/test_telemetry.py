from __future__ import annotations

from llm_input_hardening import sanitize, to_otel_attributes


def test_to_otel_attributes_uses_low_cardinality_fields() -> None:
    _, rep = sanitize("abc\u202Edef", policy="balanced_chat")
    attrs = to_otel_attributes(rep)
    assert attrs["llm_input_hardening.changed"] is True
    assert attrs["llm_input_hardening.removed_total"] == 1
    assert attrs["llm_input_hardening.reason_codes"] == "IH001_BIDI_CONTROL"
    assert attrs["llm_input_hardening.reason.IH001_BIDI_CONTROL"] == 1
