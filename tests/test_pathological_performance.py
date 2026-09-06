from __future__ import annotations

import statistics
import time

from llm_input_hardening import sanitize


def _median_runtime_s(text: str, *, rounds: int = 5) -> float:
    samples: list[float] = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        sanitize(text, policy="balanced_chat")
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def test_pathological_inputs_complete_without_panics() -> None:
    cases = [
        ("combining_storm", ("a\u0338" * 20_000), 2.5),
        ("alternating_bidi_zwsp", ("X\u202E\u200bY" * 15_000), 2.5),
        ("emoji_modifier_storm", ("👨‍👩‍👧‍👦❤️" * 8_000), 2.5),
    ]
    for _name, text, max_s in cases:
        t0 = time.perf_counter()
        clean, _ = sanitize(text, policy="balanced_chat")
        elapsed = time.perf_counter() - t0
        assert elapsed < max_s
        assert isinstance(clean, str)


def test_size_scaling_is_monotonic_and_not_superlinear() -> None:
    sizes = [1024, 8192, 32768, 131072]
    runtimes: list[float] = []
    for n in sizes:
        text = ("SAFE\u202Eevil\u200b " * ((n // 10) + 1))[:n]
        runtimes.append(_median_runtime_s(text))

    # Monotonic trend (allowing small jitter).
    for prev, curr in zip(runtimes, runtimes[1:]):
        assert curr >= prev * 0.6

    # No obvious superlinear blow-up.
    for i in range(1, len(runtimes)):
        size_ratio = sizes[i] / sizes[i - 1]
        time_ratio = runtimes[i] / max(runtimes[i - 1], 1e-9)
        assert time_ratio <= size_ratio * 2.2
