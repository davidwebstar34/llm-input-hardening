from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True)
class PolicyPreset:
    name: str
    normalization: str
    remove_bidi: bool
    remove_junk_invisibles: bool
    remove_other_controls: bool
    remove_default_ignorables: bool
    tidy_whitespace: bool
    flag_default_ignorables: bool
    flag_base64ish: bool
    flag_combining_abuse: bool
    # Added in the v1.3.0 detection-correctness release. Defaulted so the
    # dataclass stays constructible from older registries during migration.
    remove_bidi_marks: bool = False
    flag_bidi_marks: bool = True
    remove_tag_chars: bool = True
    cap_variation_selectors: bool = False


def _registry_path() -> Path:
    return Path(__file__).with_name("policy_registry.json")


@lru_cache(maxsize=1)
def _registry() -> dict[str, object]:
    with _registry_path().open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _presets() -> dict[str, PolicyPreset]:
    raw = _registry().get("presets", {})
    if not isinstance(raw, dict):
        raise ValueError("policy registry presets must be a mapping")

    presets: dict[str, PolicyPreset] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            raise ValueError("policy registry preset entries must be mappings")
        presets[name] = PolicyPreset(name=name, **spec)
    return presets


@lru_cache(maxsize=1)
def _aliases() -> dict[str, str]:
    raw = _registry().get("aliases", {})
    if not isinstance(raw, dict):
        raise ValueError("policy registry aliases must be a mapping")
    return {
        alias: canonical
        for alias, canonical in raw.items()
        if isinstance(alias, str) and isinstance(canonical, str)
    }


@lru_cache(maxsize=1)
def signal_thresholds() -> Mapping[str, float]:
    """Immutable heuristic thresholds shared with Rust via the registry.

    Inspection must not mutate process-wide enforcement or diverge from the
    compiled core. Change the registry and rebuild to change these thresholds.
    """

    raw = _registry().get("signals", {})
    if not isinstance(raw, dict):
        raise ValueError("policy registry signals must be a mapping")
    return MappingProxyType(
        {key: value for key, value in raw.items() if isinstance(value, (int, float))}
    )


def resolve_policy_name(policy: str) -> str:
    key = policy.strip()
    canonical = _aliases().get(key, key)
    if canonical not in _presets():
        allowed = ", ".join(sorted([*list(_presets().keys()), *list(_aliases().keys())]))
        raise ValueError(f"unknown policy: {policy}. Supported policies: {allowed}")
    return canonical


def policy_preset(policy: str) -> PolicyPreset:
    canonical = resolve_policy_name(policy)
    return _presets()[canonical]


def cli_policy_choices() -> list[str]:
    return [*_presets().keys(), *_aliases().keys()]
