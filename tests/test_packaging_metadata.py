from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _match(pattern: str, text: str) -> str:
    matched = re.search(pattern, text, flags=re.MULTILINE)
    assert matched is not None
    return matched.group(1)


def test_python_and_rust_versions_match() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    cargo = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    assert _match(r'^version = "([^"]+)"$', pyproject) == _match(r'^version = "([^"]+)"$', cargo)


def test_python_source_layout_points_at_python_directory() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert _match(r'^python-source = "([^"]+)"$', pyproject) == "python"
    assert _match(r'^python-packages = \[(.+)\]$', pyproject) == '"llm_input_hardening"'
    python_packages = sorted(
        path.name
        for path in (REPO_ROOT / "python").iterdir()
        if path.is_dir() and path.name.startswith("llm_input_")
    )
    assert python_packages == ["llm_input_hardening"]
    assert (REPO_ROOT / "python" / "llm_input_hardening" / "__init__.py").exists()


def test_distribution_name_and_console_script_match_release_configuration() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert _match(r'^name = "([^"]+)"$', pyproject) == "llm-input-hardening"
    assert (
        _match(r'^llm-input-hardening = "([^"]+)"$', pyproject)
        == "llm_input_hardening.cli:main"
    )


def test_only_supported_optional_extras_are_exposed() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"^ftfy = ", pyproject, flags=re.MULTILINE) is None
    assert (
        _match(r'^security = \["([^"]+)"\]$', pyproject)
        == "confusable-homoglyphs>=3.3.1"
    )
    assert re.search(r"^tokens = ", pyproject, flags=re.MULTILINE) is None
    assert re.search(r"^web = ", pyproject, flags=re.MULTILINE) is None


def test_policy_registry_contains_public_aliases_and_presets() -> None:
    registry = json.loads(
        (REPO_ROOT / "python" / "llm_input_hardening" / "policy_registry.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(registry["presets"]) == {"preserve", "balanced_chat", "strict_exec", "code_mode"}
    assert registry["aliases"] == {
        "balanced": "balanced_chat",
        "strict": "strict_exec",
        "code": "code_mode",
    }


def test_cargo_package_includes_embedded_policy_registry() -> None:
    assert shutil.which("cargo") is not None
    proc = subprocess.run(
        ["cargo", "package", "--list", "--allow-dirty"],
        cwd=REPO_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    packaged = {Path(name).as_posix() for name in proc.stdout.splitlines()}
    assert "python/llm_input_hardening/policy_registry.json" in packaged
    assert "src/policy.rs" in packaged
    metadata = {
        ".cargo_vcs_info.json",
        "Cargo.lock",
        "Cargo.toml",
        "Cargo.toml.orig",
        "LICENSE",
        "NOTICE",
        "licenses/MIT-pre-v3.txt",
        "licenses/Unicode-3.0.txt",
        "README.md",
        "python/llm_input_hardening/policy_registry.json",
    }
    unexpected = {name for name in packaged - metadata if not name.startswith("src/")}
    assert not unexpected, f"Unexpected files in Cargo package: {sorted(unexpected)}"
