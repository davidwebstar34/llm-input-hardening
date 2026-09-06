from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path


def _extension_glob() -> str:
    system = platform.system()
    if system == "Windows":
        return "_core*.pyd"
    if system == "Darwin":
        return "_core*.so"
    return "_core*.so"


def _ensure_core_extension() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pkg_dir = repo_root / "python" / "llm_input_hardening"
    if any(pkg_dir.glob(_extension_glob())):
        return

    subprocess.run(
        [sys.executable, "-m", "maturin", "develop", "--release"],
        cwd=repo_root,
        check=True,
    )


_ensure_core_extension()
