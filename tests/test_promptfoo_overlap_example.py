from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_promptfoo_overlap_fixture_catches_static_obfuscation_cases() -> None:
    fixture = PROJECT_ROOT / "examples" / "promptfoo-redteam-overlap" / "cases.smoke.json"
    script = PROJECT_ROOT / "examples" / "promptfoo-redteam-overlap" / "classify_overlap.py"

    proc = subprocess.run(
        [sys.executable, "-X", "utf8", str(script), str(fixture), "--fail-on-miss"],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONUTF8": "1"},
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "| `base64` | caught |" in proc.stdout
    assert "| `hex` | caught |" in proc.stdout
    assert "| `homoglyph` | caught |" in proc.stdout
    assert "| `emoji` | caught |" in proc.stdout
