from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from urllib.error import URLError

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_pypi.py"
SPEC = importlib.util.spec_from_file_location("verify_pypi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
WHEEL = "llm_input_hardening-2.0.0-cp310-abi3-macosx_11_0_arm64.whl"
SDIST = "llm_input_hardening-2.0.0.tar.gz"


@pytest.fixture
def distributions(tmp_path: Path) -> tuple[Path, dict[str, str], dict]:
    expected = {}
    for filename in (WHEEL, SDIST):
        content = filename.encode()
        (tmp_path / filename).write_bytes(content)
        expected[filename] = hashlib.sha256(content).hexdigest()
    payload = {
        "info": {"name": "llm-input-hardening", "version": "2.0.0"},
        "urls": [
            {"filename": filename, "digests": {"sha256": digest}, "yanked": False}
            for filename, digest in expected.items()
        ],
    }
    return tmp_path, expected, payload


def test_matching_release(distributions) -> None:
    dist_dir, expected, payload = distributions
    assert verify.local_digests(dist_dir, "2.0.0") == expected
    verify.verify_payload(payload, "2.0.0", expected)


@pytest.mark.parametrize(
    "field,value", [("name", "another-project"), ("version", "1.3.0")]
)
def test_wrong_release_identity(distributions, field, value) -> None:
    _, expected, payload = distributions
    payload["info"][field] = value
    with pytest.raises(verify.VerificationError, match="does not identify"):
        verify.verify_payload(payload, "2.0.0", expected)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda p: p["urls"].pop(), "file set differs"),
        (lambda p: p["urls"].append(deepcopy(p["urls"][0])), "duplicate PyPI"),
        (lambda p: p["urls"][0].update(filename="unexpected.whl"), "file set differs"),
        (lambda p: p["urls"][0].update(filename="../release.whl"), "contains a path"),
        (
            lambda p: p["urls"][0].update(filename="folder\\release.whl"),
            "contains a path",
        ),
        (lambda p: p["urls"][0].update(yanked=True), "is yanked"),
        (lambda p: p["urls"][0].pop("yanked"), "lacks yanked status"),
        (lambda p: p["urls"][0].update(yanked=0), "lacks yanked status"),
        (lambda p: p["urls"][0].update(digests={"sha256": "0" * 64}), "SHA256 differs"),
        (lambda p: p["urls"][0].update(digests={"sha256": "bad"}), "valid SHA256"),
        (lambda p: p.update(urls=[]), "no distribution files"),
        (lambda p: p.update(urls=[None]), "entry must be an object"),
    ],
)
def test_rejects_incorrect_files(distributions, mutation, message) -> None:
    _, expected, payload = distributions
    mutation(payload)
    with pytest.raises(verify.VerificationError, match=message):
        verify.verify_payload(payload, "2.0.0", expected)


def test_rejects_empty_local_directory(tmp_path: Path) -> None:
    with pytest.raises(verify.VerificationError, match="no wheels"):
        verify.local_digests(tmp_path, "2.0.0")


def test_rejects_duplicate_downloaded_artifacts(distributions) -> None:
    dist_dir, _, _ = distributions
    nested = dist_dir / "another-job"
    nested.mkdir()
    (nested / WHEEL).write_bytes(b"different build")
    with pytest.raises(verify.VerificationError, match="duplicate local"):
        verify.local_digests(dist_dir, "2.0.0")


def test_rejects_wrong_local_version(tmp_path: Path) -> None:
    (tmp_path / "llm_input_hardening-1.3.0.tar.gz").write_bytes(b"old")
    with pytest.raises(verify.VerificationError, match="wrong project/version"):
        verify.local_digests(tmp_path, "2.0.0")


def test_fetch_uses_official_version_endpoint_and_timeout(
    monkeypatch, distributions
) -> None:
    _, _, payload = distributions

    def fake_urlopen(request, *, timeout):
        assert (
            request.full_url == "https://pypi.org/pypi/llm-input-hardening/2.0.0/json"
        )
        assert timeout == 30
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(verify, "urlopen", fake_urlopen)
    assert verify.fetch_release("2.0.0") == payload


@pytest.mark.parametrize(
    "body,message",
    [(b"not json", "valid JSON"), (b"x" * (2 * 1024 * 1024 + 1), "response limit")],
    ids=["invalid-json", "oversized-response"],
)
def test_fetch_rejects_invalid_response(monkeypatch, body, message) -> None:
    monkeypatch.setattr(verify, "urlopen", lambda *a, **kw: io.BytesIO(body))
    with pytest.raises(verify.VerificationError, match=message):
        verify.fetch_release("2.0.0")


def test_retries_propagation_then_succeeds(monkeypatch, distributions, capsys) -> None:
    dist_dir, _, payload = distributions
    responses = iter([URLError("offline"), {**payload, "urls": []}, payload])
    sleeps = []

    def fetch(version):
        assert version == "2.0.0"
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(verify, "fetch_release", fetch)
    monkeypatch.setattr(verify.time, "sleep", sleeps.append)
    assert (
        verify.main(
            ["--version", "2.0.0", "--dist-dir", str(dist_dir), "--attempts", "3"]
        )
        == 0
    )
    assert sleeps == [10, 10]
    assert "2 files" in capsys.readouterr().out


def test_final_error_fails_release(monkeypatch, distributions, capsys) -> None:
    dist_dir, _, payload = distributions
    payload["urls"][0]["digests"]["sha256"] = "0" * 64
    monkeypatch.setattr(verify, "fetch_release", lambda version: payload)
    sleeps = []
    monkeypatch.setattr(verify.time, "sleep", sleeps.append)
    assert (
        verify.main(
            [
                "--version",
                "2.0.0",
                "--dist-dir",
                str(dist_dir),
                "--attempts",
                "2",
                "--delay",
                "0",
            ]
        )
        == 1
    )
    assert sleeps == [0]
    assert "attempt 2/2 failed: PyPI SHA256 differs" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["--version", "../2"],
        ["--version", "02.0.0"],
        ["--attempts", "0"],
        ["--attempts", "13"],
        ["--delay", "-1"],
        ["--delay", "61"],
    ],
)
def test_invalid_cli_arguments_never_fetch(monkeypatch, tmp_path, args) -> None:
    def unexpected_fetch(version):
        pytest.fail("invalid CLI input must not access the network")

    monkeypatch.setattr(verify, "fetch_release", unexpected_fetch)
    with pytest.raises(SystemExit) as exc:
        verify.main(["--version", "2.0.0", "--dist-dir", str(tmp_path), *args])
    assert exc.value.code == 2
