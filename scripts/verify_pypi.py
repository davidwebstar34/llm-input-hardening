"""Verify that a PyPI release contains exactly the distributions built by CI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


PROJECT = "llm-input-hardening"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class VerificationError(ValueError):
    """Published release metadata does not match the local distributions."""


def release_version(value: str) -> str:
    if (
        re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value)
        is None
    ):
        raise argparse.ArgumentTypeError(
            "version must be a stable version such as 2.0.0"
        )
    return value


def local_digests(dist_dir: Path, version: str) -> dict[str, str]:
    """Hash distribution files, rejecting ambiguous artifact downloads."""
    if not dist_dir.is_dir():
        raise VerificationError(f"distribution directory does not exist: {dist_dir}")
    digests: dict[str, str] = {}
    for path in sorted(dist_dir.rglob("*")):
        if not path.name.endswith((".whl", ".tar.gz")):
            continue
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"distribution must be a regular file: {path}")
        if path.name in digests:
            raise VerificationError(
                f"duplicate local distribution filename: {path.name}"
            )
        prefix = f"llm_input_hardening-{version}"
        if not (
            (path.name.startswith(prefix + "-") and path.name.endswith(".whl"))
            or path.name in {prefix + ".tar.gz", f"{PROJECT}-{version}.tar.gz"}
        ):
            raise VerificationError(
                f"distribution filename has the wrong project/version: {path.name}"
            )
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digests[path.name] = digest.hexdigest()
    if not digests:
        raise VerificationError(
            f"no wheels or source distributions found in {dist_dir}"
        )
    return digests


def verify_payload(payload: object, version: str, expected: dict[str, str]) -> None:
    if not expected:
        raise VerificationError("local distribution set is empty")
    if not isinstance(payload, dict):
        raise VerificationError("PyPI response must be a JSON object")
    info = payload.get("info")
    if (
        not isinstance(info, dict)
        or info.get("name") != PROJECT
        or info.get("version") != version
    ):
        raise VerificationError(f"PyPI metadata does not identify {PROJECT}=={version}")
    files = payload.get("urls")
    if not isinstance(files, list) or not files:
        raise VerificationError("PyPI release has no distribution files")
    published: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            raise VerificationError("PyPI distribution entry must be an object")
        filename = item.get("filename")
        if (
            not isinstance(filename, str)
            or not filename
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
        ):
            raise VerificationError(
                "PyPI distribution filename is missing or contains a path"
            )
        if filename in published:
            raise VerificationError(f"duplicate PyPI distribution filename: {filename}")
        if item.get("yanked") is not False:
            raise VerificationError(
                f"PyPI distribution is yanked or lacks yanked status: {filename}"
            )
        digests = item.get("digests")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise VerificationError(
                f"PyPI distribution lacks a valid SHA256 digest: {filename}"
            )
        published[filename] = sha256
    missing = sorted(expected.keys() - published.keys())
    unexpected = sorted(published.keys() - expected.keys())
    if missing or unexpected:
        raise VerificationError(
            f"PyPI file set differs: missing={missing}, unexpected={unexpected}"
        )
    for filename, digest in expected.items():
        if published[filename] != digest:
            raise VerificationError(
                f"PyPI SHA256 differs from the local build: {filename}"
            )


def fetch_release(version: str) -> object:
    request = Request(
        f"https://pypi.org/pypi/{PROJECT}/{version}/json",
        headers={
            "Accept": "application/json",
            "User-Agent": f"{PROJECT}-release-verification",
        },
    )
    with urlopen(request, timeout=30) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise VerificationError("PyPI metadata exceeds the 2 MiB response limit")
    try:
        return json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("PyPI response is not valid JSON") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=release_version, required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument(
        "--attempts", type=int, default=6, help="attempts, from 1 to 12 (default: 6)"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=10,
        help="retry delay, 0 to 60 seconds (default: 10)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.attempts <= 12:
        parser.error("--attempts must be between 1 and 12")
    if not 0 <= args.delay <= 60:
        parser.error("--delay must be between 0 and 60 seconds")
    try:
        expected = local_digests(args.dist_dir, args.version)
    except (VerificationError, OSError) as exc:
        print(f"PyPI verification failed: {exc}", file=sys.stderr)
        return 1
    for attempt in range(1, args.attempts + 1):
        try:
            verify_payload(fetch_release(args.version), args.version, expected)
        except (VerificationError, URLError, OSError) as exc:
            print(
                f"PyPI verification attempt {attempt}/{args.attempts} failed: {exc}",
                file=sys.stderr,
            )
            if attempt == args.attempts:
                return 1
            time.sleep(args.delay)
        else:
            print(
                f"Verified {PROJECT}=={args.version}: {len(expected)} files and SHA256 digests match PyPI."
            )
            return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
