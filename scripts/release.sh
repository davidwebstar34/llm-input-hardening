#!/usr/bin/env bash
# Compatibility entry point. The Python driver owns validation and publication.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --no-project python "$script_dir/release.py" "$@"
