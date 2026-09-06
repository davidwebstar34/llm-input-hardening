# Version 3.0.0 local validation

Checked on 2026-09-06, macOS arm64, Python 3.12, before publication:

- 1,087 Python tests passed, including 119 encoded-Unicode regressions.
- 14 Rust tests passed; Rust formatting, Clippy and Ruff passed.
- The smoke bake-off passed the existing corpus and enforcement gates.
- The Python audit reported no known vulnerabilities across all 67 locked
  versions, including platform-specific, optional and build/development packages.
- Cargo audit reported no vulnerable dependencies across 69 locked crates.
- Wheel and source distribution built with matching 3.0.0 metadata and passed
  `twine check`. Apache, earlier MIT and Unicode notices were included.
- A clean installed wheel, without optional dependencies, passed encoded-risk,
  JSON, version and license checks; ftfy and wcwidth were absent.

Coverage includes HTML markup prefixes, numeric/named entities, omitted
semicolons, leading zeros, Unicode escapes and surrogate pairs, percent-encoded
UTF-8, malformed adjacent bytes, mixed/nested representations, original sample
coordinates, escapes assembled by sanitization, configurable enforcement, and
candidate/depth/evidence budgets. Three 900K-character adversarial inputs also
completed within a subprocess deadline with incomplete inspection quarantined.

This is evidence for the documented finite contract, not a claim that every
encoding, parser sequence or prompt-injection strategy is detectable. GitHub CI
and publication repeat their own checks for the exact release commit.
