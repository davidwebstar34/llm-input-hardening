# Bake-off Governance

This page defines corpus lifecycle and release governance for bake-off integrity.

## Corpus versioning rules

Corpus versioning is semantic:

- `MAJOR`: breaking schema/contract changes.
- `MINOR`: new labels, new required postconditions, or threshold policy changes.
- `PATCH`: additive cases that do not change schema or gate semantics.

Record the corpus version in bake-off change notes and PR descriptions.

## Minimum support policy

- Support floor per critical label is enforced by `bench/bakeoff_thresholds.json`.
- CI and corpus lint must fail when critical support falls below policy.
- Zero-support critical labels are disallowed.

## Corpus review checklist

- New adversarial cases include benign counterexamples where relevant.
- Cases define explicit `expected.must_detect` and `expected_action`.
- Removal cases define `must_not_contain_codepoints` postconditions.
- Case names are unique and stable.
- Added cases include rationale in docs when behavior expectations change.

## Artifact naming and retention policy

## CI artifacts

- `llm-input-hardening-bakeoff`
  - contents:
    - `bench/results/bakeoff_latest.json`
    - `docs/bakeoff/results.md`
  - retention: 30 days

## Nightly artifacts

- `llm-input-hardening-nightly-latest`
  - most recent nightly bake-off payload for diffing.
- `llm-input-hardening-nightly-<run_id>`
  - immutable per-run snapshot.
- retention: 30 days
- workflow: `.github/workflows/nightly-bakeoff.yml`
- optional regression issue creation is configurable via workflow-dispatch input.

## Why store artifacts

- Auditability of gate decisions.
- Trend inspection without rerunning historical environments.
- Fast regression triage for nightly drift.

## Threshold justification baseline

Thresholds are justified against the recorded baseline artifact:

- `bench/results/bakeoff_baseline_v1.0.0.json`
- Hashes and baseline lock are recorded in [release notes v1.0.0](releases/v1.0.0.md).

When thresholds change, refresh and record a new baseline file with rationale.

Schema 3 adds explicit adapter capabilities and separate enforcement evaluation.
Its metrics cannot be diffed against the archived schema-2 artifact. Establish
`bench/results/bakeoff_baseline_schema4.json` from a reviewed full run as described
in [Benchmarks](../benchmarks.md); the Make target accepts `BAKEOFF_BASELINE` for
alternate baselines. Nightly runs preserve the first schema-4 result as the next
comparison baseline and explicitly mark the transition as not comparable.

## Bake-off v1.0 release gate

Before tagging `bakeoff-v1.0`, confirm:

- docs/spec/labels/threat model are complete
- nightly bake-off workflow is live
- corpus governance is documented
- thresholds are justified by a recorded baseline run

Tag command:

```bash
git tag -a bakeoff-v1.0 -m "Bake-off v1.0 baseline and governance locked"
```
