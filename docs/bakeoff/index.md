# Bake-off

The bake-off is a reproducible evaluation harness for text-integrity hardening.

- [Spec (contract)](spec.md)
- [Labels](labels.md)
- [Governance](governance.md)
- [Release notes v1.0.0](releases/v1.0.0.md)

Run locally:

```bash
make bakeoff-lint
make bakeoff-schema
make bakeoff
make bakeoff-assert
make bakeoff-diff
make bakeoff-diff-assert
```

Automation:

- CI uploads the latest generated results and diff reports as artifacts instead of committing them to the repository.
- CI gates bootstrap regressions against `bench/results/bakeoff_baseline_v1.0.0.json`.
- Nightly workflow runs bake-off, compares against prior nightly artifact, and runs mutation/fuzz corpus bake-off.
