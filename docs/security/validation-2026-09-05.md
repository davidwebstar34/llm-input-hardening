# Hardening validation — 2026-09-05

The reported implementation gaps were fixed, then tested as interacting
properties rather than only as individual attack strings. The final local
functional and regression checks passed. **Release remains blocked by the
[PyO3 dependency advisories](dependency-status.md).**

## Final verification

| Check | Result |
| --- | --- |
| Full Python suite | 857 passed |
| Rust unit tests, locked and offline | 14 passed |
| Ruff, Rustfmt, Clippy with warnings denied | Passed |
| Current corpus schema, thresholds and case contracts | 254 cases, 18 labels passed |
| Per-policy enforcement contracts | 68 outcomes; zero mismatches |
| Assembly equivalence evaluation | 4,896 checks; zero failures |
| Seeded mutation corpus | 48 cases, seed 20260905; all contracts passed |
| Unicode property coverage | Every combining mark known to the Python test runtime recognized by native Unicode 17 data |
| Pinned standardized/emoji variation coverage | All 2,095 bundled pairs accepted in their valid context |
| Clean installed wheel | Passed without optional dependencies; packaged Python files matched source |
| Dependency audit | Two PyO3 advisories remain; no ignores added |

The Python suite includes 1,024 seeded interaction cases across four policies,
checking exact repeatability, normalized output fixed points, expansion limits,
UTF-8 span boundaries and truthful change reporting. Separate tests cover
resource saturation, cancellation, long paths, numeric literals and mutable
configuration. These are local regression results, not estimates of production
attack-detection or false-positive rates.

## Resource probes

The same 10,000 nonstring leaves nested 300 levels required about **0.187 MiB**
of temporary allocations after the traversal fix, compared with **28.41 MiB**
before it. Both measurements used `tracemalloc` on the same local runtime.

A 900 KB ordinary accepted request reduced the independent event-loop
heartbeat's maximum gap from **0.513 seconds to 0.034 seconds**. Total request
time in the latter probe was 0.777 seconds: the improvement is event-loop
responsiveness and bounded concurrency, not a claim of lower request latency.

The repair regression completes a 262,145-character out-of-order combining
sequence under a ten-second subprocess deadline. The former Python normalization
path took tens of seconds on this input. Skeleton normalization has its own
hard-timeout regression, and native processing releases the GIL.

## Findings caught by the broader tests

- Randomized entropy accumulation changed report floats between identical calls;
  native summation now has a stable order.
- Default-ignorables outside Python's Format category and identifier punctuation
  could still split detection; the native property view now covers them.
- Whole-script checks needed the same continuation rules as mixed-script checks,
  while retaining a minimum of three actual letters.
- Completed workers released admission before downstream code released the body;
  admission now covers the full request lifetime and surviving cancelled work.
- Repeated long mapping keys could amplify middleware reports; incremental
  report budgets now cover those paths.
- A truthy mutable value could change a frozen policy's native-prose behavior;
  policy construction now requires an actual boolean and snapshots collections.
- The new selector signal needed evaluation coverage as well as unit tests;
  IH015 now participates in corpus labels, schemas, thresholds and enforcement.

These findings fit the [hardening contract's failure families](hardening-contract.md).
The final pass found no further failing invariant within that tested scope.

## Environment and unavailable checks

Validation used CPython 3.12 on macOS arm64 with cached dependencies and a
locally rebuilt ABI3 extension. The wheel was built with locked offline Cargo
dependencies and installed into a fresh environment with no optional packages.
Its smoke test exercised detection, assembly, field validation, JSON traversal,
meter fallback, exact numeric forwarding, duplicate-key rejection and disconnect
propagation. Other supported platforms remain covered by configured CI jobs;
they were not executed locally.

The cached RustSec audit database identified the outstanding PyO3 advisories.
The unused Criterion/Rayon/Crossbeam chain was removed and benchmark targets
still compile. Current registry access failed DNS resolution, preventing a
tested upgrade to patched PyO3. `pip-audit`, `llm-guard` and a model tokenizer
were unavailable locally. Optional-runtime audit export scope was verified;
live Python vulnerability scanning and the full third-party comparison were
not completed. Historical baselines were preserved.

CI/release audits remain enabled and fail closed. No release, publication or
advisory exemption was made during this work.
