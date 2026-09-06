# Benchmarks

This repo includes a benchmark harness intended to be:

- **Reproducible**: saves raw results + environment metadata
- **Representative**: includes multiple realistic + adversarial inputs
- **Visual**: generates charts that you can embed in README

---

## Run

```bash
make bench
make bench-plots
make bakeoff-smoke
#
# or directly:
# python bench/run_benchmarks.py --out bench/results/latest.json
# python bench/plot_benchmarks.py --in bench/results/latest.json --out-dir docs/assets
# uv run --with llm-guard --with confusable-homoglyphs python bench/run_bakeoff.py --out bench/results/bakeoff_latest.json --md-out docs/bakeoff/results.md
# uv run --with llm-guard --with confusable-homoglyphs --with tiktoken python bench/run_bakeoff.py --tokenizer tiktoken --tokenizer-model o200k_base --out bench/results/bakeoff_latest.json --md-out docs/bakeoff/results.md
# python bench/assert_bakeoff.py --in bench/results/bakeoff_latest.json --thresholds bench/bakeoff_thresholds.json
# python bench/lint_corpus.py --corpus bench/obfuscation_corpus/cases.json --thresholds bench/bakeoff_thresholds.json
# python bench/validate_json.py --corpus bench/obfuscation_corpus/cases.json --thresholds bench/bakeoff_thresholds.json --results bench/results/bakeoff_latest.json --strict-results
# python bench/bakeoff_diff.py --baseline bench/results/bakeoff_baseline_schema4.json --current bench/results/bakeoff_latest.json --out-json bench/results/bakeoff_diff_latest.json --out-md docs/bakeoff/diff_latest.md
# python bench/assert_bakeoff_diff.py --in bench/results/bakeoff_diff_latest.json
# python bench/run_microbench.py --out bench/results/microbench_latest.json
```

Outputs:
- JSON results: `bench/results/latest.json`
- Bake-off results: `bench/results/bakeoff_latest.json`
- Microbench results: `bench/results/microbench_latest.json`
- Charts:
  - `docs/assets/bench_throughput.png`
  - `docs/assets/bench_latency_us.png`
  - `docs/assets/bench_throughput.svg`
  - `docs/assets/bench_latency_us.svg`

Plot notes:
- The plotter emits SVG directly and converts to PNG using `rsvg-convert` (preferred) or ImageMagick `convert`.

Bake-off scope note:
- The automated adversarial bake-off is currently text-level and compares:
  - `llm-input-hardening`
  - `llm-guard` (`InvisibleText` scanner)
  - `confusable-homoglyphs`
- Framework-level systems (NeMo Guardrails, Guardrails AI) are typically integrated at orchestration/validation layers and are better evaluated in end-to-end app tests.
- Adapter capabilities are declared explicitly: unsupported labels render as
  N/A and do not count as false negatives. Aggregate engine scores cover
  different capabilities; use the common-label comparisons to compare engines
  on the same subset. Transform postconditions are evaluated only where the
  adapter supports the case's requirements.
- Separate per-policy enforcement results include genuine benign code,
  multilingual text, complete hashes, and encoded attachments. Expected caution
  still counts toward the benign quarantine/reject rates; decision mismatches
  gate the smoke and full assertions.
- Result schema 4 changes the comparison contract. Preserve the historical
  v1.0.0 baseline as an archive and record a new baseline with the current schema
  before comparing runs. Nightly runs establish a new baseline on a schema
  transition, without drawing a regression conclusion.
- Cases carry hashes of their full input and expectation contracts. A stable
  name is insufficient for pairing: changed cases fail comparison. Runtime
  metadata hashes the loaded Python files, native binary, policy registry and
  effective thresholds; checkout build-input hashes and dirty state identify
  local builds without claiming that a stale binary matches those sources.
- Gates validate finite numeric data, unique rows and summary totals against
  individual case evidence. A missing comparison fails unless a caller
  explicitly permits the first-baseline state, as the nightly workflow does.

Record a schema-4 baseline once, after reviewing a full run:

```bash
make bakeoff-full bakeoff-full-assert
cp -n bench/results/bakeoff_latest.json bench/results/bakeoff_baseline_schema4.json
```

After a subsequent full run, `make bakeoff-diff bakeoff-diff-assert` compares it
with that baseline. To use a different reviewed baseline, pass
`BAKEOFF_BASELINE=/path/to/baseline.json` to `make`. Do not overwrite the
historical `bakeoff_baseline_v1.0.0.json` or interpret older-schema/current-schema score
differences as a quality change. A full baseline requires all comparison
dependencies; local smoke results cannot replace that evidence.

---

## Benchmark cases (recommended)

Include at least:
- Clean ASCII (small/medium/large)
- Mixed Unicode (emoji + combining sequences)
- “Attack” strings containing bidi controls / invisibles
- Encoded payload-like text (base64/hex)
- Long repeated whitespace/newlines (tests tidying costs)
- A realistic “chat prompt” input (messages + roles + separators)

Cases live in `bench/cases.py` and should be:
- deterministic (no network, no disk I/O)
- stable across runs (so version diffs are meaningful)
- named with a stable identifier

---

## Reproducibility tips

- Run on an idle machine.
- Pin CPU governor if possible (Linux).
- Run multiple repeats and report percentiles (p50, p95).
- Record:
  - CPU model
  - OS + kernel
  - Python version
  - package version + git SHA

The harness should already capture most of this automatically.

## Comparing versions / regressions

- Commit the JSON output (or upload it as CI artifact) so you can compare:
  - p95 latency deltas per case
  - throughput deltas per case
- Prefer comparing the same machine, same Python, same build flags.
- Treat small deltas as noise; look for consistent changes across multiple cases.
- The timing harness now samples every call, with p50/p95 across individual
  durations rather than batch averages. It records `latency_sampling` in the
  environment metadata. Older batch-average baselines require replacement;
  the comparator rejects mixed sampling methods. `at_p95_latency` names the
  throughput derived from p95 latency, which is not a p95 throughput percentile.

This repo includes a simple, non-gating comparator:

```bash
python bench/compare_benchmarks.py \
  --baseline bench/results/baseline.json \
  --current bench/results/latest.json
```

Keep the baseline generated on the **same hardware** as the current run.

## Microbenchmark limitations (read before trusting numbers)

- Python call overhead is included (this measures the Python API, not just the Rust core).
- CPU frequency scaling and background load can dominate short runs.
- Per-call timer overhead is included; these local measurements do not include
  network latency, application queuing, or concurrent request contention.
- Different Python versions and allocator behavior can change results.

---

## Interpreting results

- **Throughput (MiB/s)** shows “how fast can I sanitize text streams”.
- **Latency (µs/call)** shows per-request overhead for typical prompt sizes.
- The most important metric for production APIs is often p95 latency.
