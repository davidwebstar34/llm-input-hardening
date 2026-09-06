.PHONY: bench bench-plots bakeoff-smoke bakeoff-smoke-assert bakeoff-full bakeoff-full-assert bakeoff-lint bakeoff-diff bakeoff-diff-assert bakeoff-schema microbench probe test gen-tables fuzz

PY ?= python
BAKEOFF_BASELINE ?= bench/results/bakeoff_baseline_schema4.json

ifneq ("$(wildcard .venv/bin/python)","")
PY := .venv/bin/python
endif

# Regenerate the Unicode default-ignorable table from the running Unicode
# version. Run after a Unicode data bump; the drift test enforces freshness.
gen-tables:
	$(PY) tools/gen_unicode_tables.py --write
	$(PY) tools/gen_variation_sequences.py

# Fuzz the sanitizer core (requires nightly + cargo-fuzz). See fuzz/README.md.
fuzz:
	cargo +nightly fuzz run sanitize -- -max_total_time=$(or $(FUZZ_SECONDS),60)

bench:
	$(PY) bench/run_benchmarks.py --out bench/results/latest.json

bench-plots:
	$(PY) bench/plot_benchmarks.py --in bench/results/latest.json --out-dir bench/results/assets

bakeoff-smoke:
	$(PY) bench/run_bakeoff.py --out bench/results/bakeoff_smoke_latest.json --md-out bench/results/bakeoff_smoke_latest.md

bakeoff-smoke-assert:
	$(PY) bench/assert_bakeoff.py --in bench/results/bakeoff_smoke_latest.json --thresholds bench/bakeoff_thresholds.json --engine-mode smoke

bakeoff-full:
	uv run --with llm-guard --with confusable-homoglyphs python bench/run_bakeoff.py --out bench/results/bakeoff_latest.json --md-out bench/results/bakeoff_latest.md

bakeoff-lint:
	$(PY) bench/lint_corpus.py --corpus bench/obfuscation_corpus/cases.json --thresholds bench/bakeoff_thresholds.json

bakeoff-schema:
	$(PY) bench/validate_json.py --corpus bench/obfuscation_corpus/cases.json --thresholds bench/bakeoff_thresholds.json

bakeoff-full-assert:
	$(PY) bench/assert_bakeoff.py --in bench/results/bakeoff_latest.json --thresholds bench/bakeoff_thresholds.json --engine-mode full

bakeoff-diff:
	$(PY) bench/bakeoff_diff.py --baseline $(BAKEOFF_BASELINE) --current bench/results/bakeoff_latest.json --out-json bench/results/bakeoff_diff_latest.json --out-md bench/results/bakeoff_diff_latest.md

bakeoff-diff-assert:
	$(PY) bench/assert_bakeoff_diff.py --in bench/results/bakeoff_diff_latest.json

microbench:
	$(PY) bench/run_microbench.py --out bench/results/microbench_latest.json

probe:
	$(PY) bench/probe_unicode_survivors.py

test:
	$(PY) -m pytest -q
