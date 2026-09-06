# Performance

The published package keeps one small, deterministic benchmark path for routine regression checks.

Primary command:

```bash
python bench/run_benchmarks.py --out bench/results/latest.json
```

Recommended public cases:

- short ASCII prompt text
- benign multilingual text
- bidi or invisible-character attack text
- whitespace-heavy templating input
- short execution-adjacent tool input

`bench/` also contains bake-off and comparative evaluation tooling. That machinery is useful for research and deeper release analysis, but it is intentionally separate from the default contributor path.

For more detail, see [bench/README.md](https://github.com/davidwebstar34/llm-input-hardening/blob/main/bench/README.md).
