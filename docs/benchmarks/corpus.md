# Obfuscation Corpus

Corpus path: `bench/obfuscation_corpus/cases.json`

Coverage includes:
- bidi-injected prompts
- junk invisible insertion
- Default-Ignorable insertion
  - includes Unicode Tags block and extended variation selectors
- control/format injection
- unpaired/mismatched bidi isolate patterns
- base64-like payloads
- hex payloads
- high-entropy blocks
- combining-mark storms
- mixed-script homoglyph attacks
- compound perturbations (homoglyph + invisible/deletion/token-splitting)
- benign multilingual samples (Arabic/Hebrew/Greek/Cyrillic/emoji ZWJ + VS16)

Use this corpus with:

```bash
python bench/run_bakeoff.py --out bench/results/bakeoff_latest.json --md-out docs/bakeoff/results.md
```

The output is designed for regression gating and trend dashboards.
