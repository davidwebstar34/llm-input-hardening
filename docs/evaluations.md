# Evaluation: Classifier Lift

This repository includes an evaluation-only script to measure whether deterministic sanitization improves a simple moderation-style detector.

Run:

```bash
python bench/run_classifier_lift.py --out bench/results/classifier_lift.json
```

Method:
- select current-schema cases with `kind="attack"` and nonempty `expected.must_detect`
- run lexical moderation classifier on raw input (`before`)
- sanitize input (`balanced_chat`)
- run the same classifier on sanitized output (`after`)
- compare detection rates across obfuscation corpus samples

The JSON records the denominator (`obfuscated_cases`) and per-case results.
An empty eligible set fails instead of emitting zero rates. Historical numbers
from the retired `obfuscated` corpus field are not comparable to this selection.

This is a small lexical experiment, not a moderation accuracy or jailbreak
prevention evaluation. The detector searches four keyword patterns, and the
corpus labels describe text shapes rather than malicious intent. A changed hit
rate does not demonstrate improvement on a production semantic classifier.

`bench/run_bakeoff.py` additionally evaluates default enforcement against
`bench/enforcement_corpus.json`. Every case declares `kind` and expected
allow/quarantine/reject decisions for all four policies. Benign inputs include
vocalized Arabic, pointed Hebrew, Hindi, Thai, native Greek prose, indented code,
CRLF documents, a complete digest, and an encoded attachment.

The report separates raw benign quarantine/reject rates from unexpected
decisions. Legitimate hashes and attachments remain benign even when a policy
intentionally quarantines their shape: they still contribute to friction rates.
These small hand-reviewed fixtures are regression controls, not estimates of
production false-positive rates. Add representative application traffic before
choosing enforcement thresholds.

The current corpus contains 254 cases across 18 labels, including unsupported
variation-selector contexts (`IH015`) and valid emoji, Mongolian and Han
controls. The enforcement corpus covers 68 case/policy outcomes. Assembly
evaluation adds 4,896 checks across fragment boundaries, separators, policies
and change-rejection settings; the complete report and decision must equal
direct inspection of the final content.

Results use schema 4 with case, configuration, source, native binary and harness
fingerprints. Assertions validate evidence and recompute summary counts before
applying thresholds. See the [benchmark contract](benchmarks.md) and
[hardening strategy](security/hardening-contract.md).
