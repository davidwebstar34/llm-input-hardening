# Hardening contract and regression strategy

`allow` means that the configured checks passed for the inspected text. It does
not authorize a tool call or establish benign intent. The security boundary is
the complete untrusted text consumed by the application, with its policy,
Unicode data and optional dependencies pinned.

## Why isolated fixes were insufficient

The recurring failures belonged to a few families:

| Failure family | Required invariant | Regression coverage |
| --- | --- | --- |
| Incomplete Unicode lists | Character properties come from versioned data; unrecognized marks must not reset a mark stack. | Complete mark-category coverage, multilingual benign controls, selector contexts. |
| Boundary splitting | Marks and permitted formats cannot hide a confusable word. Joining raw fragments must produce the same result as inspecting their final concatenation. | Identifier continuations, wrapped encodings, every split position, normalized output fixed points. |
| Stage interactions | Repair and normalization retain original security evidence. Normalization has one bounded implementation. | Original/repaired reports, long out-of-order combining sequences, skeleton normalization. |
| Limits that do not compose | Depth, width, buffered requests and worker cancellation cannot multiply unbounded pending work. | Wide/deep nonstring JSON, worker saturation, cancellation, body deadlines, output limits. |
| Unintended mutation | Only selected text changes. Numeric JSON values and unselected fields survive middleware rewriting. Configuration inspection cannot alter enforcement. | Lossless numeric literals, duplicate-key rejection, immutable configuration and policy snapshots. |
| Weak evaluation identity | Only identical case contracts may be paired; artifacts identify the code, compiled core and policies they exercised. | Case fingerprints, malformed/empty gate data, dependency-audit scope checks. |

The tests exercise these properties across policies and compositions. A newly
found counterexample should extend its family of tests and include a benign
control where the change could reject legitimate text. Merely adding one exact
attack string is insufficient coverage.

## Assembly and trust boundaries

Use `sanitize_assembled(parts, separator=...)` when your application combines
untrusted fragments into one content string. It bounds and joins raw parts, then
sanitizes and decides once. The character budget includes separators and the
part budget includes empty fragments. Spans refer to the assembled input under
the normal sanitizer coordinate rules.

Per-field `sanitize_json` and middleware reports describe the selected strings;
they cannot predict subsequent application concatenation. If an application
changes or joins those strings, inspect the resulting content at that boundary.
Do not join trusted role metadata or system instructions into this helper. The
application remains responsible for its schema, roles and authorization.

Do not repeatedly sanitize cleaned text to reconstruct the original decision:
removal intentionally changes the text and its evidence. Preserve the report
and decision from the original inspection. Output normalization is idempotent;
original-input evidence is not expected to reappear on the cleaned text.

## Resource boundaries

The text API checks its character budget before repair. Rust bounds
normalization expansion and span emission; optional repair leaves canonical
normalization to Rust. JSON traversal retains state proportional to depth,
with independent node, text and report limits. Output containers still require
space proportional to their permitted size.

Middleware bounds admitted requests and active CPU jobs across instances in
one process. Saturation returns HTTP 503; body-read deadlines return HTTP 408.
Cancellation does not release worker capacity until processing actually stops.
These limits complement deployment request limits; they do not implement a
distributed rate limiter or a hard operating-system CPU quota. Applications
must enforce their own model token budgets and promptly handle non-allow
decisions and errors.

## Deliberate policy limits

- Encoded-payload and entropy checks recognize suspicious shapes. They do not
  implement a universal decoder or promise to detect every encoding.
- Chat preserves legitimate multilingual and emoji variation. Context checks
  reduce arbitrary selector payloads; valid variant choices can still carry
  information. Execution policies remove default-ignorables.
- Confusable checks use documented script/skeleton coverage and context
  heuristics. They are not a universal identity-equivalence algorithm. Validate
  security-sensitive identifiers against application-owned allowed values.
- Ordinary malicious instructions, model behavior and permissions remain
  outside the text-integrity contract.

## Completion criteria for a hardening change

1. Reproduce the issue and identify the failed invariant.
2. Fix the shared mechanism and test the counterexample plus nearby variants.
3. Run the full Python/Rust suites, static checks, benign enforcement contracts,
   attack/mutation gates and an installed-wheel smoke check.
4. Preserve evaluation provenance and document behavior changes. Do not lower
   thresholds or rewrite expected decisions merely to make a failing gate pass.
5. Record unavailable checks and remaining policy limitations explicitly.

Passing these gates supports the stated contract for the tested build. It is
not proof that no future counterexample exists. New findings that are outside
this contract should first be treated as scope or policy decisions, rather than
automatically adding more detection rules.

The current [dependency audit status](dependency-status.md) records the compiled
PyO3 0.29.2 upgrade, passing regression tests and fresh Rust/Python audits.
Release validation repeats the required checks for the final release commit.
