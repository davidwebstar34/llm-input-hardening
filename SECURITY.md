# Security Policy

## Reporting vulnerabilities

Please report security issues privately through GitHub Security Advisories or direct maintainer contact before public disclosure.

Include:

- affected version/commit
- reproduction input (escaped if it contains sensitive text)
- expected vs observed behavior
- impact assessment

## Unicode obfuscation hazards

Unicode obfuscation can make text look safe while preserving hidden control or spoofing behavior.

### Copy/paste warnings

- Do not trust visual rendering alone for untrusted text.
- Treat copied snippets from chat, markdown, terminals, and issue comments as untrusted input.
- Inspect suspicious text as code points (`U+XXXX`) before triage decisions.

### Logging and storage guidance

- Do not store raw untrusted input by default in long-lived logs.
- Prefer structured counts/signals (`flagged_counts`, `removed_counts`, reason codes).
- If raw input is required for incident response, scope retention tightly and restrict access.

### Redaction guidance for corpus contributions

- Remove secrets, tokens, credentials, and personal data before adding examples.
- Use synthetic payloads for encoded blobs and attack strings.
- Include escaped representations in reviews for invisible/bidi/default-ignorable text.
