# Security Policy

CERBERUS is a static malware analysis toolkit that intentionally processes
untrusted, potentially hostile files. Treat every analyzed sample as an
attacker-controlled input, including files you download from the internet.

## Supported software

The current audit applies to the `1.0.0` line on Windows, with a plain
`python analyzer.py` local run. Engines marked as future work (archives,
YARA, feeds) are not considered part of the audited surface yet.

## Reporting a vulnerability

- Do **not** open a public issue for confirmed or suspected security defects.
  Report privately instead.
- If you find a defect that affects a third party (a leaked credential, a CVSS
  issue in a dependency, or data exposure), prefer the project maintainer's
  private contact: **@shwdaniel7**.
- Include: affected version, a minimal reproducer (ideally a tiny synthetic
  sample, not a real piece of malware), expected vs. observed behavior, and
  impact.
- For critical issues (RCE, credential exposure, arbitrary file read/write),
  expect an initial reply within 7 days.

## What is in scope

- Memory-bounded handling of hostile files (`max_file_size`, shared buffers).
- SQL injection / path traversal in reports, cache, batch, or future archive
  extraction.
- Injection into exported artifacts: CSV formula injection, HTML escaping,
  future PDF/JSON templates.
- Secret handling (VirusTotal API key) — leaks via logs, reports, cache, or
  settings.
- Deserialization of hostile data (JSON only; no pickle).

## Out of scope / no warranty

- The project deliberately does not execute untrusted code. Do not use it as a
  rewriter for behavioral (dynamic) analysis and do not run it on samples you
  were not prepared to open on your machine.
- This policy is provided as-is without warranty; reports are closed at the
  maintainer's discretion.

## Known and designed mitigations

The current audit results live in `docs/security/SECURITY_AUDIT.md`. New
engines (archives, YARA, threat-intel feeds) are gated behind the regression
rules listed there.