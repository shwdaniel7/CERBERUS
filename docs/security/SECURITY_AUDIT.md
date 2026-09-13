# CERBERUS — Security Audit

Internal document. Mirrors the audit performed while hardening the Phase 0
surface. Each finding lists the affected code, the exploit scenario, and the
mitigation with its status.

## Threat model

CERBERUS consumes **hostile input by design**: every file it analyzes may be a
malware sample or a crafted document intended to break or abuse the tool
itself. The analysis core is therefore treated as an attacker-controlled
boundary. Reports, caches, archives, and rule engines all receive data that
could originate from an adversary. This audit covers:

- Report generation and file handling.
- Memory and resource bounds when reading hostile files.
- Configuration and secrets handling.
- Future engines (archives, YARA) designed before implementation.

## Findings

| ID | Severity | Finding | Affected code | Status |
|---|---|---|---|---|
| S1 | High (cheap fix) | **CSV formula injection**: cells containing file names or paths starting with `=`, `+`, `-`, `@`, or a tab/control character are evaluated as formulas or DDE links by spreadsheet applications when a report is opened in Excel. | `modules/reports.py` `save_csv_report` | **Fixed** in Phase 0. Cells are prefixed with a single quote via `_sanitize_csv_value`. Verified by an end-to-end report written for a file literally named `=test.exe`. |
| S2 | Medium-High | **Memory exhaustion / DoS on hostile files**: the shared byte buffer is capped at 128 MB, but the per-engine fallbacks (`strings`, `ioc_extract`, `packers`, `entropy`) reread the file with an unbounded `read()`. A very large sample could exhaust memory and crash the process or the machine. | `modules/file_metrics.py`, `modules/strings.py`, `modules/ioc_extract.py`, `modules/packers.py`, `modules/entropy.py` | **Fixed** in Phase 0. A default `max_file_size` of **200 MB** is now applied in every entry point (CLI, GUI, batch) when the config does not override it (`0` = unlimited). Oversized files fail fast with a clear `ValueError` before any engine reads them. Streaming read paths remain a Phase 1 optimization to lower peak memory for files between 128 MB and the cap. |
| S3 | Medium | **Settings persistence could leak into reports/cache or be mis-validated**: a hand-edited or corrupt `settings.json` could crash startup or carry unexpected values; storing secrets there would expose them in cache keys and reports. | `modules/settings_store.py` (new) | **Fixed** in Phase 0. The store only persists non-secret operational values (the VirusTotal key stays in `.env`), returns defaults on corrupt files, and coerces/validates every field (workers ≥ 1, max_file_size ≥ 0, report_format enum, typed booleans). `settings.json` is git-ignored. |
| S4 | Medium (future) | **Zip/archive recursion**: decompressing hostile archives can produce zip bombs, absolute paths, or `..` traversal entries. | Phase 2 (`archives` engine) | **By design** — required before implementation: uncompressed-size cap, compression-ratio limit, depth limit, rejection of absolute/`..` entries, extraction into a private temp directory with guaranteed cleanup, and symlink rejection. |
| S5 | Low-Medium | **Junction/symlink escape during batch walks** could read outside the target folder. | `modules/batch.py` `collect_candidates` | **Open** (tracked). `os.walk` does not follow symlinks by default; Windows junctions may still be reported as directories depending on the runtime. Phase 1 will skip reparse points when the setting is enabled. |
| S6 | Low (future) | **YARA rule handling**: a malicious or broken rule could hang matching or crash the engine. | Phase 2 (`yara_engine`) | **By design** — required: per-file rule compilation with isolated syntax errors, rule-count and size limits, and a match timeout. |
| RS1 | Reviewed / OK | HTML reports escape all sample-controlled text with `html.escape` (`modules/reports.py` `save_html_report`). Risk-level cells derive from the internal scorer, not from file content. | `modules/reports.py` | Reviewed — no change required. |
| RS2 | Reviewed / OK | IOC, string, and path regexes are linear (no nested quantifiers); no catastrophic backtracking (ReDoS) was found on attacker-controlled content. | `modules/ioc_extract.py`, `modules/strings.py` | Reviewed — kept as a regression rule in Phase 1. |
| RS3 | Reviewed / OK | VirusTotal calls use a fixed HTTPS URL with a 15 s timeout; the key is read from `.env` and never logged, included in reports, or written to cache. 429/5xx are handled without leaking credentials. | `modules/hashes.py` | Reviewed — no change required. |
| RS4 | Reviewed / OK | Cache keys are derived from content hashes and config; the SQLite store holds only analysis results. No deserialization of hostile data (JSON only, no pickle). | `modules/analysis_cache.py` | Reviewed — no change required. |

## Regression rules (Definition of Done)

Any new feature must pass this checklist before merge (tracked in tests from
Phase 1):

1. **Hostile input**: sample-controlled bytes/strings must never reach an
   interpreter (`eval`/`exec`), a shell, or a document-macro context unsanitized.
2. **No unbounded reads**: every file read is capped (config `max_file_size`),
   streamed, or explicitly bounded.
3. **No secrets on disk**: new persisted settings never contain credentials;
   keys live only in `.env`.
4. **No injection in exports**: CSV cells are sanitized (S1); HTML is escaped;
   new export formats apply the same rule.
5. **Async GUI hygiene**: engines run in worker processes/threads; the mainloop
   only receives typed events (no `eval` of event payloads).
6. **Archive/rule engines** must satisfy S4/S6 before being enabled.

## Report a vulnerability

See `SECURITY.md` at the repository root for the public reporting policy.