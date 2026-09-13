# CERBERUS — Roadmap

Execution plan. Phases are ordered by cost × value; decisions were made with
the user on 2026-09-13:

- **North star**: local-first desktop tool. An API/web/multi-user platform is
  deferred to a later stage (post-portfolio).
- **Dependencies**: pip packages are allowed with justification; the core
  stays stdlib.
- **Testing**: a pytest suite + GitHub Actions CI lands **before** new engines.
- **Language**: English is the standard UI/report language.

## Phase 0 — UX polish + security hardening (in progress)

**Functional UX**
- Custom Scan is real: engine checkboxes in the GUI build the scan config;
  Quick/Full preset them. `modules/gui.py`.
- Settings view is a working form persisted to `settings.json` (git-ignored,
  no secrets): engines, cache, workers, max file size, report format/folder.
  `modules/settings_store.py`.
- History/Reports views are interactive: row selection, view JSON in a popup,
  open the artifact with the OS, open the reports folder.
- Paste a full path (Ctrl+V in the field) instead of only the file picker.

**Security (see `docs/security/SECURITY_AUDIT.md`)**
- S1 fixed — CSV formula injection (`_sanitize_csv_value` in `modules/reports.py`).
- S2 fixed — default `max_file_size` 200 MB enforced in CLI/GUI/batch; fail-fast
  before any engine read.
- S3 fixed — `settings_store` fail-safe, typed, secret-free.
- S5 tracked (junction walks) — Phase 1.

**Docs**: `docs/security/SECURITY_AUDIT.md`, `SECURITY.md`, this file.

## Phase 1 — Foundation (complete)

- **Tests**: `requirements-dev.txt` (pytest + pytest-cov), `pytest.ini`,
  `conftest.py`, and a `tests/` suite covering the analyzer pipeline, risk
  scoring, engines, reports, cache, batch runner, settings store, and the
  engine registry. Security regressions are first-class tests: CSV injection,
  oversized files, corrupt/hostile settings, symlink/reparse pruning.
- **CI**: `.github/workflows/ci.yml` — pytest on Python 3.12/3.13 on
  Ubuntu + Windows with coverage gates. The legacy
  `validate_all.py` / `test_cache_hit.py` suites are git-ignored and no longer
  part of CI (their scenarios moved into the pytest suite).
- **Engine registry**: `modules/engine_registry.py` is the single source of
  engine names/labels/toggles (the GUI checkboxes now derive from it) and
  exposes the `register`/`unregister` plugin hooks Phase 2 engines use.
- **S5**: `skip_reparse_points` setting (default on) prunes junctions/symlinks
  during batch walks. `docs/security/SECURITY_AUDIT.md` updated to
  **Fixed/Addressed**.

## Phase 2 — Detection engines (each with tests + report schema entry)

1. ✅ **YARA + custom rules** — `modules/yara_engine.py` scans the rules in
   `yara_rules/` using the optional `yara-python` package
   (`requirements-yara.txt`; no cp314 wheel yet, so the engine degrades to an
   `available: False` result instead of crashing, mirroring `pe_analysis`).
   Rule files compile one at a time behind a per-process fingerprint cache, so
   a broken rule is recorded in `compile_errors` without discarding the other
   files; every `match()` call runs with a 10 s timeout (S6). A YARA hit adds
   a capped risk factor and surfaces in the report as `yara_analysis`
   (JSON/CSV/HTML). CI installs `requirements-yara.txt`; tests run real rules
   on 3.12/3.13 and exercise the exception paths locally with a fake `yara`
   API. Open follow-up: rule-count/size limits for full S6 compliance.

1b. ✅ **Bundled rule catalog + templates for non-expert users** — a
   conservative, original catalog in `yara_rules/core/` (10 rules: PS cradles,
   LOLBin staging, embedded-PE, persistence, VBA macros, web shells, RAT
   markers), each with a positive/negative test pair as the FP guard. Rule
   files are loaded recursively across subfolders. Severity from `meta` maps
   to risk (low 5 / medium 10 / high 15, YARA cap 40) and matches expose
   `description`/`reference` in the report. `yara_rules/templates/` ships
   commented skeletons (string/PE/regex) and `docs/YARA_RULES.md` is the
   beginner guide.
2. ✅ **Deobfuscation** — `modules/deobfuscation.py` detects long Base64
   blobs (decode plus printable-text / embedded-header heuristic) and
   single-byte XOR content (brute force over a bounded window ranking keys by
   printable ratio and space count). The decoded view feeds back into **YARA**
   (matches tagged `decoded: True`) and **IOC extraction**, so payloads that
   hide strings inside Base64 blocks are still caught; a flagged decode adds a
   capped risk factor. stdlib only (the sixth engine to need no new
   dependency). Decoding is bounded per S7: a 2 MB raw prefix per blob, capped
   blob count/size and feed, fixed 512 KB XOR window.
3. **Fuzzy hashing** — TLSH (wheel; ssdeep as alternative) similarity.
4. **Archive recursion** — zip via `zipfile` with S4 safeguards.
5. **Authenticode on PE** — signature presence/subject/issuer; revocation off
   by default.
6. **Office macros + PDF JS** — `oletools` / `pypdf` (larger scope).
7. **RAR** — optional (`rarfile` + `unrar`), Windows-coupled.

## Phase 3 — Correlation

- MITRE ATT&CK mapping (static constraint table, e.g. `VirtualAlloc`+entropy →
  T1055).
- Report diff between two JSON analyses.
- Statistics dashboard aggregating history/batch summaries.

## Phase 4 — Threat intel feeds

- Reputation service with pluggable providers (AlienVault OTX, MISP,
  AbuseIPDB); per-feed keys in `.env`; TLS + timeouts enforced.

## Phase 5 — Deferred (post-portfolio)

- FastAPI service + modern frontend, then multi-user, roles, and audit trail,
  then SOAR plugin API. PDF export and PT/EN report localization are extras of
  Phase 3+.

## Definition of Done

Every feature ships with: tooltip, empty state, keyboard path, no regression
below 980×650, an entry in the README engines table, and a pass through the
security regression rules in `docs/security/SECURITY_AUDIT.md`.