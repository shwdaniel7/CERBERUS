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

## Phase 1 — Foundation (in progress)

- **Tests**: `requirements-dev.txt` (pytest + pytest-cov), `pytest.ini`,
  `conftest.py`, and a `tests/` suite covering the analyzer pipeline, risk
  scoring, engines, reports, cache, batch runner, settings store, and the
  engine registry. Security regressions are first-class tests: CSV injection,
  oversized files, corrupt/hostile settings, symlink/reparse pruning.
- **CI**: `.github/workflows/ci.yml` — pytest on Python 3.12/3.13 on
  Ubuntu + Windows, plus the legacy `validate_all.py` / `test_cache_hit.py`
  suites.
- **Engine registry**: `modules/engine_registry.py` is the single source of
  engine names/labels/toggles (the GUI checkboxes now derive from it) and
  exposes the `register`/`unregister` plugin hooks Phase 2 engines will use.
- **S5**: `skip_reparse_points` setting (default on) prunes junctions/symlinks
  during batch walks. `docs/security/SECURITY_AUDIT.md` updated to
  **Fixed/Addressed**.

## Phase 2 — Detection engines (each with tests + report schema entry)

1. **YARA + custom rules** (high priority) — `yara-python`, `rules/` folder,
   per-file isolation of compile errors, limits + timeout (S6), mappable into
   risk factors via metadata and MITRE later.
2. **Deobfuscation** (Base64/XOR, stdlib) feeding YARA and IOC matching.
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