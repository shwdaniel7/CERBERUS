<p align="center">
  <img src="https://i.imgur.com/VG9jzJy.png" alt="CERBERUS Logo" width="280" />
</p>

<p align="center">
  <img src="https://files.catbox.moe/c8nu8t.webp" alt="CERBERUS Demo" width="560" />
</p>

<h1 align="center">CERBERUS</h1>

<p align="center"><strong>STATIC MALWARE ANALYSIS ENGINE</strong></p>

<p align="center"><em>Three heads. One purpose. Nothing gets past.</em></p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge" alt="Python" />
  <img src="https://img.shields.io/badge/Tkinter-silver?style=for-the-badge" alt="Tkinter" />
  <img src="https://img.shields.io/badge/VirusTotal_API-orange?style=for-the-badge" alt="VirusTotal API" />
  <img src="https://img.shields.io/badge/JSON_Reports-4DB33D?style=for-the-badge" alt="JSON Reports" />
  <img src="https://img.shields.io/badge/MIT-License-brightgreen?style=for-the-badge" alt="MIT License" />
  <img src="https://img.shields.io/badge/Windows-2374E1?style=for-the-badge" alt="Windows" />
</p>

<p align="center">
  <a href="https://github.com/shwdaniel7/CERBERUS"><img src="https://img.shields.io/github/last-commit/shwdaniel7/CERBERUS?style=for-the-badge" alt="Last Commit" /></a>
  <a href="https://github.com/shwdaniel7/CERBERUS"><img src="https://img.shields.io/github/stars/shwdaniel7/CERBERUS?style=for-the-badge" alt="Stars" /></a>
  <a href="https://github.com/shwdaniel7/CERBERUS"><img src="https://img.shields.io/github/repo-size/shwdaniel7/CERBERUS?style=for-the-badge" alt="Repository Size" /></a>
</p>

<p align="center"><sub><em>made by daniel • @shwdaniel7</em></sub></p>

---

## ⚠ Warning

CERBERUS is an educational static analysis toolkit. It inspects file metadata, file headers, embedded strings, entropy values, and hash reputation without executing the target binary.

- Use this tool only on files you own or are authorized to analyze.
- It is not a sandbox and does not execute suspicious files.
- It demonstrates static malware analysis concepts, not behavioral monitoring.

---

## 📖 About

CERBERUS is a Python-based static malware analysis toolkit designed to inspect suspicious files before execution. It runs file classification checks, signature reputation lookups, string extraction, entropy assessment, and file-type validation using local data and VirusTotal.

The application is organized into small modules that separate user interaction, hashing, reputation checks, report generation, string analysis, entropy calculation, and header inspection.

These modules are composed into a command-driven analyzer in `analyzer.py`. With no arguments it opens the Tkinter dashboard; passing a file or folder with CLI flags runs non-interactive scans for automation.

---

## ✨ Capabilities

CERBERUS implements interactive and automated scan profiles:

| Profile | Enabled Engines | Report Output |
|---|---|---|
| Full Scan | Local blacklist, VirusTotal lookup, string IOC scan, Shannon entropy, magic number header check | JSON, CSV, and HTML reports |
| Quick Scan | Local blacklist, magic number header check | JSON, CSV, and HTML reports |
| Custom Scan | User-selected combination of all available engines | Optional JSON, CSV, and HTML reports |
| Analysis History | Lists previous JSON reports with optional name, hash, or risk-level filtering | Terminal listing |
| Batch Scan | Full Scan applied to every file in a selected folder with **parallel worker processes**, cache reuse, and an optimized SQLite WAL cache | Risk-filtered JSON reports plus batch summary |
| IOC Lists Integrity | Validates local hashes and suspicious terms, reporting valid and malformed entries | Terminal listing |
| **Clear History/Reports** | Delete all reports (JSON, CSV, HTML) and optionally the analysis cache | Terminal confirmation + GUI buttons |

The default no-argument launch opens the Tkinter dashboard. The dashboard organizes each analysis into `IDENTITY`, `EVIDENCE`, and `VERDICT`, while CLI mode remains available for automation.

The toolkit can:

- compute a SHA-256 fingerprint for the selected file
- compare the fingerprint against `iocs/blacklist.txt`
- query VirusTotal using `VT_API_KEY` from `.env`
- extract suspicious strings with regex matching
- extract URLs, IP addresses, domains, e-mails, suspicious paths, and PowerShell/CMD commands
- calculate Shannon entropy as an indicator of possible compression or packing
- detect known packer signatures such as PyInstaller and UPX to contextualize entropy
- analyze PE headers and sections when the optional `pefile` engine is available
- compare declared extensions with detected file types and report compatibility
- query VirusTotal only when an API key is configured, with explicit clean, unknown, suspicious, and malicious states
- identify file type from magic bytes and detect disguised PE executables
- calculate a transparent risk score from the analysis indicators and explain the factors that raised it
- assign higher weight to high-signal indicators such as `keylogger`, `VirtualAlloc`, PowerShell, and `cmd.exe`
- emit structured JSON, CSV, and HTML reports under `reports/`
- include extracted strings, file metadata, detected type, indicator count, CERBERUS version, and analysis duration in reports
- browse previous analyses and filter them by file name, SHA-256 hash, or risk level
- select a folder and analyze relevant files recursively, generating individual reports only when the risk is High or Critical
- skip common static assets and generated dependency folders during batch analysis
- validate and reload IOC lists without changing the source code
- **clear all analysis history and reports via CLI (`--clear-history`) or GUI buttons (History/Reports views)**
- **clear the persistent analysis cache via CLI (`--clear-history --include-cache`) or checkpoint it automatically when a batch finishes**
- use the first dashboard interface to select files, run scans, monitor engines, and inspect results

---

## 📂 Project Structure

```
CERBERUS/
├── analyzer.py
├── LICENSE
├── README.md
├── requirements.txt
├── .env
├── .gitignore
├── docs/
│   ├── gui/
│   │   └── ISSUE_18_GUI_RESPONSIVENESS.md
│   └── optimization/
│       ├── BATCH_OPTIMIZATION.md
│       └── P1-P5.md
├── iocs/
│   ├── blacklist.txt
│   └── suspect_strings.txt
├── modules/
│   ├── analysis_cache.py
│   ├── analysis_events.py
│   ├── batch.py
│   ├── colors.py
│   ├── entropy.py
│   ├── file_metrics.py
│   ├── gui.py
│   ├── hashes.py
│   ├── ioc_extract.py
│   ├── iocs.py
│   ├── magic_numbers.py
│   ├── packers.py
│   ├── pe_analysis.py
│   ├── reports.py
│   ├── risk.py
│   └── strings.py
└── reports/
    └── .cerberus-cache.sqlite3 (created at runtime)

```

- `analyzer.py` is the entrypoint and orchestrates analysis flow.
- `modules/gui.py` provides the Tkinter dashboard without duplicating analysis logic.
- `modules/analysis_events.py` defines lifecycle events consumed by the dashboard and other interfaces.
- `modules/analysis_cache.py` stores reusable results for repeated scans in an SQLite WAL database.
- `modules/batch.py` runs folder scans across parallel worker processes and reuses the cache per worker.
- `modules/iocs.py` loads and sanity-checks the local blacklist and suspicious-term lists.
- `modules/` contains each analysis engine and utility.
- `iocs/` stores local indicators for blacklist and suspicious string matching.
- `docs/` records the optimization and GUI work behind the project.
- `reports/` is the output folder for JSON, CSV, and HTML report files; `.cerberus-cache.sqlite3` is created there at runtime.
- `requirements.txt` contains the runtime dependencies used by the project.

Modular separation keeps reputation checks, static analysis, and reporting isolated from the user interaction layer.

---

## 🔄 Analysis Workflow

```text
[Start] python analyzer.py
       │
       ├─► Dashboard (Tkinter): New Analysis / Batch Scan / History / Reports / IOC Lists
       │        │
       │        └─► File selection
       │
       ├─► Scan profile (Full / Quick / Custom)
       │
       ├─► Optional analysis history lookup
       │
       ├─► Optional folder analysis and batch summary
       │
       ├─► Optional SHA-256 hash calculation
       │
       ├─► Optional local blacklist lookup
       │
       ├─► Optional VirusTotal lookup
       │
       ├─► Optional magic number header inspection
       │
       ├─► Optional Shannon entropy analysis
       │
       ├─► Optional suspicious string extraction
       │
       ├─► Optional URL/IP/domain/e-mail/path/command extraction
       │
       ├─► Optional JSON, CSV, and HTML report generation
       │
       └─► End
```

Running `python analyzer.py <file-or-folder> --full` bypasses the dashboard and executes the same pipeline from the terminal.

---

## 🚀 Installation

```bash
git clone https://github.com/shwdaniel7/CERBERUS.git
cd CERBERUS
pip install -r requirements.txt
```

> If you prefer a dedicated environment, use `python -m venv .venv` before installing dependencies.

---

## 🔑 Configuration

CERBERUS loads the VirusTotal API key from `.env` using `python-dotenv`.

Create or update `.env` with:

```env
VT_API_KEY=your_virustotal_api_key_here
```

If `.env` is missing or `VT_API_KEY` is not set, VirusTotal lookups will fail gracefully and report connection errors without breaking the overall scan flow.

---

## 💻 Usage

Run the toolkit from the repository root:

```bash
python analyzer.py
```

The command above opens the Tkinter dashboard. For automation, pass a file or folder path and use CLI options; no graphical window is created:

```bash
python analyzer.py arquivo.exe --full
python analyzer.py arquivo.exe --quick --no-virustotal --report html --output reports/ --quiet
python analyzer.py ./samples/ --full
```

Passing a folder runs the Batch Scan engine over every relevant file inside it. `--report` defaults to `all` (JSON, CSV, and HTML), and `--quick` scans still write reports for the engines they run.

CLI options:

- `--full`: run all analysis engines.
- `--quick`: run the local blacklist and file-type checks.
- `--clear-history`: delete all analysis reports and history files.
- `--no-virustotal`: disable VirusTotal requests.
- `--report all|json|csv|html`: choose generated report formats.
- `--output PATH`: choose the report directory.
- `--quiet`: suppress engine progress and print only the final risk and duration.
- `--workers N`: configure concurrent workers for batch analysis.
- `--no-cache`: disable the persistent SQLite analysis cache.
- `--max-file-size BYTES`: skip files larger than the configured limit.
- `--include-cache`: also clear the analysis cache when using `--clear-history`.

### Terminal-only execution

CERBERUS can run entirely from the terminal without opening the Tkinter dashboard. Provide the target file as the first argument and select a scan profile:

```bash
# Complete terminal analysis
python analyzer.py sample.exe --full

# Quick terminal analysis without VirusTotal
python analyzer.py sample.exe --quick --no-virustotal

# Automation-friendly output with no animation
python analyzer.py sample.exe --full --no-virustotal --quiet
```

Terminal-only mode is intended for scripts, CI jobs, remote sessions, and environments without a graphical display. It writes the selected reports to the directory passed with `--output` and returns a non-interactive summary containing the risk level and execution time.

Without a file argument, CERBERUS opens the graphical dashboard. During normal analysis and batch scans, each enabled engine reports its execution time and the final result includes total duration.

While an engine is running, the terminal displays an animated progress bar with the completed percentage, spinner, active engine, engine elapsed time, and total elapsed time. Batch scans retain the per-file progress line and show the same engine-level bar for every selected file. Use `--quiet` to disable animation for log-friendly automation.

Interactive output includes a red CERBERUS identity banner, `[>]` engine-start states, `[OK]` completion states, and a final summary divided into `VERDICT`, `EVIDENCE`, and `IDENTITY`, with deliberate spacing between analysis blocks.

Batch analysis uses configurable workers and a persistent cache keyed by file metadata, enabled engines, and analyzer version. The dashboard batch uses a bounded pool of up to four worker processes, avoids CSV/HTML generation for every low-risk file, and writes individual JSON reports only at the configured risk threshold. Repeated scans can reuse previous results when the file and configuration are unchanged. When SHA-256 and entropy are both enabled, their reusable byte metrics are collected in one streaming pass.

**Performance improvements**: Large batch scans run in **separate worker processes** through a `ProcessPoolExecutor`, so CPU-heavy engines no longer contend on the Python GIL and the GUI stays responsive regardless of the number of files or workers. The analysis cache uses **SQLite WAL mode** with connections confined to each worker for concurrent access without locking contention. Cache connections are closed (WAL checkpoint) after batch completion.

The analysis core emits structured `AnalysisEvent` values for file and engine lifecycle changes. Future interfaces can subscribe to these events without parsing terminal output.

### First dashboard interface

Running `python analyzer.py` opens the initial Tkinter dashboard. Its layout follows the CERBERUS identity:

- `IDENTITY`: file name, type, extension, compatibility, hash, and size.
- `EVIDENCE`: engine states, progress, and execution times.
- `VERDICT`: risk level, score, factors, and report path.

The dashboard runs analysis in a background thread so the window remains responsive. It is an evolving interface; the operational flows described below (batch, history, reports, and IOC lists) build on the same lifecycle. CLI mode is unchanged for scripts and automation.

The first interface stage also defines the visual lifecycle used by future screens: `QUEUED`, `RUNNING`, `COMPLETE`, `SKIPPED`, `FAILED`, and `CACHED`. The three-stage indicator follows `IDENTITY -> EVIDENCE -> VERDICT`, while the identity panel exposes the full path and a copy action for SHA-256.

### Evidence exploration

The Evidence panel now keeps an `Overview` tab for live engine progress and provides focused tabs for `Strings`, `IOCs`, `PE`, `Entropy`, and `Reputation` after analysis completes. These tabs distinguish observed data from contextual indicators such as high entropy or packer signatures, while preserving the main three-panel layout.

### Application flows

The dashboard navigation now includes `New Analysis`, `Batch Scan`, `History`, `Reports`, `IOC Lists`, and `Settings`. Batch Scan runs files in the background and reports completion, risk, duration, cache hits, and failures incrementally. History reads previous JSON summaries, Reports lists generated artifacts, and IOC Lists reuses the existing integrity checks. These are the first operational flows; deeper report comparison and filtering remain future polish.

### Interface polish

The dashboard includes lightweight interaction polish without turning the forensic workflow into decoration: tooltips on controls, keyboard shortcuts (`Ctrl+O`, `F5`, and `Ctrl+Enter`), hover cursors, semantic compatibility colors, a subtle running-stage pulse, and a staggered verdict-factor reveal. Motion is disabled from the analysis data path and does not alter CLI or `--quiet` behavior.

On file selection the Identity panel is populated immediately with the name, extension, size, header-detected type, and compatibility, while the SHA-256 is computed in the background. The window enforces a `980x650` minimum and the path and hash text reflows when resized, so the layout never clips at small sizes.

The dashboard opens with a file picker. After selecting a target file, choose **Full Scan**, **Quick Scan**, or **Custom Scan** as the profile. The analysis runs in a background thread while each enabled engine reports its status, and the result fills the `IDENTITY`, `EVIDENCE`, and `VERDICT` panels.

The **History** view lists previous JSON reports stored in `reports/`. It can be filtered by file name, SHA-256 hash, or risk level, and displays the analysis date, risk score, hash, and report path. A **Clear History** button deletes all JSON report files (with confirmation).

The **Batch Scan** flow chooses a folder. CERBERUS recursively analyzes relevant files using the Full Scan profile, but only generates individual JSON, CSV, and HTML reports when the risk score reaches `50/100` (`High` or `Critical`). Lower-risk files are still included in the analysis summary without creating individual reports. The batch consults VirusTotal only when local indicators are present, which avoids spending API quota on routine files. The `batch_summary_<timestamp>.json` file contains totals, risk-level counts, generated reports, risk-filtered reports, failures, skipped files, and report references. Common assets such as images, fonts, audio, and video are skipped by default, as are `.git`, `.venv`, `__pycache__`, and `node_modules` directories.

**Large folder handling**: Batch scans dispatch files across worker processes and emit progress per file, so the UI remains interactive even with thousands of files.

The **Reports** navigation tab lists all generated artifacts (JSON, CSV, HTML). A **Clear Reports** button removes all report files including batch summaries (with confirmation).

The **IOC Lists** flow validates the IOC files. `iocs/blacklist.txt` accepts one SHA-256 hash per line, with optional `#` comments. `iocs/suspect_strings.txt` accepts one suspicious term per line. Invalid hashes, empty terms, and malformed entries are ignored during analysis and reported by this flow. Both files are reloaded from disk for every analysis, so updating them does not require a code change or restart.

### Example interaction

Terminal output from a full CLI run:

```text
$ python analyzer.py sample.exe --full

+--------------------------------------------------+
| CERBERUS  /  STATIC MALWARE ANALYSIS ENGINE      |
| Three heads. One purpose. Nothing gets past.      |
+--------------------------------------------------+

[ TARGET ]
  File   sample.exe
  Size   145.06 KB

[>] Starting SHA-256
[+] SHA256: 24d004a104d4d540340c7831432f90a5...
[OK] SHA-256 completed

[>] Starting Local blacklist
[+] Hash is clean in the local control list.
[OK] Local blacklist completed

[>] Starting File type and magic numbers
[+] Declared Extension: .exe
[+] Detected Type: Windows Executable (EXE/DLL)
[+] Compatibility: Compatible
[OK] File type and magic numbers completed

[>] Starting Entropy and packers
[+] Shannon Entropy Score: 7.12/8.0
[->] Status: NORMAL: Low randomness (Standard readable code/text)
[OK] Entropy and packers completed

[>] Starting Strings
Total of strings: 134
Alerts found: 0
[OK] Strings completed

[ ANALYSIS COMPLETE ]
  [VERDICT]
    Risk       Low (20/100)
    Indicators 1
    Duration   0.526s
  [EVIDENCE]
    > 1 suspicious string alert(s) (+4)
  [IDENTITY]
    Report      reports/report_sample.exe_24d004a1.json
```

Add `--quiet` to collapse this into a single line: `sample.exe: Low (20/100) - 0.526s`.

---

## 🧩 Analysis Engines

### `modules/colors.py`

- Responsible for ANSI terminal coloring.
- Provides text wrappers for red, green, yellow, cyan, and bold output.
- Used by `analyzer.py` to keep CLI output readable.

### `modules/hashes.py`

- Computes SHA-256 from the selected file.
- Reads `iocs/blacklist.txt` for local hash reputation.
- Performs VirusTotal lookups using `requests` and `VT_API_KEY` from `.env`.
- Returns human-readable status strings for API results.

### `modules/magic_numbers.py`

- Reads a 32-byte window of the file header.
- Matches magic signatures for Windows PE (EXE/DLL), ELF, PDF, PNG, GIF, JPEG, ZIP/OOXML, RAR, 7z, GZIP, BZIP2, XZ, HDF5, RIFF (WAV/AVI/WebP), MP3 (ID3), OGG, FLAC, and ICO.
- Flags disguised Windows PE files when a non-executable extension is used.

### `modules/entropy.py`

- Computes Shannon entropy across all bytes in the file.
- Uses a 256-bin frequency distribution.
- Classifies high entropy differently for compressed and media formats.
- Reports `INDICATOR` or `NORMAL`; high entropy is evidence of possible compression, encryption, or packing, not proof of malware.

### `modules/packers.py`

- Detects conservative signatures for common packers such as PyInstaller and UPX.
- Returns the packer name and matching evidence for report context.
- Packer detection is informational: it does not add risk points or establish that a file is malicious.

### `modules/pe_analysis.py`

- Analyzes `MZ` files with the optional `pefile` dependency.
- Reports the `PE` signature, section count, section names, raw and virtual sizes, and entropy per section.
- Returns a `not_executed` status when `pefile` is not installed and skips non-`MZ` files.
- PE structure is descriptive evidence and does not add risk points by itself.

### File type and VirusTotal results

The magic-number engine reports the declared extension, detected type, and compatibility as `Compatible`, `Mismatch`, or `Unknown`. It covers executable, archive, document, image, audio, and video signatures.

VirusTotal requests use a 15-second timeout and are skipped when `VT_API_KEY` is absent. A `404` is stored as `unknown`, while a successful analysis is classified as `clean`, `suspicious`, or `malicious`. Reports preserve separate `malicious`, `suspicious`, `harmless`, and `undetected` counts.

### `modules/strings.py`

- Extracts printable ASCII-like strings from binary content using regex.
- Loads suspicious indicators from `iocs/suspect_strings.txt`.
- Matches IOC terms as tokens instead of arbitrary substrings.
- Ignores common benign terms such as `http`, `https`, `KERNEL32.dll`, and Python module names when generating alerts.
- Returns the extracted strings and any triggered alerts.

### `modules/ioc_extract.py`

- Extracts URLs, valid IP addresses, domains, e-mail addresses, suspicious Windows/Unix paths, and PowerShell/CMD command fragments.
- Returns values grouped by category in the `ioc_extraction` report section.
- Network indicators are collected as evidence and do not increase risk by themselves; suspicious paths and shell commands add only a small risk signal.

### `modules/iocs.py`

- Loads and validates `iocs/blacklist.txt` and `iocs/suspect_strings.txt` on every analysis.
- Reports valid versus malformed entries for the IOC Lists integrity check without a code change or restart.

### `modules/reports.py`

- Generates JSON, CSV, and HTML output under `reports/`.
- JSON contains metadata (including per-engine timings), selected engines, signatures, VirusTotal results, entropy scores, detected file type, magic alerts, IOC extraction, PE details, all extracted strings, string alerts, and the indicator count.
- CSV provides a compact, one-row summary suitable for comparing analyzed files.
- HTML provides a color-coded risk summary and collapsible sections for alerts, extracted strings, and technical analysis.
- Creates the `reports/` folder if it does not exist.

### `modules/batch.py`

- Collects candidate files from a folder and skips common assets, `.git`, `.venv`, `__pycache__`, and `node_modules`.
- Runs each candidate through a worker process pool (`ProcessPoolExecutor`) with a configurable worker count and a thread-based fallback.
- Provides per-file progress callbacks, a shared analysis cache per worker, and writes a `batch_summary_<timestamp>.json`.

### `modules/analysis_cache.py`

- Persistent SQLite cache with **WAL (Write-Ahead Logging) mode** for concurrent read/write access.
- **Connections confined to each worker** prevent lock contention during batch scans.
- Cache keys include file metadata, enabled engines, and analyzer version for correctness.
- Configurable via `--no-cache` (CLI) or `cache_enabled` (config dict).
- Connections are closed with `close()` (WAL checkpoint) after batch completion.

---

## 🔬 Technical Concepts

### SHA-256

CERBERUS computes the SHA-256 digest of the selected file and uses it for local blacklist matching and VirusTotal queries.

### VirusTotal lookups

The toolkit queries `https://www.virustotal.com/api/v3/files/{hash}` and reports detection counts from the `last_analysis_stats` payload.

### Magic Numbers

CERBERUS inspects the file header bytes to determine the real file type. It treats a Windows PE header inside a non-executable extension as a masquerade warning.

### Shannon Entropy

Entropy is calculated from byte frequency distribution. High entropy is reported as an indicator of possible compression, encryption, or packing, while compressed media formats are treated as expected cases. Entropy alone contributes only a small amount to the score and does not make a file suspicious or trigger a VirusTotal lookup.

Known packer signatures are checked alongside entropy. For example, a PyInstaller or UPX signature can explain high entropy in a packaged executable. This context is recorded in `entropy_analysis.packer_context`, but packing remains neutral evidence and must be combined with other indicators.

### IOC matching and regex extraction

Embedded strings are extracted from raw file bytes using a regex pattern for printable sequences. IOC terms from `iocs/suspect_strings.txt` are matched as complete tokens, and common benign values such as protocol names, Windows runtime DLLs, and Python modules are kept as extracted strings without being promoted to alerts. A string alert is evidence to combine with other signals, not proof by itself.

The separate `modules/ioc_extract.py` engine extracts structured observables from the same file content. It validates IPv4/IPv6 values, separates network indicators from suspicious paths and shell commands, and keeps all categories available in the JSON and HTML technical report.

### UTF-16 strings and PE sections

The string engine scans both ASCII-like bytes and UTF-16LE text, which covers common Windows Unicode resources and embedded messages. The optional PE engine stores section-level details under `pe_analysis` in the report. Install `pefile` to enable it:

```bash
pip install pefile
```

---

## 📄 Example Report

```json
{
  "metadata": {
    "archive_name": "suspicious_sample.exe",
    "full_path": "C:/samples/suspicious_sample.exe",
    "kb_size": 145.76,
    "byte_size": 149258,
    "extension": ".exe",
    "analysis_date": "2026-06-26 12:34:56",
    "cerberus_version": "1.0.0",
    "analysis_duration_seconds": 0.526,
    "engine_times_seconds": {
      "SHA-256": 0.021,
      "Local blacklist": 0.002,
      "File type and magic numbers": 0.004,
      "Entropy and packers": 0.310,
      "Strings": 0.087,
      "PE sections": 0.011,
      "IOC extraction": 0.023
    }
  },
  "signatures": {
    "sha256": "24d004a104d4d540340c7831432f90a5..."
  },
  "virustotal_analysis": {
    "message": "Flagged by VirusTotal: 3/82 antivírus detectaram perigo.",
    "malicious": 3,
    "suspicious": 1,
    "harmless": 74,
    "undetected": 4
  },
  "statistics_analysis": {
    "blacklist_local": "Clean / Not found",
    "entropy_analysis": {
      "score": 7.12,
      "status": "INDICATOR: High randomness (Possible packer, encrypted or compressed data)",
      "packer_context": {
        "detected": true,
        "packers": ["PyInstaller"]
      }
    },
    "magic_number_analysis": {
      "declared_extension": ".exe",
      "detected_type": "Windows Executable (EXE/DLL)",
      "compatibility": "Compatible",
      "compatible": true,
      "alert": null
    },
    "ioc_extraction": {
      "urls": ["https://malicious.example/dropper"],
      "ip_addresses": ["203.0.113.10"],
      "domains": [],
      "emails": [],
      "suspicious_paths": [],
      "powershell_commands": ["rundll32.exe ..."],
      "cmd_commands": []
    },
    "pe_analysis": {
      "status": "analyzed",
      "has_pe_signature": true,
      "number_of_sections": 5,
      "sections": [...]
    },
    "total_alerts": 1,
    "alerts": [
      "Suspect term found: 'PowerShell'. Trigger: 'PowerShell'."
    ],
    "all_strings": [
      "kernel32",
      "PowerShell",
      "..."
    ],
    "indicator_count": 6
  },
  "risk_summary": {
    "score": 34,
    "level": "Moderate",
    "factors": [
      "1 suspicious string alert(s) (+4)",
      "IOC: 1 URL(s) extracted (+2)",
      "High entropy INDICATOR (+5)"
    ]
  }
}
```

Engines disabled by the chosen profile appear as `"Not executed"` in their section.

---

## 📚 Technologies

- Python
- Tkinter
- requests
- python-dotenv
- JSON
- SQLite (WAL mode for concurrent cache access)
- Windows file handling

---

## ⚖ Legal Notice

CERBERUS is provided for education, malware analysis, digital forensics, and security research.

The author assumes no responsibility for misuse, unauthorized scanning, or any actions taken with the results.

Use this project only on files you are permitted to analyze.
