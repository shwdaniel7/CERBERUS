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

These modules are composed into a command-driven analyzer in `analyzer.py`, which uses Tkinter for file selection and a simple CLI menu for scan selection.

---

## ✨ Capabilities

CERBERUS implements interactive and automated scan profiles:

| Profile | Enabled Engines | Report Output |
|---|---|---|
| Full Scan | Local blacklist, VirusTotal lookup, string IOC scan, Shannon entropy, magic number header check | JSON, CSV, and HTML reports |
| Quick Scan | Local blacklist, magic number header check | No report |
| Custom Scan | User-selected combination of all available engines | Optional JSON, CSV, and HTML reports |
| Analysis History | Lists previous JSON reports with optional name, hash, or risk-level filtering | Terminal listing |
| Batch Scan | Full Scan applied to every file in a selected folder | Individual reports plus batch summary |
| IOC Lists Integrity | Validates local hashes and suspicious terms, reporting valid and malformed entries | Terminal listing |

The default no-argument launch opens the first Tkinter dashboard. The dashboard organizes each analysis into `IDENTITY`, `EVIDENCE`, and `VERDICT`, while CLI mode remains available for automation.

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
├── iocs/
│   ├── blacklist.txt
│   └── suspect_strings.txt
├── modules/
│   ├── colors.py
│   ├── gui.py
│   ├── analysis_cache.py
│   ├── analysis_config.py
│   ├── analysis_events.py
│   ├── file_metrics.py
│   ├── entropy.py
│   ├── hashes.py
│   ├── magic_numbers.py
│   ├── menu.py
│   ├── packers.py
│   ├── pe_analysis.py
│   ├── reports.py
│   ├── risk.py
│   ├── strings.py
│   └── ioc_extract.py
├── reports/

```

- `analyzer.py` is the entrypoint and orchestrates analysis flow.
- `modules/gui.py` provides the first Tkinter dashboard without duplicating analysis logic.
- `modules/analysis_events.py` defines lifecycle events consumed by the dashboard and future interfaces.
- `modules/analysis_cache.py` stores reusable results for repeated scans.
- `modules/` contains each analysis engine and utilities.
- `iocs/` stores local indicators for blacklist and suspicious string matching.
- `reports/` is the output folder for JSON, CSV, and HTML report files.
- `requirements.txt` contains the runtime dependencies used by the project.

Modular separation keeps reputation checks, static analysis, and reporting isolated from the user interaction layer.

---

## 🔄 Analysis Workflow

```text
[Start] python analyzer.py
       │
       ├─► File selection (Tkinter dialog)
       │
       ├─► Menu selection
       │      ├─ Full Scan
       │      ├─ Quick Scan
      │      ├─ Custom Scan
      │      └─ Batch Scan
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
      ├─► Optional URL/IP/domain/e-mail/path/command extraction
       │
      ├─► Optional JSON, CSV, and HTML report generation
       │
       └─► End
```

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

The command above keeps the default Tkinter file selector. For automation, pass a file path and use CLI options; no graphical window is created:

```bash
python analyzer.py arquivo.exe --full
python analyzer.py arquivo.exe --quick --no-virustotal --report html --output reports/ --quiet
```

CLI options:

- `--full`: run all analysis engines.
- `--quick`: run the local blacklist and file-type checks.
- `--no-virustotal`: disable VirusTotal requests.
- `--report all|json|csv|html`: choose generated report formats.
- `--output PATH`: choose the report directory.
- `--quiet`: suppress engine progress and print only the final risk and duration.
- `--workers N`: configure concurrent workers for batch analysis.
- `--no-cache`: disable the persistent SQLite analysis cache.
- `--max-file-size BYTES`: skip files larger than the configured limit.

Without a file argument, CERBERUS retains the interactive menu and graphical file selector. During normal analysis and batch scans, each enabled engine reports its execution time and the final result includes total duration.

While an engine is running, the terminal displays an animated progress bar with the completed percentage, spinner, active engine, engine elapsed time, and total elapsed time. Batch scans retain the per-file progress line and show the same engine-level bar for every selected file. Use `--quiet` to disable animation for log-friendly automation.

Interactive output includes a red CERBERUS identity banner, `[>]` engine-start states, `[OK]` completion states, and a final summary divided into `VERDICT`, `EVIDENCE`, and `IDENTITY`, with deliberate spacing between analysis blocks.

Batch analysis uses configurable workers and a persistent cache keyed by file metadata, enabled engines, and analyzer version. Repeated scans can reuse previous results when the file and configuration are unchanged. When SHA-256 and entropy are both enabled, their reusable byte metrics are collected in one streaming pass.

The analysis core emits structured `AnalysisEvent` values for file and engine lifecycle changes. Future interfaces can subscribe to these events without parsing terminal output.

### First dashboard interface

Running `python analyzer.py` opens the initial Tkinter dashboard. Its layout follows the CERBERUS identity:

- `IDENTITY`: file name, type, extension, compatibility, hash, and size.
- `EVIDENCE`: engine states, progress, and execution times.
- `VERDICT`: risk level, score, factors, and report path.

The dashboard runs analysis in a background thread so the window remains responsive. It is a first functional interface; batch controls, history navigation, and richer report exploration remain future interface work. CLI mode is unchanged for scripts and automation.

The first interface stage also defines the visual lifecycle used by future screens: `QUEUED`, `RUNNING`, `COMPLETE`, `SKIPPED`, `FAILED`, and `CACHED`. The three-stage indicator follows `IDENTITY -> EVIDENCE -> VERDICT`, while the identity panel exposes the full path and a copy action for SHA-256.

The application opens a file picker. After selecting a target file, choose one of the scan profiles:

```text
  1 - Full Scan (All checks + Report)
  2 - Quick Scan (Local Blacklist + Header)
  3 - Custom Scan (Choose your options)
  4 - Analysis History
  5 - Batch Scan (Full Scan on a folder)
  6 - IOC Lists Integrity
```

Select `4` to browse reports already stored in `reports/`. The history view can be filtered by file name, SHA-256 hash, or risk level, and displays the analysis date, risk score, hash, and report path.

Select `5` to choose a folder. CERBERUS recursively analyzes relevant files using the Full Scan profile, but only generates individual JSON, CSV, and HTML reports when the risk score reaches `50/100` (`High` or `Critical`). Lower-risk files are still included in the analysis summary without creating individual reports. The batch consults VirusTotal only when local indicators are present, which avoids spending API quota on routine files. The `batch_summary_<timestamp>.json` file contains totals, risk-level counts, generated reports, risk-filtered reports, failures, skipped files, and report references. Common assets such as images, fonts, audio, and video are skipped by default, as are `.git`, `.venv`, `__pycache__`, and `node_modules` directories.

Select `6` to validate the IOC files. `iocs/blacklist.txt` accepts one SHA-256 hash per line, with optional `#` comments. `iocs/suspect_strings.txt` accepts one suspicious term per line. Invalid hashes, empty terms, and malformed entries are ignored during analysis and reported by this menu option. Both files are reloaded from disk for every analysis, so updating them does not require a code change or restart.

### Example interaction

```text
[?] Select scan type (1-3): 1
[*] Profiling: Full Scan selected. Activating all engines...
--- Generating file signature ---
[+] SHA256: <hash>
--- Consulting local blacklist ---
[+] Hash clean in local control list.
--- Querying VirusTotal API ---
[->] VirusTotal: File not found or unknown in their database.
--- Verifying magic signature ---
[+] Detected real type: Windows Executable (EXE/DLL)
--- Calculating Shannon entropy ---
[+] Entropy score: 7.12/8.0
[->] Status: NORMAL: Low randomness (Standard readable code/text)
--- Analyzing file strings ---
Total number of strings: 134
Alerts found: 0
--- Risk Summary ---
[!] Risk: Low (0/100)
[+] Factors:
  -> No risk indicators were detected
--- Exporting results ---
[+] Dynamic report generated on: reports/report_filename_<shorthash>.json
```

---

## 🧩 Analysis Engines

### `modules/colors.py`

- Responsible for ANSI terminal coloring.
- Provides text wrappers for red, green, yellow, cyan, and bold output.
- Used by `analyzer.py` and `modules/menu.py` to keep CLI output readable.

### `modules/hashes.py`

- Computes SHA-256 from the selected file.
- Reads `iocs/blacklist.txt` for local hash reputation.
- Performs VirusTotal lookups using `requests` and `VT_API_KEY` from `.env`.
- Returns human-readable status strings for API results.

### `modules/magic_numbers.py`

- Reads the first 4 bytes of the file header.
- Matches known magic signatures for EXE, ELF, PDF, PNG, GIF, JPEG, and ZIP/Office archive.
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
- Returns `unavailable` when `pefile` is not installed and skips non-`MZ` files.
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

### `modules/reports.py`

- Generates JSON, CSV, and HTML output under `reports/`.
- JSON contains metadata, selected engines, signatures, VirusTotal results, entropy scores, detected file type, magic alerts, all extracted strings, and string alerts.
- CSV provides a compact, one-row summary suitable for comparing analyzed files.
- HTML provides a color-coded risk summary and collapsible sections for alerts, extracted strings, and technical analysis.
- Creates the `reports/` folder if it does not exist.

### `modules/menu.py`

- Presents the CLI scan profile menu.
- Implements Full Scan, Quick Scan, and Custom Scan modes.
- Maps user choices to engine activation flags consumed by `analyzer.py`.

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
    "analysis_duration_seconds": 0.526
  },
  "signatures": {
    "sha256": "24d004a104d4d540340c7831432f90a5..."
  },
  "virustotal_analysis": {
    "virustotal": "Flagged by VirusTotal: 3/82 antivírus detectaram perigo."
  },
  "statistics_analysis": {
    "blacklist_local": "Clean / Not found",
    "entropy_analysis": {
      "score": 7.12,
      "status": "NORMAL: Low randomness (Standard readable code/text)"
    },
    "magic_number_analysis": {
      "detected_type": "Windows Executable (EXE/DLL)",
      "masquerade_alert": "None (Extension matches header)"
    },
    "all_strings": [
      "kernel32",
      "PowerShell"
    ],
    "total_alerts": 1,
    "alerts": [
      "Suspect term found: 'kernel32'. Trigger: 'kernel32'."
    ]
  },
  "risk_summary": {
    "score": 20,
    "level": "Moderate",
    "factors": [
      "1 suspicious string alert(s) (+4)"
    ]
  }
}
```

---

## 📚 Technologies

- Python
- Tkinter
- requests
- python-dotenv
- JSON
- Windows file handling

---

## ⚖ Legal Notice

CERBERUS is provided for education, malware analysis, digital forensics, and security research.

The author assumes no responsibility for misuse, unauthorized scanning, or any actions taken with the results.

Use this project only on files you are permitted to analyze.
