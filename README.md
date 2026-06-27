<p align="center">
  <img src="https://i.imgur.com/VG9jzJy.png" alt="CERBERUS Logo" width="280" />
</p>

<p align="center">
  <img src="https://files.catbox.moe/8r57lx.gif" alt="CERBERUS Demo" width="560" />
</p>

<h1 align="center">CERBERUS</h1>

<p align="center"><strong>Static Malware Analysis Toolkit</strong></p>

<p align="center">Inspect suspicious files before execution using modern static analysis techniques.</p>

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

<p align="center">made by arneb • @shwdaniel7</p>

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

CERBERUS implements three scan profiles:

| Profile | Enabled Engines | Report Output |
|---|---|---|
| Full Scan | Local blacklist, VirusTotal lookup, string IOC scan, Shannon entropy, magic number header check | JSON report |
| Quick Scan | Local blacklist, magic number header check | No report |
| Custom Scan | User-selected combination of all available engines | Optional JSON report |

The toolkit can:

- compute a SHA-256 fingerprint for the selected file
- compare the fingerprint against `iocs/blacklist.txt`
- query VirusTotal using `VT_API_KEY` from `.env`
- extract suspicious strings with regex matching
- calculate Shannon entropy for file randomness
- identify file type from magic bytes and detect disguised PE executables
- emit a structured JSON report under `reports/`

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
│   ├── entropy.py
│   ├── hashes.py
│   ├── magic_numbers.py
│   ├── menu.py
│   ├── reports.py
│   └── strings.py
├── reports/

```

- `analyzer.py` is the entrypoint and orchestrates analysis flow.
- `modules/` contains each analysis engine and utilities.
- `iocs/` stores local indicators for blacklist and suspicious string matching.
- `reports/` is the output folder for JSON report files.
- `samples/requirements.txt` contains the runtime dependencies used by the project.

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
       │      └─ Custom Scan
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
       ├─► Optional JSON report generation
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

The application opens a file picker. After selecting a target file, choose one of the scan profiles:

```text
  1 - Full Scan (All checks + Report)
  2 - Quick Scan (Local Blacklist + Header)
  3 - Custom Scan (Choose your options)
```

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
- Reports `CRITICAL`, `SUSPICIOUS`, or `NORMAL` based on the implementation thresholds.

### `modules/strings.py`

- Extracts printable ASCII-like strings from binary content using regex.
- Loads suspicious indicators from `iocs/suspect_strings.txt`.
- Reports any embedded strings that match local IOC terms.
- Returns the extracted strings and any triggered alerts.

### `modules/reports.py`

- Generates structured JSON output under `reports/`.
- Includes metadata, selected engines, signatures, VirusTotal results, entropy scores, detected file type, magic alerts, and string alerts.
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

Entropy is calculated from byte frequency distribution. The implementation reports a risk level for high randomness and treats compressed media formats as expected high-entropy cases.

### IOC matching and regex extraction

Embedded strings are extracted from raw file bytes using a regex pattern for printable sequences. These strings are compared against the local `iocs/suspect_strings.txt` list for suspicious terms.

---

## 📄 Example Report

```json
{
  "metadata": {
    "archive_name": "suspicious_sample.exe",
    "full_path": "C:/samples/suspicious_sample.exe",
    "kb_size": 145.76,
    "analysis_date": "2026-06-26 12:34:56"
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
    "total_alerts": 1,
    "alerts": [
      "Suspect term found: 'kernel32'. Trigger: 'kernel32'."
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
