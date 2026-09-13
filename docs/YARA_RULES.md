# CERBERUS YARA rules — beginner guide

CERBERUS ships with a small catalog of original, conservative YARA rules plus
templates you can copy to write your own. This page explains how rules work,
what the catalog covers, and how matches become risk — no security background
required.

## What a YARA rule is

A YARA rule is a text file that says: *"if this file contains these signs,
report it."* A minimal rule:

```yara
rule example_rule {          // rule name: what the report will call it
    meta:
        severity = "medium"  // CERBERUS uses this for the risk score
    strings:
        $a = "malware-sign"
    condition:
        $a                    // match when the string $a is present
}
```

- `strings:` are the things to look for (plain text, hex bytes, or regexes).
- `condition:` is the logic (here: "any of the strings is present").
- `meta:` lists extra facts (severity, description, reference) that CERBERUS
  reads and shows in the report.

## How CERBERUS uses the rules

- **Where rules live:** `yara_rules/`. Every `.yar`/`.yara` file in that
  folder *and its subfolders* (for example `yara_rules/core/`) is compiled and
  applied to every scanned candidate. `yara_rules/templates/` only holds
  commented skeletons — they are not active rules.
- **Bad rules don't break the scan:** each rule file is compiled separately.
  A syntax error in one file is recorded under `compile_errors` in the JSON
  report and the other rules keep working.
- **Timeout:** every rule runs with a 10-second timeout, so a pathological
  rule can never hang your scan.
- **Turning a rule off:** delete the file (or move it out of `yara_rules/`).
  There is no per-rule checkbox — file presence is the switch.
- **The YARA engine itself is optional:** it activates when
  `python -m pip install -r requirements-yara.txt` has been run. Without it,
  the engine reports `available: false` and the scan still completes.

## The bundled catalog (`yara_rules/core/`)

All rules are original and written to be *conservative*: each one needs
several signs together, so normal files keep a low score. Every rule has a
positive and a negative test in `tests/test_yara_rule_catalog.py` that runs on
CI — the built-in false-positive guard.

| Rule | Detects | Severity | Points |
|---|---|---|---|
| `cerberus_ps_iex_downloader` | PowerShell download-and-execute cradle (`DownloadString`/`FromBase64String` + `Invoke-Expression`) | high | 15 |
| `cerberus_ps_encoded_command` | PowerShell `-EncodedCommand` / `-enc` one-liner | high | 15 |
| `cerberus_cmd_bitsadmin_stage` | `bitsadmin /transfer … powershell` staging | medium | 10 |
| `cerberus_cmd_certutil_decode` | `certutil -urlcache` + `-decode` staging | medium | 10 |
| `cerberus_embedded_pe_signature` | MZ + PE header inside a file that does **not** start with MZ (embedded PE/dropper shape) | medium | 10 |
| `cerberus_reg_run_persistence` | Registry `Run`/`RunOnce` persistence key reference | medium | 10 |
| `cerberus_schtasks_onlogon` | `schtasks /create` with autostart trigger | medium | 10 |
| `cerberus_vba_autostart_macro` | Office/VBA `AutoOpen`/`Workbook_Open`/`Document_Open` | medium | 10 |
| `cerberus_php_webshell` | PHP one-line web shell (`eval`/`assert`/`system` over `$_POST`/`$_REQUEST`) | high | 15 |
| `cerberus_meterpreter_session` | "meterpreter" present (contextual, informational) | low | 5 |

## How matches affect the risk score

Each matching rule contributes points according to its `meta.severity`:

| severity | points per matching rule |
|---|---|
| `low`    | 5  |
| `medium` | 10 |
| `high`   | 15 |

The YARA contribution is **capped at 40 points** total. If a rule has no
`severity` meta it counts as `medium` (10). The report's `factors` list
explains which rules fired and why — for example
`YARA: PHP one-line web shell (high, +15)`.

> A match is evidence, not proof: treat YARA matches as a reason to look
> closer, not as a verdict by itself.

## Writing your own rules

1. Copy one of the skeletons in `yara_rules/templates/` into
   `yara_rules/` (name it `something.yar`).
   - `string_rule.yar.template` — detect literal strings (with `nocase`,
     `any of them`, etc.)
   - `pe_rule.yar.template` — use numeric helpers (`uint16(0) == 0x5A4D`,
     `filesize`, offsets)
   - `regex_rule.yar.template` — match a RE2-style pattern
2. Fill in the `meta` block (`severity`, `description`, `reference`).
3. Save and re-run a **Full Scan** — a new rule file is picked up the next
   time a process scans (the compiled cache is invalidated when files change).

Inline reference: <https://yara.readthedocs.io/>

## Verifying your rules quickly

Full-scan a small sample you know should (and should not) match:

```bash
python cerberus.py "<path-to-sample>" --full
```

The terminal shows `YARA matches: N` with the matching rule names, and the
JSON report stores the full detail under `details.yara`.