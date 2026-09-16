"""Tests for the ZIP archive recursion engine (Phase 2.4, S4)."""

import io
import zipfile

import pytest

from modules import zip_engine
from modules.zip_engine import scan_zip, MAX_ZIP_DEPTH, MAX_ZIP_RATIO


def _build_zip(members):
    """Build a ZIP in memory. ``members`` is [{name, data}] (deflated)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for member in members:
            archive.writestr(member["name"], member.get("data", b""))
    return buffer.getvalue()


def _write(tmp_path, name, data):
    target = tmp_path / name
    target.write_bytes(data)
    return str(target)


MZ_BYTES = b"MZ\x90\x00" + b"\x00" * 32
VBS_DATA = b"WScript.CreateObject(\"Scripting.FileSystemObject\")"


# ------------------------------------------------------------------
# scan_zip — input handling
# ------------------------------------------------------------------

def test_scan_non_zip_returns_no_data(tmp_path):
    result = scan_zip(_write(tmp_path, "plain.txt", b"just some text"))
    assert result["status"] == "no_data"
    assert result["is_zip"] is False
    assert result["entry_count"] == 0
    assert result["error"] is None


def test_scan_corrupt_zip_returns_error(tmp_path):
    corrupt = b"PK\x03\x04" + b"\x00" * 100  # ZIP-looking signature, no valid structure
    result = scan_zip(_write(tmp_path, "corrupt.zip", corrupt))
    assert result["available"] is True
    assert result["status"] == "error"
    assert result["is_zip"] is True


def test_scan_matches_filepath_and_buffer(tmp_path):
    payload = _build_zip([{"name": "notes.txt", "data": b"hello"}])
    path = _write(tmp_path, "a.zip", payload)
    file_result = scan_zip(path)
    buffer_result = scan_zip(path, content=payload)
    file_result.pop("entries"), buffer_result.pop("entries")
    assert file_result == buffer_result


# ------------------------------------------------------------------
# Member inspection
# ------------------------------------------------------------------

def test_scan_basic_members(tmp_path):
    payload = _build_zip([
        {"name": "readme.txt", "data": b"hello world"},
        {"name": "data.bin", "data": bytes(range(256))},
    ])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["status"] == "clean"
    assert result["entry_count"] == 2
    names = [entry["name"] for entry in result["entries"]]
    assert names == ["readme.txt", "data.bin"]
    assert result["entries"][0]["flags"] == []


def test_scan_flags_embedded_executable(tmp_path):
    payload = _build_zip([{"name": "payload.exe", "data": MZ_BYTES * 8}])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["findings"]["embedded_executable"] is True
    assert result["status"] == "matched"
    assert "embedded_executable" in result["entries"][0]["flags"]
    assert result["entries"][0]["detected_type"].startswith("Windows Executable")


def test_scan_flags_suspicious_script(tmp_path):
    payload = _build_zip([{"name": "run.vbs", "data": VBS_DATA}])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["findings"]["suspicious_script"] is True
    assert result["findings"]["embedded_executable"] is False


# ------------------------------------------------------------------
# S4 guards
# ------------------------------------------------------------------

def test_scan_high_compression_ratio(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_engine, "MIN_BOMB_SIZE", 1024)
    payload = _build_zip([{"name": "compressible.dat", "data": b"\x00" * (64 * 1024)}])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["findings"]["high_compression_ratio"] is True
    assert result["entries"][0]["ratio"] >= MAX_ZIP_RATIO
    assert "high_compression_ratio" in result["entries"][0]["flags"]


def test_scan_no_bomb_heuristic_for_small_entries(tmp_path):
    """Small members with a high ratio do not trip the heuristic (bounded by MIN_BOMB_SIZE)."""
    payload = _build_zip([{"name": "tiny.txt", "data": b"\x00" * 512}])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["findings"]["high_compression_ratio"] is False


def test_scan_traversal_member_flagged(tmp_path):
    payload = _build_zip([
        {"name": "../../etc/passwd", "data": b"root:x:0:0"},
        {"name": "C:\\evil\\run.bat", "data": b"del C:\\"},
    ])
    result = scan_zip(_write(tmp_path, "a.zip", payload))
    assert result["findings"]["traversal_attempt"] is True
    assert result["findings"]["unsafe_name"] is True
    assert result["unsafe_entries"] >= 2
    unsafe_names = [entry["name"] for entry in result["entries"] if "unsafe_path" in entry["flags"]]
    assert set(unsafe_names) == {"(unsafe)"}


def test_scan_entry_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(zip_engine, "MAX_ZIP_ENTRIES", 3)
    members = [{"name": f"f{i}.txt", "data": b"x"} for i in range(8)]
    result = scan_zip(_write(tmp_path, "a.zip", _build_zip(members)))
    assert result["truncated"] is True
    assert result["entry_count"] <= 3


# ------------------------------------------------------------------
# Nested recursion
# ------------------------------------------------------------------

def test_nested_zip_recurse_finds_files(tmp_path):
    inner = _build_zip([{"name": "evil.scr", "data": MZ_BYTES * 4}])
    outer = _build_zip([{"name": "inner/package.zip", "data": inner}])
    result = scan_zip(_write(tmp_path, "a.zip", outer))
    assert result["nested_archives"] >= 1
    assert result["findings"]["embedded_executable"] is True
    names = [entry["name"] for entry in result["entries"]]
    assert any(name.endswith("evil.scr") for name in names)


def test_nested_depth_limit_stops_recursion(tmp_path):
    leaf = _build_zip([{"name": "note.txt", "data": b"hi"}])
    for _ in range(MAX_ZIP_DEPTH + 1):
        leaf = _build_zip([{"name": "levels.zip", "data": leaf}])
    result = scan_zip(_write(tmp_path, "a.zip", leaf))
    assert result["nested_archives"] >= MAX_ZIP_DEPTH
    assert result["status"] in ("clean", "matched")
    assert all(entry["uncompressed_size"] <= zip_engine.MAX_ENTRY_UNCOMPRESSED for entry in result["entries"])


# ------------------------------------------------------------------
# Risk factor
# ------------------------------------------------------------------

def test_calculate_risk_adds_zip_factors():
    from modules.risk import (
        calculate_risk,
        ZIP_TRAVERSAL_POINTS,
        ZIP_BOMB_POINTS,
        ZIP_EXECUTABLE_POINTS,
        ZIP_SCRIPT_POINTS,
    )
    baseline = calculate_risk(False, {"status": "not_selected"}, "NORMAL", [], None, iocs={})
    compact = {"findings": {
        "traversal_attempt": True,
        "high_compression_ratio": True,
        "embedded_executable": True,
        "suspicious_script": True,
        "unsafe_name": True,
    }}
    flagged = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        zip_analysis=compact,
    )
    assert flagged["score"] == baseline["score"] + (
        ZIP_TRAVERSAL_POINTS + ZIP_BOMB_POINTS + ZIP_EXECUTABLE_POINTS + ZIP_SCRIPT_POINTS
    )
    assert sum(1 for f in flagged["factors"] if f.startswith("Archive (ZIP):")) == 4


def test_calculate_risk_zip_clean_adds_nothing():
    from modules.risk import calculate_risk
    result = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        zip_analysis={"findings": {
            "traversal_attempt": False, "high_compression_ratio": False,
            "embedded_executable": False, "suspicious_script": False, "unsafe_name": False,
        }},
    )
    assert result["score"] == 0
    assert not any(f.startswith("Archive (ZIP):") for f in result["factors"])


# ------------------------------------------------------------------
# Pipeline (full analyzer)
# ------------------------------------------------------------------

def _zip_pipeline_config(tmp_path, **overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": False, "ioc_extract": False,
        "entropy": False, "magic_numbers": True, "pe_analysis": False,
        "deobfuscation": False, "fuzzy": False, "zip": True, "yara": False,
        "gerar_report": True, "report_format": "json", "output_dir": str(tmp_path / "reports"),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }
    config.update(overrides)
    return config


def test_pipeline_zip_flags_and_risk(tmp_path):
    from analyzer import analyze_file

    payload = _build_zip([{"name": "drop.scr", "data": MZ_BYTES * 8}])
    sample = tmp_path / "bundle.zip"
    sample.write_bytes(payload)
    result = analyze_file(str(sample), _zip_pipeline_config(tmp_path), show_details=False)
    assert result["success"] is True
    zip_result = result["details"]["zip"]
    assert zip_result["findings"]["embedded_executable"] is True
    assert result["risk"]["score"] >= 10
    assert any(f.startswith("Archive (ZIP):") for f in result["risk"]["factors"])


def test_pipeline_zip_disabled_is_absent(tmp_path):
    from analyzer import analyze_file

    sample = tmp_path / "bundle.zip"
    sample.write_bytes(_build_zip([{"name": "readme.txt", "data": b"hi"}]))
    result = analyze_file(str(sample), _zip_pipeline_config(tmp_path, zip=False), show_details=False)
    assert result["success"] is True
    assert result["details"]["zip"] is None


def test_pipeline_plain_file_zip_gate_is_no_data(tmp_path):
    from analyzer import analyze_file

    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"nothing special here")
    result = analyze_file(str(sample), _zip_pipeline_config(tmp_path), show_details=False)
    assert result["success"] is True
    assert result["details"]["zip"]["status"] == "no_data"
    assert result["risk"]["score"] == 0