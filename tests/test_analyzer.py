"""Integration tests for the analyzer pipeline (Phase 0/1 regressions included)."""

import hashlib
import os

import pytest

from analyzer import analyze_file, cli_config


def _full_config(output_dir, **overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": True,
        "entropy": True, "magic_numbers": True, "pe_analysis": False,
        "gerar_report": True, "report_format": "json", "output_dir": output_dir,
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }
    config.update(overrides)
    return config


@pytest.mark.integration
def test_analyze_benign_sample(tmp_path):
    sample = tmp_path / "hello.txt"
    sample.write_text("hello world, this is a plain benign file for the integration test.")
    result = analyze_file(str(sample), _full_config(str(tmp_path / "reports")), show_details=False)
    assert result["success"] is True
    assert result["risk_level"] in ("Low", "Moderate")
    assert result["path"] == str(sample)
    details = result["details"]
    assert len(details["sha256"]) == 64
    assert details["file_type"]["compatible"] is True or details["file_type"]["compatible"] is None
    assert details["size_bytes"] == sample.stat().st_size


@pytest.mark.integration
def test_analyze_exe_like_sample(tmp_path):
    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ" + b"\x90" * 512 + b"cmd.exe\npowershell\n")
    result = analyze_file(str(sample), _full_config(str(tmp_path / "reports")), show_details=False)
    assert result["success"] is True
    assert result["details"]["file_type"]["detected_type"] == "Windows Executable (EXE/DLL)"
    assert result["details"]["file_type"]["compatible"] is True
    assert result["details"]["iocs"]["powershell_commands"]
    assert result["details"]["alerts"]
    expected = hashlib.sha256(sample.read_bytes()).hexdigest()
    assert result["details"]["sha256"] == expected
    assert os.path.exists(str(tmp_path / "reports"))


def test_oversized_file_raises_fast(tmp_path):
    sample = tmp_path / "huge.bin"
    sample.write_bytes(b"x" * 64)
    with pytest.raises(ValueError, match="exceeds configured limit"):
        analyze_file(str(sample), _full_config(str(tmp_path), max_file_size=10))


def test_zero_max_file_size_means_unlimited(tmp_path):
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"x" * 32)
    result = analyze_file(str(sample), _full_config(str(tmp_path), max_file_size=0))
    assert result["success"] is True


def test_none_max_file_size_uses_default(tmp_path):
    sample = tmp_path / "default.bin"
    sample.write_bytes(b"x" * 32)
    config = _full_config(str(tmp_path))
    config["max_file_size"] = None
    result = analyze_file(str(sample), config)
    assert result["success"] is True


@pytest.mark.integration
def test_cache_roundtrip_through_analyze_file(tmp_path):
    from modules.analysis_cache import AnalysisCache
    sample = tmp_path / "cached.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 256)
    cache = AnalysisCache(str(tmp_path / "cache"), analyzer_version="test")
    config = _full_config(str(tmp_path / "reports"), cache_enabled=True, report_format="json")
    first = analyze_file(str(sample), {**config, "_cache": cache})
    assert first.get("cache_hit", False) is False
    second = analyze_file(str(sample), {**config, "_cache": cache})
    assert second["cache_hit"] is True
    assert second["path"] == str(sample)
    cache.close()


def test_cli_config_defaults(monkeypatch):
    from modules import settings_store
    monkeypatch.setattr(settings_store, "load_settings", lambda: dict(settings_store.DEFAULT_SETTINGS))

    class Args:
        quick = False
        no_virustotal = False
        report = None
        output = None
        quiet = False
        workers = None
        no_cache = False
        max_file_size = None

    config = cli_config(Args())
    assert config["max_file_size"] == settings_store.DEFAULT_SETTINGS["max_file_size"]
    assert config["workers"] == 4
    assert config["report_format"] == "all"
    assert config["output_dir"] == "reports"
    assert config["virustotal"] is True
    assert config["skip_reparse_points"] is True


def test_cli_config_quick_disables_full_engines(monkeypatch):
    from modules import settings_store
    monkeypatch.setattr(settings_store, "load_settings", lambda: dict(settings_store.DEFAULT_SETTINGS))

    class Args:
        quick = True
        no_virustotal = False
        report = None
        output = None
        quiet = False
        workers = None
        no_cache = False
        max_file_size = None

    config = cli_config(Args())
    assert config["virustotal"] is False
    assert config["strings"] is False
    assert config["entropy"] is False
    assert config["blacklist"] is True
    assert config["magic_numbers"] is True