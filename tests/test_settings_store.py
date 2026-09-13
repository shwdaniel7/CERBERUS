"""Tests for the fail-safe settings store (S3)."""

import json

import pytest

from modules import settings_store


@pytest.fixture
def store(tmp_path, monkeypatch):
    target = tmp_path / "settings.json"
    monkeypatch.setattr(settings_store, "settings_path", lambda: str(target))
    return target


def test_missing_file_returns_defaults(store):
    settings = settings_store.load_settings()
    assert settings["max_file_size"] == 200 * 1024 * 1024
    assert settings["workers"] == 4
    assert settings["report_format"] == "all"
    assert settings["output_dir"] == "reports"
    assert settings["skip_reparse_points"] is True
    for name in ("blacklist", "virustotal", "strings", "ioc_extract", "entropy", "magic_numbers", "pe_analysis"):
        assert settings[name] is True


def test_save_then_load_roundtrip(store):
    settings_store.save_settings({"workers": 8, "max_file_size": 10 * 1024 * 1024})
    loaded = settings_store.load_settings()
    assert loaded["workers"] == 8
    assert loaded["max_file_size"] == 10 * 1024 * 1024


def test_corrupt_json_returns_defaults(store, capsys):
    store.write_text("{ not valid json", encoding="utf-8")
    settings = settings_store.load_settings()
    assert settings["workers"] == 4


def test_invalid_types_coerced_to_defaults(store):
    store.write_text(json.dumps({"workers": 0, "max_file_size": -5, "report_format": "pdf",
                                 "cache_enabled": "not-a-bool"}), encoding="utf-8")
    loaded = settings_store.load_settings()
    assert loaded["workers"] == 4
    assert loaded["max_file_size"] == 200 * 1024 * 1024
    assert loaded["report_format"] == "all"
    assert loaded["cache_enabled"] is True


def test_engine_toggles_accept_int_bools(store):
    store.write_text(json.dumps({"blacklist": 0, "magic_numbers": 1}), encoding="utf-8")
    loaded = settings_store.load_settings()
    assert loaded["blacklist"] is False
    assert loaded["magic_numbers"] is True


def test_unknown_keys_are_dropped_on_save(store):
    saved = settings_store.save_settings({"virustotal": False, "api_key": "should-never-persist"})
    assert "api_key" not in saved
    assert json.loads(store.read_text(encoding="utf-8")) == {  # no unknown key leaks to disk
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": True,
        "entropy": True, "magic_numbers": True, "pe_analysis": True,
        "skip_reparse_points": True, "max_file_size": 200 * 1024 * 1024,
        "workers": 4, "cache_enabled": True, "output_dir": "reports",
        "report_format": "all",
    }


def test_non_dict_json_returns_defaults(store):
    store.write_text("[1, 2, 3]", encoding="utf-8")
    assert settings_store.load_settings()["workers"] == 4


def test_settings_filename_is_at_project_root():
    assert settings_store.settings_path().endswith("settings.json")