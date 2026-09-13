"""Tests for the persistent SQLite analysis cache."""

import os

from modules.analysis_cache import AnalysisCache


def _config(**overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": True,
        "entropy": True, "magic_numbers": True, "pe_analysis": False,
        "max_file_size": 0, "cache_enabled": True,
    }
    config.update(overrides)
    return config


def test_miss_then_hit_roundtrip(tmp_path):
    filepath = tmp_path / "cached.bin"
    filepath.write_bytes(b"some bytes")
    cache = AnalysisCache(str(tmp_path), analyzer_version="test")
    assert cache.get(str(filepath), _config()) is None
    result = {"file": "cached.bin", "risk_score": 30}
    cache.put(str(filepath), _config(), result)
    hit = cache.get(str(filepath), _config())
    assert hit == {**result, "cache_hit": True}
    cache.close()


def test_key_changes_when_config_changes(tmp_path):
    filepath = tmp_path / "cfg.bin"
    filepath.write_bytes(b"data")
    cache = AnalysisCache(str(tmp_path), analyzer_version="test")
    key_a = cache.key_for(str(filepath), _config(blacklist=True))[0]
    key_b = cache.key_for(str(filepath), _config(blacklist=False))[0]
    assert key_a != key_b
    key_same = cache.key_for(str(filepath), _config(blacklist=True))[0]
    assert key_a == key_same
    cache.close()


def test_key_changes_when_file_changes(tmp_path):
    filepath = tmp_path / "content.bin"
    filepath.write_bytes(b"small")
    cache = AnalysisCache(str(tmp_path), analyzer_version="test")
    key_a = cache.key_for(str(filepath), _config())[0]
    filepath.write_bytes(b"a different and much longer content")
    key_b = cache.key_for(str(filepath), _config())[0]
    assert key_a != key_b
    cache.close()


def test_close_releases_connections(tmp_path):
    filepath = tmp_path / "close.bin"
    filepath.write_bytes(b"x")
    cache = AnalysisCache(str(tmp_path), analyzer_version="test")
    cache.key_for(str(filepath), _config())
    cache.close()
    assert not cache._connections
    cache.close()  # idempotent


def test_cache_file_is_created(tmp_path):
    AnalysisCache(str(tmp_path)).close()
    assert os.path.exists(str(tmp_path / ".cerberus-cache.sqlite3"))