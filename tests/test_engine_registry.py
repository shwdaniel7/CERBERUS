"""Tests for the lightweight engine registry (Phase 1 plugin path)."""

import pytest

from modules import engine_registry
from modules.engine_registry import Engine


def test_registry_has_all_core_engines():
    names = [engine.name for engine in engine_registry.iter_engines()]
    assert names == ["blacklist", "virustotal", "magic_numbers", "entropy",
                     "strings", "pe_analysis", "ioc_extract", "deobfuscation", "fuzzy", "yara"]


def test_engine_fields_are_consistent():
    labels = []
    for engine in engine_registry.iter_engines():
        assert engine.name
        assert engine.label
        assert engine.config_key == engine.name
        assert not engine.config_key.startswith("_")
        labels.append(engine.label)
    assert len(labels) == len(set(labels))


def test_get_engine():
    assert engine_registry.get_engine("strings").label == "Strings"
    assert engine_registry.get_engine("missing") is None


def test_config_keys():
    assert engine_registry.config_keys() == {
        "blacklist", "virustotal", "magic_numbers", "entropy", "strings",
        "pe_analysis", "ioc_extract", "deobfuscation", "fuzzy", "yara",
    }


def test_engine_defaults_match_settings():
    from modules.settings_store import DEFAULT_SETTINGS
    defaults = engine_registry.engine_defaults()
    for name, default in defaults.items():
        assert DEFAULT_SETTINGS[name] is default


def test_toggles_shape():
    toggles = engine_registry.toggles()
    assert all(isinstance(item, tuple) and len(item) == 2 for item in toggles)
    names = {name for _, name in toggles}
    assert names == engine_registry.config_keys()
    assert toggles[0] == ("Local blacklist", "blacklist")


def test_enabled_names():
    config = {"blacklist": True, "virustotal": False, "magic_numbers": True,
              "entropy": True, "strings": False, "pe_analysis": True, "ioc_extract": False}
    assert engine_registry.enabled_names(config) == ["blacklist", "magic_numbers", "entropy", "pe_analysis"]


def test_validate_config_preserves_unknown_keys_and_coerces():
    config = engine_registry.validate_config({
        "blacklist": 0, "strings": "yes", "pe_analysis": 1, "_cache": object(), "extra": 1,
    })
    assert config["blacklist"] is False
    assert config["strings"] is True
    assert config["pe_analysis"] is True
    assert "_cache" in config and config["extra"] == 1
    assert config.keys() == engine_registry.config_keys() | {"_cache", "extra"}


def test_register_and_unregister_plugin_hook():
    extra = Engine("ext_test", "Extra test engine", "ext_test", optional=False, description="plugin hook demo")
    engine_registry.register(extra)
    assert engine_registry.get_engine("ext_test") == extra
    engine_registry.unregister("ext_test")
    assert engine_registry.get_engine("ext_test") is None
    assert [e.name for e in engine_registry.iter_engines()] == [
        "blacklist", "virustotal", "magic_numbers", "entropy", "strings",
        "pe_analysis", "ioc_extract", "deobfuscation", "fuzzy", "yara",
    ]


def test_register_duplicate_and_invalid_raise():
    duplicate = Engine("strings", "dup", "strings")
    with pytest.raises(ValueError, match="already registered"):
        engine_registry.register(duplicate)
    with pytest.raises(TypeError):
        engine_registry.register("not-an-engine")
    with pytest.raises(KeyError):
        engine_registry.unregister("does-not-exist")