"""Tests for the optional YARA rule engine.

The engine degrades when ``yara-python`` is not installed (local runs on
Python 3.14), so every YARA-dependent test is gated on ``NEEDS_YARA`` while the
degradation path itself is always exercised.
"""

import os

import pytest

from modules import yara_engine
from modules.yara_engine import scan_yara

NEEDS_YARA = pytest.mark.skipif(
    yara_engine.yara is None, reason="yara-python not installed (requirements-yara.txt)"
)

MARKER_RULE = """\
rule cerberus_test_rule: test_tag {
    strings:
        $a = "CERBERUS-MARKER"
    condition:
        $a
}
"""


def _write_rules(rules_dir, source=MARKER_RULE, name="test_rules.yar"):
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_path = rules_dir / name
    rule_path.write_text(source)
    return rule_path


def _target(root, content="CERBERUS-MARKER payload", name="sample.bin"):
    target = root / name
    target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return str(target)


def _config(rules_dir):
    return {"yara": True, "yara_rules_dir": str(rules_dir), "yara_timeout": 2.0}


def test_missing_lib_degrades_gracefully(tmp_path, monkeypatch):
    monkeypatch.setattr("modules.yara_engine.yara", None)
    result = scan_yara(str(tmp_path / "anything.bin"), {"yara_timeout": 1})
    assert result["available"] is False
    assert result["match_count"] == 0
    assert result["matches"] == []
    assert "yara-python" in result["error"]


@NEEDS_YARA
def test_missing_rules_dir_returns_empty(tmp_path):
    empty = tmp_path / "no_rules_here"
    result = scan_yara(_target(tmp_path), _config(empty))
    assert result["available"] is True
    assert result["match_count"] == 0
    assert result["rules_files"] == 0


@NEEDS_YARA
def test_match_is_reported_with_rule_and_tags(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir)
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["available"] is True
    assert result["match_count"] == 1
    assert result["matches"][0]["rule"] == "cerberus_test_rule"
    assert "test_tag" in result["matches"][0]["tags"]


@NEEDS_YARA
def test_no_match_on_clean_file(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir)
    result = scan_yara(_target(tmp_path, content="nothing suspicious here"), _config(rules_dir))
    assert result["match_count"] == 0


@NEEDS_YARA
def test_broken_rule_file_does_not_poison_other_rules(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir, name="good.yar")
    bad_path = _write_rules(
        rules_dir,
        name="bad.yar",
        source="rule broken { strings: $a = \"unterminated",
    )
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["match_count"] == 1
    assert any("bad.yar" in message for message in result["compile_errors"])


@NEEDS_YARA
def test_rules_dir_can_be_taken_from_config(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir)
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["rules_dir"] == str(rules_dir)


@NEEDS_YARA
def test_cache_is_invalidated_when_rules_change(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir)
    assert scan_yara(_target(tmp_path), _config(rules_dir))["match_count"] == 1

    _write_rules(rules_dir, name="other.yar", source=(
        "rule cerberus_other { strings: $b = \"DIFFERENT-MARKER\" condition: $b }\n"
    ))
    result = scan_yara(_target(tmp_path, content="DIFFERENT-MARKER"), _config(rules_dir))
    assert result["match_count"] == 1
    assert result["matches"][0]["rule"] == "cerberus_other"


def test_analysis_pipeline_runs_yara_hermetically(tmp_path):
    from analyzer import analyze_file

    report_dir = tmp_path / "reports"
    _write_rules(tmp_path / "rules")
    config = {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": False,
        "entropy": False, "magic_numbers": False, "pe_analysis": False, "yara": True,
        "gerar_report": True, "report_format": "json", "output_dir": str(report_dir),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True, "yara_rules_dir": str(tmp_path / "rules"),
    }
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"CERBERUS-MARKER")
    result = analyze_file(str(sample), config, show_details=False)
    assert result["success"] is True
    yara_result = result["details"]["yara"]
    assert yara_result["available"] in (True, False)
    assert "match_count" in yara_result
    if yara_result["available"]:
        assert yara_result["match_count"] == 1
    else:
        assert yara_result["match_count"] == 0


@NEEDS_YARA
def test_yara_matches_increase_risk(tmp_path):
    from analyzer import analyze_file

    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir)
    report_dir = tmp_path / "reports"
    config = {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": False,
        "entropy": False, "magic_numbers": False, "pe_analysis": False, "yara": True,
        "gerar_report": True, "report_format": "json", "output_dir": str(report_dir),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True, "yara_rules_dir": str(rules_dir),
    }
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"CERBERUS-MARKER")
    result = analyze_file(str(sample), config, show_details=False)
    assert result["success"] is True
    risk = result["risk"]
    assert risk["score"] >= 10
    assert any("YARA" in factor for factor in risk["factors"])


def test_scan_yara_is_importable_without_lib():
    assert callable(scan_yara)
    assert isinstance(yara_engine.YARA_TIMEOUT_DEFAULT_SECONDS, float)


class _FakeYaraError(Exception):
    pass


class _FakeMatch:
    def __init__(self, rule, tags=("fake_tag",), namespace="default"):
        self.rule = rule
        self.tags = tags
        self.namespace = namespace


class _FakeRules:
    def __init__(self, matches):
        self._matches = matches

    def match(self, filepath=None, timeout=None):
        return list(self._matches)


class _FakeYara:
    """Stand-in for the yara-python API, keyed off rule file names."""

    Error = _FakeYaraError

    def compile(self, path):
        name = os.path.basename(str(path))
        stem = os.path.splitext(name)[0]
        if "bad" in stem:
            raise _FakeYaraError("syntax error in rule file")
        matches = [_FakeMatch(stem)] if "match" in stem else []
        if "timeout" in stem:
            return _TimeoutRules()
        return _FakeRules(matches)


class _TimeoutRules(_FakeRules):
    def __init__(self):
        super().__init__([])

    def match(self, filepath=None, timeout=None):
        raise _FakeYaraError("match timeout")


@pytest.fixture
def fake_yara(monkeypatch):
    monkeypatch.setattr("modules.yara_engine.yara", _FakeYara())
    return monkeypatch


def test_fake_lib_match_reports_rule_tags_namespace(tmp_path, fake_yara):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir, source="rule placeholder { condition: false }", name="match_first.yar")
    (rules_dir / "quiet.yar").write_text("rule placeholder { condition: false }")
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["available"] is True
    assert result["match_count"] == 1
    assert result["matches"][0]["rule"] == "match_first"
    assert result["matches"][0]["tags"] == ["fake_tag"]
    assert result["matches"][0]["namespace"] == "default"
    assert result["rules_files"] == 2


def test_fake_lib_compile_error_does_not_poison(tmp_path, fake_yara):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir, name="match_ok.yar")
    (rules_dir / "bad_rule.yar").write_text("rule placeholder { strings: $a = \"x\"")
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["match_count"] == 1
    assert any("bad_rule.yar" in message for message in result["compile_errors"])


def test_fake_lib_timeout_is_recorded_not_fatal(tmp_path, fake_yara):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "timeout_rule.yar").write_text("rule placeholder { condition: true }")
    result = scan_yara(_target(tmp_path), _config(rules_dir))
    assert result["available"] is True
    assert result["match_count"] == 0
    assert any("timeout" in message.lower() for message in result["compile_errors"])