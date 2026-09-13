"""Tests for report generation, CSV-injection hardening (S1) and HTML escaping."""

import csv
import json
import os

from modules import reports
from modules.reports import _sanitize_csv_value, clear_history, save_batch_summary, save_report


def _config(output_dir, report_format="all"):
    return {
        "blacklist": True, "virustotal": False, "strings": True, "ioc_extract": False,
        "entropy": True, "magic_numbers": True, "pe_analysis": False,
        "gerar_report": True, "report_format": report_format, "output_dir": output_dir,
    }


def _risk(score=0, level="Low", factors=None):
    return {"score": score, "level": level, "factors": factors or ["No risk indicators were detected"]}


def _report_args(filepath, config, **overrides):
    args = dict(
        filepath=filepath, kb_size=0.5, file_hash="a" * 64, result_vt={"status": "not_selected"},
        alerts=[], all_strings=[], detected_bl=False, config_choices=config,
        entropy_score=1.0, entropy_status="NORMAL", real_type="Text", magic_alert=None,
        risk=_risk(), analysis_duration=0.123, iocs={},
        packer_analysis={"detected": False, "packers": {}},
        pe_analysis={"status": "not_executed", "sections": []},
        file_type_analysis={"declared_extension": ".txt", "detected_type": "Text",
                            "compatibility": "Compatible", "compatible": True, "alert": None},
        engine_times={},
    )
    args.update(overrides)
    return args


def test_sanitize_csv_value():
    assert _sanitize_csv_value("=SUM(A1)") == "'=SUM(A1)"
    assert _sanitize_csv_value("+CMD") == "'+CMD"
    assert _sanitize_csv_value("-1") == "'-1"
    assert _sanitize_csv_value("@import") == "'@import"
    assert _sanitize_csv_value("\tpayload") == "'\tpayload"
    assert _sanitize_csv_value("\rpayload") == "'\rpayload"
    assert _sanitize_csv_value("\npayload") == "'\npayload"
    assert _sanitize_csv_value("plain name.exe") == "plain name.exe"
    assert _sanitize_csv_value(42) == 42
    assert _sanitize_csv_value("") == ""


def test_save_report_all_formats(tmp_path):
    target = tmp_path / "=evil.txt"
    target.write_text("hello")
    config = _config(str(tmp_path))
    report_path = save_report(**_report_args(str(target), config))
    assert report_path.endswith(".json")
    for extension in (".json", ".csv", ".html"):
        assert any(name.endswith(extension) for name in os.listdir(tmp_path))


def test_save_report_csv_cell_sanitized(tmp_path):
    target = tmp_path / "=evil.txt"
    target.write_text("hello")
    config = _config(str(tmp_path))
    save_report(**_report_args(str(target), config))
    csv_file = next(name for name in os.listdir(tmp_path) if name.endswith(".csv"))
    with open(str(tmp_path / csv_file), encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["file_name"] == "'=evil.txt"


def test_save_report_html_escapes_sample_controlled_content(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    config = _config(str(tmp_path))
    risk = _risk(score=55, level="High", factors=["<script>alert('xss')</script>"])
    save_report(**_report_args(str(target), config, risk=risk,
                                alerts=["payload <img src=x onerror=alert(1)>"]))
    html_file = next(name for name in os.listdir(tmp_path) if name.endswith(".html"))
    content = (tmp_path / html_file).read_text(encoding="utf-8")
    assert "<script>alert" not in content
    assert "&lt;script&gt;" in content
    assert "&lt;img" in content


def test_save_report_single_format_returns_correct_path(tmp_path):
    target = tmp_path / "only.html.txt"
    target.write_text("x")
    config = _config(str(tmp_path), report_format="html")
    path = save_report(**_report_args(str(target), config))
    assert path.endswith(".html")
    assert not any(name.endswith(".json") for name in os.listdir(tmp_path))


def test_save_batch_summary_aggregates(tmp_path):
    results = [
        {"file": "a", "risk_level": "Low", "success": True, "report_generated": False},
        {"file": "b", "risk_level": "High", "success": True, "report_generated": True},
        {"file": "bad", "success": False, "error": "boom"},
    ]
    summary_path = save_batch_summary(str(tmp_path), results, 1.5, reports_folder=str(tmp_path))
    with open(summary_path, encoding="utf-8") as handle:
        summary = json.load(handle)
    assert summary["files_found"] == 3
    assert summary["files_analyzed"] == 2
    assert summary["files_failed"] == 1
    assert summary["reports_generated"] == 1
    assert summary["reports_skipped_by_risk"] == 1
    assert summary["risk_levels"] == {"Low": 1, "High": 1, "Unknown": 1}
    assert summary["duration_seconds"] == 1.5


def test_clear_history_deletes_reports(tmp_path):
    for name in ("a.json", "b.csv", "c.html", "batch_summary_x.json"):
        (tmp_path / name).write_text("{}")
    result = clear_history(str(tmp_path), include_cache=False)
    assert result["deleted"] == 4
    assert list(tmp_path.iterdir()) == []


def test_clear_history_include_cache(tmp_path):
    (tmp_path / "report.json").write_text("{}")
    cache_path = tmp_path / ".cerberus-cache.sqlite3"
    cache_path.write_bytes(b"sqlite")
    result = clear_history(str(tmp_path), include_cache=True)
    assert result["deleted"] == 2
    assert result["cache_cleared"] is True


def test_clear_history_missing_folder():
    result = clear_history("C:\\definitely\\missing\\folder", include_cache=True)
    assert result == {"deleted": 0, "errors": [], "cache_cleared": False}