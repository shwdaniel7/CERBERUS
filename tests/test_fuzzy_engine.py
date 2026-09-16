"""Tests for the fuzzy TLSH similarity engine (Phase 2.3)."""

import pytest

from modules import fuzzy_engine
from modules.fuzzy_engine import (
    load_corpus,
    scan_similarity,
    similarity_pct,
    _compute_tlsh,
    FUZZY_MATCH_DISTANCE,
    FUZZY_EXACT_DISTANCE,
    MAX_TLSH_DISTANCE,
)


FAKE_DIGEST = "4" * 70  # valid even-length hex string

NEEDS_TLSH = pytest.mark.skipif(
    not fuzzy_engine.tlsh_available(), reason="Requires py-tlsh"
)


class _FakeTlsh:
    """Minimal fake mimicking the py-tlsh incremental API."""

    def __init__(self):
        self._data = b""

    def update(self, data):
        self._data += data
        return self

    def final(self):
        pass

    def hexdigest(self):
        return FAKE_DIGEST


class _FakeTlshError(_FakeTlsh):
    def hexdigest(self):
        raise ValueError("insufficient variation")


def _fake_diff(a, b):
    return 0 if a == b else 999


def _make_fake_diff(mapping):
    def _diff(a, b):
        return mapping.get((a, b), 999)
    return _diff


# ------------------------------------------------------------------
# Unit helpers
# ------------------------------------------------------------------

def test_tlsh_available_reflects_import():
    assert isinstance(fuzzy_engine.tlsh_available(), bool)


def test_similarity_pct_boundary_values():
    assert similarity_pct(0) == 100
    assert similarity_pct(MAX_TLSH_DISTANCE) == 0
    assert similarity_pct(MAX_TLSH_DISTANCE * 2) == 0
    assert isinstance(similarity_pct(FUZZY_EXACT_DISTANCE), int)


# ------------------------------------------------------------------
# Corpus parsing
# ------------------------------------------------------------------

def test_load_corpus_valid_entries(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(
        "# comment\n\n"
        f"{FAKE_DIGEST} label-A\n"
        f"{FAKE_DIGEST} label with spaces\n",
        encoding="utf-8",
    )
    entries = load_corpus(str(corpus))
    assert len(entries) == 2
    assert entries[0]["label"] == "label-A"
    assert entries[0]["hash"] == FAKE_DIGEST.lower()
    assert entries[1]["label"] == "label with spaces"
    assert entries[0]["source_line"] == 3


def test_load_corpus_invalid_hex_skipped(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(
        "g" * 70 + " bad-hex\n"          # non-hex characters
        + "a" * 69 + " odd-length\n"      # odd length → not hex
        + "  \n"                           # blank after strip
        + "# full-line comment\n",
        encoding="utf-8",
    )
    assert load_corpus(str(corpus)) == []


def test_load_corpus_missing_file(tmp_path):
    assert load_corpus(str(tmp_path / "nonexistent.txt")) == []


# ------------------------------------------------------------------
# scan_similarity — degraded / edge cases
# ------------------------------------------------------------------

def test_scan_degrade_when_lib_missing(monkeypatch):
    monkeypatch.setattr(fuzzy_engine, "tlsh", None)
    result = scan_similarity("/fake/file", content=b"data")
    assert result["available"] is False
    assert result["status"] == "unavailable"
    assert result["match_count"] == 0
    assert result["file_hash"] is None
    assert result["nearest_distance"] is None


def test_scan_no_hash_when_file_lacks_variation(monkeypatch, tmp_path):
    monkeypatch.setattr(fuzzy_engine, "tlsh", type("FakeMod", (), {"Tlsh": _FakeTlshError, "diff": _fake_diff}))
    result = scan_similarity("/fake", content=b"data")
    assert result["available"] is True
    assert result["status"] == "no_hash"
    assert result["file_hash"] is None
    assert result["match_count"] == 0


# ------------------------------------------------------------------
# scan_similarity — fake lib
# ------------------------------------------------------------------

def _fake_tlsh_module():
    import types
    mod = types.ModuleType("tlsh_fake")
    mod.Tlsh = _FakeTlsh
    mod.diff = _fake_diff
    return mod


def test_scan_match_with_fake_lib(tmp_path, monkeypatch):
    monkeypatch.setattr(fuzzy_engine, "tlsh", _fake_tlsh_module())
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(f"{FAKE_DIGEST} known-malware\n", encoding="utf-8")
    result = scan_similarity("/fake", content=b"payload" * 50, corpus_path=str(corpus))
    assert result["available"] is True
    assert result["status"] == "matched"
    assert result["file_hash"] == FAKE_DIGEST
    assert result["match_count"] == 1
    assert result["nearest_distance"] == 0
    assert result["matches"][0]["label"] == "known-malware"
    assert result["matches"][0]["distance"] == 0
    assert result["matches"][0]["similarity"] == 100
    assert result["corpus_entries"] == 1


def test_scan_no_match(tmp_path, monkeypatch):
    monkeypatch.setattr(fuzzy_engine, "tlsh", _fake_tlsh_module())
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(f"aabb{'00' * 33} unrelated\n", encoding="utf-8")
    result = scan_similarity("/fake", content=b"payload" * 50, corpus_path=str(corpus))
    assert result["status"] == "no_match"
    assert result["match_count"] == 0
    assert result["nearest_distance"] is None


def test_scan_distance_threshold_includes_boundary(tmp_path, monkeypatch):
    mod = _fake_tlsh_module()
    boundary_digest = "aabb" + "00" * 33
    mapping = {(FAKE_DIGEST, boundary_digest.lower()): FUZZY_MATCH_DISTANCE}
    mod.diff = _make_fake_diff(mapping)
    monkeypatch.setattr(fuzzy_engine, "tlsh", mod)
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(f"{boundary_digest} boundary\n", encoding="utf-8")
    result = scan_similarity("/fake", content=b"x" * 60, corpus_path=str(corpus))
    assert result["match_count"] == 1
    assert result["matches"][0]["distance"] == FUZZY_MATCH_DISTANCE

    mapping[(FAKE_DIGEST, boundary_digest.lower())] = FUZZY_MATCH_DISTANCE + 1
    result2 = scan_similarity("/fake", content=b"x" * 60, corpus_path=str(corpus))
    assert result2["match_count"] == 0


def test_scan_sorted_nearest_first(tmp_path, monkeypatch):
    mod = _fake_tlsh_module()
    digest_a = "aa" + "00" * 34
    digest_b = "bb" + "00" * 34
    mapping = {
        (FAKE_DIGEST, digest_a.lower()): 5,
        (FAKE_DIGEST, digest_b.lower()): 1,
    }
    mod.diff = _make_fake_diff(mapping)
    monkeypatch.setattr(fuzzy_engine, "tlsh", mod)
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(f"{digest_a} far\n{digest_b} near\n", encoding="utf-8")
    result = scan_similarity("/fake", content=b"data" * 50, corpus_path=str(corpus))
    assert [m["label"] for m in result["matches"]] == ["near", "far"]
    assert result["nearest_distance"] == 1


# ------------------------------------------------------------------
# _compute_tlsh internals
# ------------------------------------------------------------------

def test_compute_tlsh_returns_none_on_error(monkeypatch):
    import types
    fake = types.ModuleType("tlsh_err")
    fake.Tlsh = _FakeTlshError
    fake.diff = _fake_diff
    monkeypatch.setattr(fuzzy_engine, "tlsh", fake)
    assert _compute_tlsh(b"data" * 20) is None


def test_compute_tlsh_streams_data(monkeypatch):
    """Verify that update() receives data in bounded chunks."""
    received = []

    class _CaptureTlsh:
        def update(self, data):
            received.append(len(data))
            return self
        def final(self):
            pass
        def hexdigest(self):
            return FAKE_DIGEST

    import types
    fake = types.ModuleType("tlsh_cap")
    fake.Tlsh = _CaptureTlsh
    fake.diff = _fake_diff
    monkeypatch.setattr(fuzzy_engine, "tlsh", fake)
    big = b"\x00" * (fuzzy_engine.HASH_CHUNK_SIZE * 2 + 500)
    _compute_tlsh(big)
    assert received == [fuzzy_engine.HASH_CHUNK_SIZE, fuzzy_engine.HASH_CHUNK_SIZE, 500]


# ------------------------------------------------------------------
# Risk factor
# ------------------------------------------------------------------

@NEEDS_TLSH
def test_real_lib_same_file_roundtrip(tmp_path):
    """Real py-tlsh path: identical bytes hash to distance 0; unrelated differs."""
    import tlsh as real_tlsh

    data = (b"cerberus fuzzy roundtrip sample with real variation here " * 40)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(data)
    first = scan_similarity(str(sample))
    assert first["available"] is True
    assert first["file_hash"]
    assert real_tlsh.diff(first["file_hash"], first["file_hash"]) == 0
    unrelated = tmp_path / "other.bin"
    unrelated.write_bytes(b"A" * 2000)
    other = scan_similarity(str(unrelated))
    assert real_tlsh.diff(first["file_hash"], other["file_hash"]) > 0

def test_calculate_risk_fuzzy_exact(monkeypatch):
    from modules.risk import calculate_risk, FUZZY_EXACT_POINTS
    exact = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        fuzzy_analysis={"match_count": 1, "nearest_distance": 0, "matches": [{"label": "a"}]},
    )
    baseline = calculate_risk(False, {"status": "not_selected"}, "NORMAL", [], None, iocs={})
    assert exact["score"] == baseline["score"] + FUZZY_EXACT_POINTS
    assert any("Fuzzy similarity:" in f and "(TLSH distance 0, +20)" in f for f in exact["factors"])


def test_calculate_risk_fuzzy_no_match():
    from modules.risk import calculate_risk
    result = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        fuzzy_analysis={"match_count": 0, "nearest_distance": None, "matches": []},
    )
    assert result["score"] == 0
    assert not any("Fuzzy similarity:" in f for f in result["factors"])


# ------------------------------------------------------------------
# Pipeline (full analyzer)
# ------------------------------------------------------------------

def _fuzzy_pipeline_config(tmp_path, **overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": False, "ioc_extract": False,
        "entropy": False, "magic_numbers": False, "pe_analysis": False,
        "deobfuscation": False, "fuzzy": True, "yara": False,
        "gerar_report": True, "report_format": "json", "output_dir": str(tmp_path / "reports"),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }
    config.update(overrides)
    return config


def test_pipeline_fuzzy_match(monkeypatch, tmp_path):
    from analyzer import analyze_file

    monkeypatch.setattr(fuzzy_engine, "tlsh", _fake_tlsh_module())
    corpus = tmp_path / "tlsh_corpus.txt"
    corpus.write_text(f"{FAKE_DIGEST} pipeline-label\n", encoding="utf-8")
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

    result = analyze_file(
        str(sample),
        _fuzzy_pipeline_config(tmp_path, fuzzy_corpus=str(corpus)),
        show_details=False,
    )
    assert result["success"] is True
    fuzzy = result["details"]["fuzzy"]
    assert fuzzy["available"] is True
    assert fuzzy["match_count"] == 1
    assert fuzzy["matches"][0]["label"] == "pipeline-label"
    assert result["risk"]["score"] >= 20
    assert any("Fuzzy similarity:" in f for f in result["risk"]["factors"])


def test_pipeline_fuzzy_unavailable(tmp_path):
    """Without the real TLSH lib the engine degrades and the pipeline still completes."""
    from analyzer import analyze_file

    sample = tmp_path / "plain.txt"
    sample.write_bytes(b"hello world")
    result = analyze_file(str(sample), _fuzzy_pipeline_config(tmp_path), show_details=False)
    assert result["success"] is True
    assert result["details"]["fuzzy"]["available"] is False
    assert result["risk"]["score"] == 0
