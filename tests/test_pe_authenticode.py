"""Tests for the stdlib Authenticode engine (Phase 2.5)."""

import pytest

from modules import pe_authenticode
from modules.pe_authenticode import analyze_authenticode


# ------------------------------------------------------------------
# DER helpers (build a minimal PKCS#7 SignedData wrapping an X.509 cert)
# ------------------------------------------------------------------

def _tlv(tag, payload):
    if len(payload) < 0x80:
        return bytes([tag, len(payload)]) + payload
    if len(payload) < 0x100:
        return bytes([tag, 0x81, len(payload)]) + payload
    return bytes([tag, 0x82, (len(payload) >> 8) & 0xFF, len(payload) & 0xFF]) + payload


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _set_of(*parts):
    return _tlv(0x31, b"".join(parts))


def _integer(value):
    return _tlv(0x02, value)


def _null():
    return _tlv(0x05, b"")


def _encode_oid(*arcs):
    chunks = []
    for arc in arcs[2:]:
        group = [arc & 0x7F]
        arc >>= 7
        while arc:
            group.append(0x80 | (arc & 0x7F))
            arc >>= 7
        chunks.extend(reversed(group))
    return bytes([arcs[0] * 40 + arcs[1]]) + bytes(chunks)


def _oid(*arcs):
    return _tlv(0x06, _encode_oid(*arcs))


def _utctime_stub():
    return _tlv(0x17, b"240101000000Z")


def _name(attributes):
    rdns = []
    for oid_arcs, value in attributes:
        rdns.append(_set_of(_seq(_oid(*oid_arcs), _tlv(0x0C, value.encode("utf-8")))))
    return _seq(*rdns)


_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)
_SIGNED_DATA_OID = (1, 2, 840, 113549, 1, 7, 2)


def _build_certificate():
    issuer = _name([((2, 5, 4, 3), "Test Issuer"), ((2, 5, 4, 10), "Acme Root")])
    subject = _name([((2, 5, 4, 3), "Test Subject"), ((2, 5, 4, 11), "Cerberus")])
    sig_alg = _seq(_oid(*_SHA256), _null())
    tbscert = _seq(
        b"\xa0\x03\x02\x01\x02",                 # version [0] INTEGER 2
        _integer(b"\x01\x02\x03"),                # serial number
        sig_alg,
        issuer,
        _seq(_utctime_stub(), _utctime_stub()),   # validity
        subject,
        _seq(b"\x30\x0d\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x03\x81\x02\x00\x01"),
    )
    return _seq(tbscert, sig_alg, _tlv(0x03, b"\x00\x00"))


def _build_signed_data(certificate):
    return _seq(
        _integer(b"\x01"),
        _set_of(_seq(_oid(*_SHA256), _null())),
        _seq(_oid(1, 2, 840, 113549, 1, 7, 1)),
        _tlv(0xA0, certificate),  # [0] IMPLICIT SET OF Certificate
    )


def _build_pkcs7_payload():
    certificate = _build_certificate()
    signed_data = _build_signed_data(certificate)
    return _seq(_oid(*_SIGNED_DATA_OID), _tlv(0xA0, signed_data))


# ------------------------------------------------------------------
# PE builder
# ------------------------------------------------------------------

SECURITY_OFFSET = 0x400


def _win_cert(payload, revision=0x0200, cert_type=0x0002, length_override=None):
    length = 8 + len(payload) if length_override is None else length_override
    return (
        length.to_bytes(4, "little")
        + revision.to_bytes(2, "little")
        + cert_type.to_bytes(2, "little")
        + payload
    )


def _build_pe(security=None, dir_size=None, magic=0x10B, num_dirs=16):
    """Build a minimal PE (PE32 or PE32+) with an optional Authenticode block."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = e_lfanew.to_bytes(4, "little")

    file_header = bytearray(20)
    file_header[0:2] = (0x14C).to_bytes(2, "little")
    file_header[16:18] = (0xE0).to_bytes(2, "little")
    file_header[18:20] = (0x0102).to_bytes(2, "little")

    optional = bytearray(0xE0)
    optional[0:2] = magic.to_bytes(2, "little")
    data_dir_off = 96 if magic == 0x10B else 116  # fixed 8-byte entries
    num_dir_pos = 92 if magic == 0x10B else 112
    optional[num_dir_pos:num_dir_pos + 4] = num_dirs.to_bytes(4, "little")
    if security is not None:
        entry = data_dir_off + 4 * 8  # Security directory is index 4
        optional[entry:entry + 4] = SECURITY_OFFSET.to_bytes(4, "little")
        optional[entry + 4:entry + 8] = (dir_size if dir_size is not None else len(security)).to_bytes(4, "little")

    content = bytes(dos) + b"PE\0\0" + bytes(file_header) + bytes(optional)
    content = content.ljust(SECURITY_OFFSET, b"\x00")
    if security is not None:
        content += security
    return content


def _write(tmp_path, name, data):
    target = tmp_path / name
    target.write_bytes(data)
    return str(target)


# ------------------------------------------------------------------
# Scans
# ------------------------------------------------------------------

def test_not_pe_returns_no_data(tmp_path):
    result = analyze_authenticode(_write(tmp_path, "plain.txt", b"text file, not a PE"))
    assert result["status"] == "no_data"
    assert result["is_pe"] is False
    assert result["signed"] is False


def test_pe_without_signature_is_unsigned(tmp_path):
    result = analyze_authenticode(_write(tmp_path, "unsigned.exe", _build_pe()))
    assert result["status"] == "unsigned"
    assert result["is_pe"] is True
    assert result["signed"] is False


def test_pe32plus_signed(tmp_path):
    payload = _build_pkcs7_payload()
    block = _win_cert(payload)
    result = analyze_authenticode(_write(tmp_path, "signed64.exe", _build_pe(block, magic=0x20B)))
    assert result["status"] == "signed"
    assert "Test Subject" in (result["subject"] or "")


def test_unknown_optional_header_magic_is_unsigned(tmp_path):
    result = analyze_authenticode(_write(tmp_path, "weird.exe", _build_pe(magic=0x9999)))
    assert result["status"] == "unsigned"
    assert result["is_pe"] is True


def test_security_index_out_of_range_is_unsigned(tmp_path):
    result = analyze_authenticode(_write(tmp_path, "fewdirs.exe", _build_pe(num_dirs=4)))
    assert result["status"] == "unsigned"
    assert result["signed"] is False


def test_truncated_pe_header_is_unsigned(tmp_path):
    truncated = bytearray(b"MZ" + b"\x00" * 0x3E)
    truncated[0x3C:0x40] = (0x1000).to_bytes(4, "little")
    result = analyze_authenticode(_write(tmp_path, "cut.exe", bytes(truncated)))
    assert result["status"] == "unsigned"
    assert result["is_pe"] is True


def test_signed_pe_extracts_subject_issuer(tmp_path):
    payload = _build_pkcs7_payload()
    block = _win_cert(payload)
    result = analyze_authenticode(_write(tmp_path, "signed.exe", _build_pe(block)))
    assert result["status"] == "signed"
    assert result["signed"] is True
    assert result["block_size"] == len(payload) + 8
    assert result["revision"] == "0x200"
    assert result["cert_type"] == "PKCS#7 SignedData"
    assert "Test Subject" in result["subject"]
    assert "Cerberus" in result["subject"]
    assert "Test Issuer" in result["issuer"]
    assert result["issuer"].startswith("CN=Test Issuer")
    assert result["notes"] == []


def test_filepath_and_buffer_paths_agree(tmp_path):
    payload = _build_pkcs7_payload()
    block = _win_cert(payload)
    path = _write(tmp_path, "signed.exe", _build_pe(block))
    with open(path, "rb") as handle:
        content = handle.read()
    assert analyze_authenticode(path) == analyze_authenticode(path, content=content)


def test_garbage_certificate_payload_is_safe(tmp_path):
    block = _win_cert(b"\xde\xad\xbe\xef" * 32)
    result = analyze_authenticode(_write(tmp_path, "garbage.exe", _build_pe(block)))
    assert result["signed"] is True
    assert result["subject"] is None
    assert result["issuer"] is None
    assert result["status"] == "signed"


def test_bad_der_length_does_not_crash(tmp_path):
    block = _win_cert(b"\x30\x82\xff\xff\xff\xff")
    result = analyze_authenticode(_write(tmp_path, "badlen.exe", _build_pe(block)))
    assert result["signed"] is True
    assert result["subject"] is None
    assert result["issuer"] is None


def test_printable_string_name_is_rendered(tmp_path):
    # Rebuild a certificate whose subject uses PrintableString (0x13).
    printable_subject = _seq(_set_of(_seq(_oid(2, 5, 4, 3), _tlv(0x13, b"Print Co"))))
    issuer = _name([((2, 5, 4, 3), "Issuer P")])
    sig_alg = _seq(_oid(*_SHA256), _null())
    tbscert = _seq(
        b"\xa0\x03\x02\x01\x02",
        _integer(b"\x09"),
        sig_alg,
        issuer,
        _seq(_utctime_stub(), _utctime_stub()),
        printable_subject,
        _seq(b"\x30\x0d\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x03\x81\x02\x00\x01"),
    )
    certificate = _seq(tbscert, sig_alg, _tlv(0x03, b"\x00\x00"))
    signed_data = _seq(
        _integer(b"\x01"),
        _set_of(_seq(_oid(*_SHA256), _null())),
        _seq(_oid(1, 2, 840, 113549, 1, 7, 1)),
        _tlv(0xA0, certificate),
    )
    payload = _seq(_oid(*_SIGNED_DATA_OID), _tlv(0xA0, signed_data))
    result = analyze_authenticode(_write(tmp_path, "print.exe", _build_pe(_win_cert(payload))))
    assert result["status"] == "signed"
    assert "CN=Print Co" in (result["subject"] or "")


# ------------------------------------------------------------------
# Malformed signatures
# ------------------------------------------------------------------

def test_invalid_win_cert_length_flagged(tmp_path):
    block = _win_cert(b"\x00" * 16, length_override=6)
    result = analyze_authenticode(_write(tmp_path, "odd.exe", _build_pe(block)))
    assert result["notes"]
    assert any("length" in note for note in result["notes"])


def test_unexpected_revision_flagged(tmp_path):
    block = _win_cert(_build_pkcs7_payload(), revision=0x0100)
    result = analyze_authenticode(_write(tmp_path, "old.exe", _build_pe(block)))
    assert any("revision" in note for note in result["notes"])
    assert result["subject"] is None


def test_truncated_security_directory_flagged(tmp_path):
    dir_claim = b"\x00" * 4  # claimed size 4, but the block needs >= 8
    result = analyze_authenticode(_write(tmp_path, "t.exe", _build_pe(dir_claim, dir_size=4)))
    assert result["status"] == "error"
    assert any("malformed" in note for note in result["notes"])


# ------------------------------------------------------------------
# Risk factor
# ------------------------------------------------------------------

def test_calculate_risk_authenticode_notes():
    from modules.risk import calculate_risk, AUTHENTICODE_MALFORMED_POINTS
    baseline = calculate_risk(False, {"status": "not_selected"}, "NORMAL", [], None, iocs={})
    flagged = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        authenticode_analysis={"notes": ["invalid WIN_CERTIFICATE length"]},
    )
    assert flagged["score"] == baseline["score"] + AUTHENTICODE_MALFORMED_POINTS
    assert any(f.startswith("Authenticode:") and "(+5)" in f for f in flagged["factors"])


def test_calculate_risk_authenticode_clean_adds_nothing():
    from modules.risk import calculate_risk
    result = calculate_risk(
        False, {"status": "not_selected"}, "NORMAL", [], None, iocs={},
        authenticode_analysis={"notes": []},
    )
    assert result["score"] == 0
    assert not any(f.startswith("Authenticode:") for f in result["factors"])


# ------------------------------------------------------------------
# Pipeline (full analyzer)
# ------------------------------------------------------------------

def _auth_pipeline_config(tmp_path, **overrides):
    config = {
        "blacklist": True, "virustotal": False, "strings": False, "ioc_extract": False,
        "entropy": False, "magic_numbers": True, "pe_analysis": False,
        "deobfuscation": False, "fuzzy": False, "zip": False, "authenticode": True, "yara": False,
        "gerar_report": True, "report_format": "json", "output_dir": str(tmp_path / "reports"),
        "quiet": True, "workers": 1, "cache_enabled": False, "max_file_size": 0,
        "skip_reparse_points": True,
    }
    config.update(overrides)
    return config


def test_pipeline_signed_pe(tmp_path):
    from analyzer import analyze_file

    sample = tmp_path / "signed.exe"
    sample.write_bytes(_build_pe(_win_cert(_build_pkcs7_payload())))
    result = analyze_file(str(sample), _auth_pipeline_config(tmp_path), show_details=False)
    assert result["success"] is True
    auth = result["details"]["authenticode"]
    assert auth["signed"] is True
    assert "Test Subject" in (auth["subject"] or "")
    assert result["risk"]["score"] == 0  # a valid signature adds no points


def test_pipeline_malformed_signature_adds_risk(tmp_path):
    from analyzer import analyze_file

    sample = tmp_path / "odd.exe"
    sample.write_bytes(_build_pe(_win_cert(b"\x00" * 16, length_override=6)))
    result = analyze_file(str(sample), _auth_pipeline_config(tmp_path), show_details=False)
    auth = result["details"]["authenticode"]
    assert auth["notes"]
    assert any(f.startswith("Authenticode:") for f in result["risk"]["factors"])


def test_pipeline_authenticode_disabled_is_absent(tmp_path):
    from analyzer import analyze_file

    sample = tmp_path / "signed.exe"
    sample.write_bytes(_build_pe(_win_cert(_build_pkcs7_payload())))
    result = analyze_file(str(sample), _auth_pipeline_config(tmp_path, authenticode=False), show_details=False)
    assert result["success"] is True
    assert result["details"]["authenticode"] is None