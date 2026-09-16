"""Authenticode (PE digital signature) engine - stdlib only.

Roadmap item 5: signature **presence**, **subject/issuer**, revocation off
by default. This module locates the WIN_CERTIFICATE block bound to the PE
Security entry of the Optional Header data directory (index 4), validates its
header, and - when it is a PKCS#7 SignedData blob - extracts the signing
certificate's issuer and subject with a minimal DER walker.

Design constraints (S9):

- Zero new dependencies: the PE layout and the ASN.1 structure are parsed
  directly from the shared bounded buffer. Revocation checking is intentionally
  out of scope (offline tool), matching the roadmap.
- Bounded work: the certificate payload is capped at ``MAX_DER_TRAVERSAL`` and
  the DER walker never follows a length larger than the remaining buffer, so a
  hostile padding or fake security directory cannot cause unbounded iteration.
- Evidence, not verdict: a valid signature is reported descriptively; only a
  *malformed/truncated* signature block adds risk points, because a broken or
  oversized fake signature area is a tell-tale sign of tampering.
"""


MAX_DER_TRAVERSAL = 256 * 1024
AUTHENTICODE_REVISION = 0x0200
AUTHENTICODE_TYPE = 0x0002
SECURITY_DIRECTORY_INDEX = 4

_PE32_DATA_DIR_OFFSET = 96
_PE32_PLUS_DATA_DIR_OFFSET = 116

_OID_LABELS = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
}

_PKCS7_SIGNED_DATA_OID = bytes((
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
))


def _u16(data, offset):
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


# ------------------------------------------------------------------
# PE Security directory parsing
# ------------------------------------------------------------------

def _find_security_directory(content):
    """Return ``(offset, size)`` of the Authenticode block, or ``None``.

    ``None`` covers both "not a PE" and "PE without a security directory".
    """
    if content[:2] != b"MZ" or len(content) < 0x40:
        return None
    pe_offset = _u32(content, 0x3C)
    if pe_offset + 24 > len(content) or content[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    file_header = pe_offset + 4
    optional_size = _u16(content, file_header + 16)
    optional_start = file_header + 20
    if optional_size < 2 or optional_start + optional_size > len(content):
        return None
    magic = content[optional_start:optional_start + 2]
    if magic == b"\x0b\x01":
        data_dir_offset, num_dir_offset = _PE32_DATA_DIR_OFFSET, 92
    elif magic == b"\x0b\x02":
        data_dir_offset, num_dir_offset = _PE32_PLUS_DATA_DIR_OFFSET, 112
    else:
        return None
    number_of_directories = _u32(content, optional_start + num_dir_offset)
    if SECURITY_DIRECTORY_INDEX >= number_of_directories:
        return None
    entry_offset = optional_start + data_dir_offset + SECURITY_DIRECTORY_INDEX * 8
    if entry_offset + 8 > len(content):
        return None
    offset = _u32(content, entry_offset)
    size = _u32(content, entry_offset + 4)
    if offset == 0 or size == 0:
        return None
    return offset, size


# ------------------------------------------------------------------
# Minimal DER reader (bounded)
# ------------------------------------------------------------------

class _DerError(ValueError):
    pass


def _read_tlv(data, position, limit):
    """Read one DER TLV from ``data`` at ``position``; bounds-checked."""
    if position >= limit:
        raise _DerError("TLV past limit")
    tag = data[position]
    position += 1
    if position >= limit:
        raise _DerError("length missing")
    first = data[position]
    position += 1
    if first < 0x80:
        length = first
    elif first == 0x81:
        if position >= limit:
            raise _DerError("short long-form length")
        length = data[position]
        position += 1
    elif first == 0x82:
        if position + 2 > limit:
            raise _DerError("short long-form length")
        length = int.from_bytes(data[position:position + 2], "big")
        position += 2
    else:
        raise _DerError("unsupported length encoding")
    value_end = position + length
    if value_end > limit:
        raise _DerError("TLV exceeds limit")
    return tag, data[position:value_end], value_end


def _children(data, start, end):
    position = start
    while position < end:
        tag, value, value_end = _read_tlv(data, position, end)
        yield tag, value
        position = value_end


def _oid_to_string(value):
    if len(value) < 2:
        return "?"
    parts = [str(value[0] // 40), str(value[0] % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)


def _decode_directory_string(tag, value):
    try:
        if tag in (0x0C,):          # UTF8String
            return value.decode("utf-8")
        if tag in (0x13, 0x16, 0x14):  # PrintableString / IA5String / T61String
            return value.decode("ascii")
        if tag == 0x1E:             # BMPString (UTF-16BE)
            return value.decode("utf-16-be")
    except (UnicodeDecodeError, ValueError):
        return "?"
    return "?"


def _certificate_subject_issuer(certificate, limit):
    """Extract ``(subject, issuer)`` from the first X.509 certificate."""
    cert_children = list(_children(certificate, 0, min(len(certificate), limit)))
    tbs_only = [item for item in cert_children if item[0] == 0x30]
    if not tbs_only:
        raise _DerError("no TBSCertificate")
    tbscert = tbs_only[0][1]
    fields = list(_children(tbscert, 0, len(tbscert)))

    def render_name(raw):
        if not raw or raw[0:1] not in (b"\x30", b"\x31"):
            return ""
        names = []
        for _, rdn_set in _children(raw, 0, len(raw)):
            if not rdn_set:
                continue
            for _, attribute in _children(rdn_set, 0, len(rdn_set)):
                attribute_children = list(_children(attribute, 0, len(attribute)))
                if len(attribute_children) < 2:
                    continue
                oid_tag, oid_value = attribute_children[0]
                value_tag, value_value = attribute_children[1]
                if oid_tag != 0x06:
                    continue
                oid = _oid_to_string(oid_value)
                label = _OID_LABELS.get(oid, oid)
                names.append(f"{label}={_decode_directory_string(value_tag, value_value)}")
        return ", ".join(names)

    # TBSCertificate fields (positional): [version?, serial, sigalg, issuer,
    # validity, subject, ...]. The version field is a context tag when present.
    has_version = bool(fields) and fields[0][0] in (0xA0, 0xA1)
    version_offset = 1 if has_version else 0
    issuer = ""
    subject = ""
    if len(fields) > version_offset + 2 and fields[version_offset + 2][0] == 0x30:
        issuer = render_name(fields[version_offset + 2][1])
    if len(fields) > version_offset + 4 and fields[version_offset + 4][0] == 0x30:
        subject = render_name(fields[version_offset + 4][1])
    return subject, issuer


def _parse_pkcs7_signed_data(payload, limit):
    """Return ``(subject, issuer)`` from a PKCS#7 SignedData payload."""
    seq = list(_children(payload, 0, min(len(payload), limit)))
    if not seq or seq[0][0] != 0x30:
        return None, None
    outer = list(_children(seq[0][1], 0, min(len(seq[0][1]), limit)))
    if len(outer) < 2 or outer[0][0] != 0x06:
        return None, None
    if not outer[0][1].startswith(_PKCS7_SIGNED_DATA_OID[2:]):
        return None, None

    def unpack_explicit(blob):
        pieces = list(_children(blob, 0, len(blob)))
        return pieces[0][1] if pieces else b""

    signed_data = unpack_explicit(outer[1][1]) if outer[1][0] == 0xA0 else b""
    sections = list(_children(signed_data, 0, len(signed_data)))
    for tag, value in sections:
        if tag == 0xA0:  # [0] IMPLICIT SET OF Certificate
            for _, certificate in _children(value, 0, min(len(value), limit)):
                if certificate[0:1] == b"\x30":
                    return _certificate_subject_issuer(certificate, limit)
    return None, None


def _extract_subject_issuer(payload):
    try:
        return _parse_pkcs7_signed_data(payload, min(len(payload), MAX_DER_TRAVERSAL))
    except _DerError:
        return None, None


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def analyze_authenticode(filepath, content=None):
    """Analyze the Authenticode signature of ``filepath``.

    ``content`` may be the shared analysis buffer. Returns a JSON-safe dict:
    portable across PE / non-PE / malformed inputs, never raising.
    """
    if content is None:
        with open(filepath, "rb") as handle:
            content = handle.read()

    security = _find_security_directory(content)
    if security is None:
        is_pe = content[:2] == b"MZ"
        return {
            "available": True,
            "status": "no_data" if not is_pe else "unsigned",
            "error": None,
            "is_pe": is_pe,
            "signed": False,
            "block_size": None,
            "revision": None,
            "cert_type": None,
            "subject": None,
            "issuer": None,
            "notes": [],
        }

    offset, size = security
    notes = []
    if offset + 8 > len(content) or size < 8:
        return {
            "available": True,
            "status": "error",
            "error": "malformed or truncated security directory",
            "is_pe": True,
            "signed": False,
            "block_size": size,
            "revision": None,
            "cert_type": None,
            "subject": None,
            "issuer": None,
            "notes": ["malformed signature block"],
        }

    block_length = _u32(content, offset)
    revision = _u16(content, offset + 4)
    cert_type = _u16(content, offset + 6)
    if block_length < 8 or block_length > size + 8:
        notes.append("invalid WIN_CERTIFICATE length")
    if revision != AUTHENTICODE_REVISION:
        notes.append(f"unexpected certificate revision 0x{revision:04x}")
    if cert_type != AUTHENTICODE_TYPE:
        notes.append(f"unexpected certificate type 0x{cert_type:04x}")

    payload_start = offset + 8
    payload_end = min(payload_start + block_length - 8, payload_start + MAX_DER_TRAVERSAL, len(content))
    payload = content[payload_start:payload_end]
    subject, issuer = None, None
    if revision == AUTHENTICODE_REVISION and cert_type == AUTHENTICODE_TYPE and payload:
        subject, issuer = _extract_subject_issuer(payload)

    return {
        "available": True,
        "status": "signed" if not notes else "signed" if subject else "error",
        "error": None if not notes else "; ".join(notes),
        "is_pe": True,
        "signed": bool(payload),
        "block_size": block_length,
        "revision": hex(revision),
        "cert_type": "PKCS#7 SignedData" if cert_type == AUTHENTICODE_TYPE else f"0x{cert_type:04x}",
        "subject": subject,
        "issuer": issuer,
        "notes": notes,
    }