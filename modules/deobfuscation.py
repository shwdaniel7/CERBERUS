"""Base64/XOR deobfuscation engine (stdlib only).

Detects long Base64 blobs embedded in a file (decode + printable-text /
embedded-executable heuristic) and single-byte XOR-encrypted content (brute
force over the window that maximizes printable text). The decoded candidates
are exposed as ``feed_blobs`` so the analyzer can re-run YARA and IOC
extraction over the *decoded* view of the file -- the whole point of item 2 of
the roadmap ("Deobfuscation feeding YARA and IOC matching").

Safety (S7 in ``docs/security/SECURITY_AUDIT.md``): every decode is bounded.
Base64 runs are only decoded up to ``MAX_RAW_B64`` characters per blob (a
truncated, padding-safe prefix keeps the printable-text heuristic valid), only
the largest ``MAX_BASE64_BLOBS`` matches are kept, the total decoded bytes kept
is capped per blob and per feed, and the XOR brute force works on at most
``XOR_SCAN_WINDOW`` bytes. Nothing here unpacks more bytes than it reads from
the input, so compressed-file style expansion bombs are not possible.
"""

import base64
import re


MIN_BASE64_RUN = 16
MIN_DECODED_BYTES = 5
TEXT_RATIO_BASE64 = 0.35
MAX_RAW_B64 = 2 * 1024 * 1024
MAX_BASE64_BLOBS = 10
MAX_BLOB_DECODED_SIZE = 256 * 1024
MAX_FEED_BLOBS = 4
MAX_FEED_BLOB_SIZE = 1024 * 1024
XOR_SCAN_WINDOW = 512 * 1024
XOR_ACCEPT_RATIO = 0.55
XOR_IMPROVEMENT = 0.4
XOR_TEXT_PRECONDITION = 0.6
SAMPLE_CHARS = 150

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_EMBEDDED_MAGICS = (b"MZ", b"\x7fELF", b"%PDF", b"RIFF", b"\x89PNG", b"PK\x03\x04")
_EMBEDDED_MAGIC_LABELS = {
    b"MZ": "embedded PE executable header (MZ)",
    b"\x7fELF": "embedded ELF executable header",
    b"%PDF": "embedded PDF header",
    b"RIFF": "embedded RIFF header",
    b"\x89PNG": "embedded PNG header",
    b"PK\x03\x04": "embedded ZIP header",
}

DECODE_FLAG_MARKERS = (
    b"powershell",
    b"invoke-expression",
    b"iex(",
    b"-encodedcommand",
    b"cmd /c",
    b"cmd.exe",
    b"schtasks",
    b"bitsadmin",
    b"certutil",
    b"rundll32",
    b"regsvr32",
    b"mshta",
    b"wscript",
    b"cscript",
    b"frombase64string",
    b"downloadstring",
    b"<?php",
    b"mimikatz",
    b"lsass",
)

_PRINTABLE_DELETE = bytes(range(0x20, 0x7F)) + b"\t\n\r"

_XOR_TABLES = {
    key: bytes.maketrans(bytes(range(256)), bytes(byte ^ key for byte in range(256)))
    for key in range(256)
}


def _printable_ratio(data):
    """Fraction of bytes that are printable ASCII (space through ~ plus tabs/newlines)."""
    if not data:
        return 0.0
    non_printable = len(data.translate(None, _PRINTABLE_DELETE))
    return (len(data) - non_printable) / len(data)


def _embedded_magic(decoded):
    """Return the magic label when ``decoded`` starts with an embedded file header."""
    for magic in _EMBEDDED_MAGICS:
        if decoded.startswith(magic):
            return _EMBEDDED_MAGIC_LABELS[magic]
    return None


def _decode_base64_run(raw):
    """Decode a base64 run after padding safety: strip ``=``, align to 4 chars."""
    body = raw.rstrip(b"=")
    remainder = len(body) % 4
    if remainder:
        body = body[:-remainder]
    if len(body) < 4:
        return None
    try:
        decoded = base64.b64decode(body, validate=False)
    except (ValueError, OSError) as error:
        return None if error else None
    return decoded or None


def _sample(decoded):
    return decoded[:SAMPLE_CHARS].decode("ascii", errors="replace")


def _flag_reasons_for(decoded):
    lowered = decoded.lower()
    reasons = []
    for marker in DECODE_FLAG_MARKERS:
        if marker in lowered:
            reasons.append(f"decoded payload string '{marker.decode('ascii', errors='replace')}'")
    magic = _embedded_magic(decoded)
    if magic:
        reasons.append(magic)
    return reasons


def _best_xor_key(probe, raw_ratio):
    """Brute force the single-byte key that makes ``probe`` most text-like.

    Keys are ranked by (printable ratio, space count). The space count breaks
    ties between keys that map a small character set onto printable bytes --
    the real key reproduces words separated by spaces while decoy keys produce
    printable letter soup. Only keys whose decode is clearly more printable
    than the raw window are considered (``XOR_IMPROVEMENT``).
    """
    best_key = None
    best_ratio = XOR_ACCEPT_RATIO
    best_spaces = -1
    for key in range(1, 256):
        decoded = probe.translate(_XOR_TABLES[key])
        ratio = _printable_ratio(decoded)
        if ratio < XOR_ACCEPT_RATIO or (ratio - raw_ratio) < XOR_IMPROVEMENT:
            continue
        spaces = decoded.count(b" ")
        if (ratio, spaces) > (best_ratio, best_spaces):
            best_ratio, best_spaces, best_key = ratio, spaces, key
    return best_key, best_ratio


def _collect_feed(entries):
    """Build up to ``MAX_FEED_BLOBS`` decoded byte buffers from ``(entry, decoded)`` pairs."""
    feed = []
    for _, decoded in entries:
        if len(feed) >= MAX_FEED_BLOBS:
            break
        feed.append(decoded[:MAX_FEED_BLOB_SIZE])
    return feed


def analyze_deobfuscation(filepath, content=None):
    """Detect and decode Base64/XOR-obfuscated content.

    ``content`` may be a shared byte buffer (the analyzer passes it), otherwise
    the file is read directly. Returns a JSON-safe dict describing what was
    found plus a ``feed_blobs`` key (list of bytes, not JSON-safe) that the
    analyzer consumes to feed YARA/IOC extraction and strips before reporting.
    """
    if content is None:
        with open(filepath, "rb") as handle:
            data = handle.read()
    else:
        data = content

    candidates = []
    for match in _B64_RUN.finditer(data):
        raw = match.group()
        if len(raw) < MIN_BASE64_RUN:
            continue
        source_len = min(len(raw), MAX_RAW_B64)
        source_len -= source_len % 4
        decoded = _decode_base64_run(raw[:source_len])
        if decoded is None or len(decoded) < MIN_DECODED_BYTES:
            continue
        if _printable_ratio(decoded) < TEXT_RATIO_BASE64 and not _embedded_magic(decoded):
            continue
        candidates.append((
            {
                "kind": "base64",
                "offset": match.start(),
                "encoded_size": len(raw),
                "decoded_size": len(decoded),
                "sample": _sample(decoded),
            },
            decoded,
        ))

    candidates.sort(key=lambda item: item[0]["decoded_size"], reverse=True)
    base64_entries = candidates[:MAX_BASE64_BLOBS]
    base64_blobs = [entry for entry, _ in base64_entries]
    feed = _collect_feed(candidates)

    xor_blobs = []
    probe = data[:XOR_SCAN_WINDOW]
    raw_ratio = _printable_ratio(probe) if probe else 1.0
    if len(probe) >= 64 and raw_ratio < XOR_TEXT_PRECONDITION:
        best_key, best_ratio = _best_xor_key(probe, raw_ratio)
        if best_key is not None:
            decoded = probe.translate(_XOR_TABLES[best_key])
            xor_entry = {
                "kind": "xor",
                "offset": 0,
                "window_size": len(probe),
                "key": best_key,
                "printable_ratio": round(best_ratio, 4),
                "decoded_size": len(decoded),
                "sample": _sample(decoded),
            }
            xor_blobs.append(xor_entry)
            if len(feed) < MAX_FEED_BLOBS:
                feed.append(decoded[:MAX_FEED_BLOB_SIZE])

    all_entries = list(base64_entries)
    if xor_blobs:
        all_entries.append((xor_blobs[0], probe.translate(_XOR_TABLES[xor_blobs[0]["key"]])))

    flagged = False
    flag_reasons = []
    for _, decoded in all_entries:
        for reason in _flag_reasons_for(decoded):
            if reason not in flag_reasons:
                flag_reasons.append(reason)
    flagged = bool(flag_reasons)

    return {
        "available": True,
        "error": None,
        "blob_count": len(base64_blobs),
        "base64_blobs": base64_blobs,
        "xor_count": len(xor_blobs),
        "xor_blobs": xor_blobs,
        "detected_total": len(base64_blobs) + len(xor_blobs),
        "decoded_bytes_processed": sum(
            entry.get("decoded_size", entry.get("window_size", 0))
            for entry in (*base64_blobs, *xor_blobs)
        ),
        "flagged": flagged,
        "flag_reasons": flag_reasons,
        "feed_blobs_count": len(feed),
        "feed_blobs": feed,
    }