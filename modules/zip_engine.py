"""ZIP archive recursion engine (stdlib ``zipfile`` only).

Decompressing hostile archives is a classic attack surface (zip bombs,
traversal escapes, absolute paths), so this engine is conservative by design
(S4). It never extracts a member for analysis: each member is read in a
bounded, streaming way from the ``ZipFile`` object, validated against the
following limits, and then lazily typed via the magic-number signatures:

- ``MAX_ZIP_ENTRIES``: member count cap (avoids archive bombs made of many files).
- ``MAX_ENTRY_UNCOMPRESSED``: per-member uncompressed size cap.
- ``MAX_ZIP_TOTAL_UNCOMPRESSED``: running total cap across the whole archive.
- ``MAX_ZIP_RATIO`` (+ ``MIN_BOMB_SIZE``): compression-ratio heuristic for
  classic zip-bomb shapes (e.g. a 5 MB member that compresses to 1 KB).
- ``MAX_ZIP_DEPTH``: recursion depth cap for nested archives.
- Traversal guard: members whose normalized name contains ``..`` or resolves
  to an absolute/drive path are flagged and never opened for reading.

Nested ZIP members are recursed into (up to ``MAX_ZIP_DEPTH``) from an
in-memory ``BytesIO`` so nothing is ever written to disk; findings cascade up
to the top-level result. The engine's output is purely evidence for the risk
scorer and the report -- verified member content is still analysed
individually if the operator extracts it explicitly.
"""

import io
import os
import posixpath
import re
import zipfile

from modules.magic_numbers import _detect_signature


MAX_ZIP_ENTRIES = 500
MAX_ENTRY_UNCOMPRESSED = 50 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024
MAX_ZIP_RATIO = 100
MIN_BOMB_SIZE = 1024 * 1024
MAX_ZIP_DEPTH = 3

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".cpl", ".ocx", ".sys",
    ".vbs", ".vbe", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta",
    ".jar", ".apk", ".docm", ".xlsm", ".pptm",
}

_DRIVE_RE = re.compile(r"^[a-zA-Z]:")
_NESTED_SIGNATURES = (b"PK\x03\x04",)


def _normalized_member_name(raw_name):
    """Return a safe POSIX-style member name or ``None`` if it is unsafe."""
    if not raw_name or isinstance(raw_name, bytes):
        return None
    normalized = raw_name.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_RE.match(normalized) or normalized.startswith("//"):
        return None
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None
    return posixpath.join(*parts) if parts else None


def _read_member_header(archive, info, limit=64):
    """Read up to ``limit`` bytes from a member without materialising it."""
    with archive.open(info) as handle:
        return handle.read(limit)


def _compute_ratio(info):
    if info.file_size <= 0 or info.compress_size <= 0:
        return 0
    return info.file_size / info.compress_size


def _recursively_scan(content, depth, config):
    result = _scan_bytes(content, depth=depth, config=config)
    return result


def _scan_bytes(content, depth, config):
    """Open an in-memory ZIP and run the member gauntlet (shared core)."""
    archive = zipfile.ZipFile(io.BytesIO(content))
    try:
        return _scan_members(archive, depth=depth, config=config)
    finally:
        archive.close()


def _scan_members(archive, depth, config):
    entries = []
    findings = {
        "traversal_attempt": False,
        "high_compression_ratio": False,
        "embedded_executable": False,
        "suspicious_script": False,
        "unsafe_name": False,
    }
    total_uncompressed = 0
    inspected = 0
    nested_archives = 0
    unsafe_count = 0
    truncated = False

    for info in archive.infolist():
        if inspected >= MAX_ZIP_ENTRIES:
            truncated = True
            break
        inspected += 1
        is_dir = info.is_dir() or info.filename.endswith("/")
        member_name = _normalized_member_name(info.filename)
        ratio = _compute_ratio(info)
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED:
            truncated = True
            break

        entry_flags = []
        unsafe_name = member_name is None and not is_dir
        if unsafe_name:
            findings["unsafe_name"] = True
            findings["traversal_attempt"] = True
            unsafe_count += 1
            entry_flags.append("unsafe_path")
        if not is_dir and ratio >= MAX_ZIP_RATIO and info.file_size >= MIN_BOMB_SIZE:
            findings["high_compression_ratio"] = True
            entry_flags.append("high_compression_ratio")

        detected_type = "unknown"
        is_nested = False
        if not is_dir and member_name is not None and info.file_size <= MAX_ENTRY_UNCOMPRESSED:
            try:
                header = _read_member_header(archive, info)
                if header:
                    detected_type, _ = _detect_signature(header)
            except (zipfile.BadZipFile, OSError):
                pass
            is_nested = detected_type.startswith("ZIP")

        extension = os.path.splitext(member_name or "")[1].lower()
        if extension in SUSPICIOUS_EXTENSIONS:
            if extension in (".exe", ".dll", ".scr", ".cpl", ".ocx", ".sys"):
                findings["embedded_executable"] = True
                entry_flags.append("embedded_executable")
            else:
                findings["suspicious_script"] = True
                entry_flags.append("suspicious_script")

        if is_nested:
            nested_archives += 1
            if depth < MAX_ZIP_DEPTH:
                try:
                    with archive.open(info) as handle:
                        payload = handle.read()
                except (zipfile.BadZipFile, OSError):
                    payload = None
                if payload is not None and len(payload) <= MAX_ENTRY_UNCOMPRESSED:
                    inner = _recursively_scan(payload, depth + 1, config)
                    for nested_finding, active in inner.get("findings", {}).items():
                        if active:
                            findings[nested_finding] = True
                    nested_archives += inner.get("nested_archives", 0)
                    for entry in inner.get("entries", []):
                        entry["name"] = f"{member_name}!{entry['name']}"
                    entries.extend(inner.get("entries", []))

        if not is_dir and (member_name is not None or unsafe_name):
            entries.append({
                "name": member_name if member_name is not None else "(unsafe)",
                "uncompressed_size": info.file_size,
                "compressed_size": info.compress_size,
                "ratio": round(ratio, 2),
                "detected_type": detected_type,
                "flags": entry_flags,
            })

    status = "matched" if any(findings.values()) else ("truncated" if truncated else "clean")
    return {
        "available": True,
        "status": status,
        "error": None,
        "is_zip": True,
        "entry_count": len(entries),
        "depth": depth,
        "nested_archives": nested_archives,
        "truncated": truncated,
        "unsafe_entries": unsafe_count,
        "findings": findings,
        "entries": entries,
    }


_EMPTY_ZIP_SIGNATURE = b"PK\x05\x06"


def _looks_like_zip(content):
    return content.startswith((b"PK\x03\x04", _EMPTY_ZIP_SIGNATURE))


def scan_zip(filepath, config=None, content=None):
    """Fuzzy-style entry point compatible with the analyzer gate.

    ``content`` may be the shared analysis buffer (in-memory path); otherwise
    the file is opened directly. Files that are not ZIP containers degrade to
    ``no_data``; ZIP-looking containers that fail to parse report ``error``
    without crashing the pipeline.
    """
    if content is None:
        with open(filepath, "rb") as handle:
            head = handle.read(4)
    else:
        head = content[:4]

    if not _looks_like_zip(head):
        return {
            "available": True,
            "status": "no_data",
            "error": None,
            "is_zip": False,
            "entry_count": 0,
            "depth": 0,
            "nested_archives": 0,
            "truncated": False,
            "unsafe_entries": 0,
            "findings": {
                "traversal_attempt": False,
                "high_compression_ratio": False,
                "embedded_executable": False,
                "suspicious_script": False,
                "unsafe_name": False,
            },
            "entries": [],
        }

    try:
        if content is None:
            with zipfile.ZipFile(filepath) as archive:
                result = _scan_members(archive, depth=1, config=config)
        else:
            result = _scan_bytes(content, depth=1, config=config)
    except zipfile.BadZipFile:
        return {
            "available": True,
            "status": "error",
            "error": "corrupt or truncated ZIP container",
            "is_zip": True,
            "entry_count": 0,
            "depth": 0,
            "nested_archives": 0,
            "truncated": False,
            "unsafe_entries": 0,
            "findings": {
                "traversal_attempt": False,
                "high_compression_ratio": False,
                "embedded_executable": False,
                "suspicious_script": False,
                "unsafe_name": False,
            },
            "entries": [],
        }
    except (OSError, ValueError) as exc:
        return {
            "available": True,
            "status": "error",
            "error": f"could not inspect archive: {exc}",
            "is_zip": True,
            "entry_count": 0,
            "depth": 0,
            "nested_archives": 0,
            "truncated": False,
            "unsafe_entries": 0,
            "findings": {
                "traversal_attempt": False,
                "high_compression_ratio": False,
                "embedded_executable": False,
                "suspicious_script": False,
                "unsafe_name": False,
            },
            "entries": [],
        }
    return result