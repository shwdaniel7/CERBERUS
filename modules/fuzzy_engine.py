"""TLSH fuzzy similarity engine (optional dependency: ``py-tlsh``).

Optional exactly like ``yara-python``: when ``import tlsh`` fails the engine
degrades to ``available: False`` and the scan still completes (see
``requirements-fuzzy.txt``). The analyzed file's TLSH is streamed through the
C API in bounded chunks and diffed against every entry in
``iocs/tlsh_corpus.txt`` (one ``<hex> <label>`` per line, ``#`` comments
allowed). Entries within ``FUZZY_MATCH_DISTANCE`` of the file hash are
reported, nearest first.

Safety: hashing streams the shared analysis buffer in bounded chunks (no full
re-read of the file), corpus parsing never executes content (`int(..., 16)`
validation only), and the diff threshold keeps the engine conservative --
similarity is evidence to investigate, not a verdict.
"""

import os


try:
    import tlsh
except ImportError:
    tlsh = None


DEFAULT_CORPUS = os.path.join("iocs", "tlsh_corpus.txt")
FUZZY_MATCH_DISTANCE = 60
FUZZY_CLOSE_DISTANCE = 30
FUZZY_EXACT_DISTANCE = 10
MAX_TLSH_DISTANCE = 330
HASH_CHUNK_SIZE = 1024 * 1024


def tlsh_available():
    """True when py-tlsh is importable."""
    return tlsh is not None


def similarity_pct(distance):
    """Map a TLSH distance (0 = identical) to a 0-100 similarity percentage."""
    bounded = min(int(distance), MAX_TLSH_DISTANCE)
    return round(100 - (bounded * 100 // MAX_TLSH_DISTANCE))


def _is_hex(value):
    if not value or len(value) % 2:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _compute_tlsh(data):
    """Stream ``data`` into the TLSH C API and return the 70-char hexdigest.

    Returns ``None`` when the library is missing or the data is too short /
    lacks variation to produce a hash.
    """
    if tlsh is None:
        return None
    try:
        handle = tlsh.Tlsh()
        for offset in range(0, len(data), HASH_CHUNK_SIZE):
            handle.update(data[offset:offset + HASH_CHUNK_SIZE])
        handle.final()
        return handle.hexdigest()
    except (ValueError, TypeError, RuntimeError, OSError):
        return None


def load_corpus(corpus_path=None):
    """Parse ``iocs/tlsh_corpus.txt`` into ``[{hash, label, source_line}]``."""
    path = corpus_path or DEFAULT_CORPUS
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                parts = text.split(None, 1)
                digest = parts[0].strip().lower()
                label = parts[1].strip() if len(parts) > 1 else digest
                if not _is_hex(digest):
                    continue
                entries.append({
                    "hash": digest,
                    "label": label,
                    "source_line": line_number,
                })
    except OSError:
        pass
    return entries


def scan_similarity(filepath, config=None, content=None, corpus_path=None):
    """Fuzzy-match ``filepath`` against the local TLSH corpus.

    ``content`` may be the shared analysis buffer. Returns a JSON-safe dict
    with ``available``/``status``/``matches``/``match_count``/``file_hash``
    and the ``nearest_distance`` used for risk scoring.
    """
    if tlsh is None:
        return {
            "available": False,
            "status": "unavailable",
            "error": "py-tlsh not installed (pip install py-tlsh / requirements-fuzzy.txt)",
            "file_hash": None,
            "corpus_entries": 0,
            "match_count": 0,
            "matches": [],
            "nearest_distance": None,
        }

    if content is None:
        with open(filepath, "rb") as handle:
            data = handle.read()
    else:
        data = content

    digest = _compute_tlsh(data)
    if digest is None:
        return {
            "available": True,
            "status": "no_hash",
            "error": "TLSH could not be computed (file too short or lacks variation)",
            "file_hash": None,
            "corpus_entries": 0,
            "match_count": 0,
            "matches": [],
            "nearest_distance": None,
        }

    corpus = load_corpus(corpus_path or (config or {}).get("fuzzy_corpus") or DEFAULT_CORPUS)
    matches = []
    for entry in corpus:
        try:
            distance = tlsh.diff(digest, entry["hash"])
        except (ValueError, TypeError, RuntimeError):
            continue
        if not isinstance(distance, int):
            continue
        if distance <= FUZZY_MATCH_DISTANCE:
            matches.append({
                "label": entry["label"],
                "distance": int(distance),
                "similarity": similarity_pct(distance),
                "corpus_line": entry["source_line"],
            })
    matches.sort(key=lambda match: match["distance"])

    return {
        "available": True,
        "status": "matched" if matches else "no_match",
        "error": None,
        "file_hash": digest,
        "corpus_entries": len(corpus),
        "match_count": len(matches),
        "matches": matches,
        "nearest_distance": matches[0]["distance"] if matches else None,
    }