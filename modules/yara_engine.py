"""YARA rule engine (optional dependency).

Scans files against the YARA rules found in ``yara_rules/`` next to the
repository. Requires the optional ``yara-python`` package (see
``requirements-yara.txt``); when it is missing the engine degrades to an
``available: False`` result instead of crashing the scan, mirroring how
``pe_analysis`` tolerates a missing ``pefile``.

Rules are compiled once per process and cached; the cache is invalidated when
any rule file changes (fingerprint of name/size/mtime). Every ``match`` call
runs with a timeout so a pathological rule cannot hang a scan
(``docs/security/SECURITY_AUDIT.md``, S6).
"""

import os
import threading

try:
    import yara
except ImportError:  # pragma: no cover - optional dependency
    yara = None

YARA_RULE_EXTENSIONS = {".yar", ".yara"}
YARA_RULES_DIR = "yara_rules"
YARA_TIMEOUT_DEFAULT_SECONDS = 10.0

_cache = {}
_cache_lock = threading.Lock()


def yara_available():
    """True when the optional yara-python package is importable."""
    return yara is not None


def _fingerprint(rules_dir):
    """Hashable state of the rule files in ``rules_dir`` (name, size, mtime)."""
    try:
        entries = sorted(os.listdir(rules_dir))
    except OSError:
        return None
    state = []
    for name in entries:
        if os.path.splitext(name)[1].lower() not in YARA_RULE_EXTENSIONS:
            continue
        path = os.path.join(rules_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            stat = os.stat(path)
        except OSError:
            continue
        state.append((name, stat.st_size, stat.st_mtime_ns))
    return tuple(state) or None


def _compile_rules(rules_dir, fingerprint):
    """Compile every rule file in ``fingerprint`` separately.

    Rules are compiled file-by-file so a broken rule in one file is recorded
    in ``errors`` instead of silently discarding the other files.
    """
    rules_objs = []
    errors = []
    for name, _, _ in fingerprint:
        path = os.path.join(rules_dir, name)
        try:
            rules_objs.append((name, yara.compile(str(path))))
        except (yara.Error, OSError) as error:
            errors.append((name, f"{name}: {error}"))
    return (rules_objs or None), errors


def _get_rules(rules_dir):
    """Return ``(rules_objs_or_None, errors)`` using the per-process cache."""
    fingerprint = _fingerprint(rules_dir)
    with _cache_lock:
        cached = _cache.get(rules_dir)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
    if yara is None or fingerprint is None:
        payload = (None, [])
    else:
        payload = _compile_rules(rules_dir, fingerprint)
    with _cache_lock:
        _cache[rules_dir] = (fingerprint, payload)
    return payload


def scan_yara(filepath, config, rules_dir=None):
    """Scan ``filepath`` against the cached YARA rules.

    Returns a dict with ``available``, ``match_count``, ``matches`` (each entry
    holding ``rule``, ``tags`` and ``namespace``), plus diagnostics
    (``rules_dir``, ``rules_files`` and ``compile_errors``).
    """
    if yara is None:
        return {
            "available": False,
            "match_count": 0,
            "matches": [],
            "error": "yara-python not installed (install requirements-yara.txt)",
        }

    rules_dir = rules_dir or config.get("yara_rules_dir") or YARA_RULES_DIR
    rules_objs, errors = _get_rules(rules_dir)
    if not rules_objs:
        return {
            "available": True,
            "match_count": 0,
            "matches": [],
            "rules_dir": rules_dir,
            "rules_files": 0,
            "compile_errors": [message for _, message in errors],
        }

    timeout = float(config.get("yara_timeout", YARA_TIMEOUT_DEFAULT_SECONDS))
    matches = []
    for source, rules_object in rules_objs:
        try:
            found = rules_object.match(filepath=filepath, timeout=timeout)
        except yara.Error as error:
            errors.append((source, str(error)))
            continue
        for match in found:
            matches.append({
                "rule": str(match.rule),
                "tags": list(getattr(match, "tags", []) or []),
                "namespace": getattr(match, "namespace", "") or "",
            })

    return {
        "available": True,
        "match_count": len(matches),
        "matches": matches,
        "rules_dir": rules_dir,
        "rules_files": len(rules_objs),
        "compile_errors": [message for _, message in errors],
    }