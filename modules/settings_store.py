"""Persistent user settings.

Reads and writes ``settings.json`` at the project root. The file must never
hold secrets: the VirusTotal API key stays in ``.env``. A missing or corrupt
file falls back to the defaults so the application always starts, and every
value is re-validated on load so a hand-edited file cannot crash the runtime.
"""

import json
import os
import threading

SETTINGS_FILENAME = "settings.json"

DEFAULT_SETTINGS = {
    "blacklist": True,
    "virustotal": True,
    "strings": True,
    "ioc_extract": True,
    "entropy": True,
    "magic_numbers": True,
    "pe_analysis": True,
    "deobfuscation": True,
    "fuzzy": True,
    "zip": True,
    "authenticode": True,
    "yara": True,
    "skip_reparse_points": True,
    "max_file_size": 200 * 1024 * 1024,
    "workers": 4,
    "cache_enabled": True,
    "output_dir": "reports",
    "report_format": "all",
}

_write_lock = threading.Lock()


def project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def settings_path():
    return os.path.join(project_root(), SETTINGS_FILENAME)


def _coerce(key, value, default):
    if key == "report_format" and value not in ("all", "json", "csv", "html"):
        return default
    if isinstance(default, bool):
        return bool(value) if isinstance(value, (bool, int)) else default
    if isinstance(default, int):
        try:
            coerced = int(value)
        except (TypeError, ValueError):
            return default
        if key == "workers" and coerced < 1:
            return default
        if key == "max_file_size" and coerced < 0:
            return default
        return coerced
    if isinstance(default, str):
        return value if isinstance(value, str) and value else default
    return default


def _sanitize(raw):
    if not isinstance(raw, dict):
        return dict(DEFAULT_SETTINGS)
    return {key: _coerce(key, raw.get(key, default), default) for key, default in DEFAULT_SETTINGS.items()}


def load_settings():
    try:
        with open(settings_path(), "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_SETTINGS)
    return _sanitize(raw)


def save_settings(settings):
    sanitized = _sanitize(settings) if isinstance(settings, dict) else dict(DEFAULT_SETTINGS)
    with _write_lock:
        with open(settings_path(), "w", encoding="utf-8") as handle:
            json.dump(sanitized, handle, indent=4, ensure_ascii=False)
        return sanitized