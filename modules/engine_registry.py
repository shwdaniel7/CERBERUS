"""Lightweight engine registry.

Single source of truth for the analysis engines the analyzer can run. Phase 1
keeps the registry read-only and uses it to validate configuration and to
derive the GUI engine toggles; ``register``/``unregister`` are the plugin hooks
that Phase 2 and later engines (YARA, archive recursion, fuzzy hashing) will
use so the CLI and GUI discover them without any extra wiring.

The registry never imports an engine module at registration time: imports stay
lazy in the analyzer so a broken optional dependency (e.g. ``pefile``) cannot
crash startup.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Engine:
    """Description of a single analysis engine."""

    name: str
    label: str
    config_key: str
    default: bool = True
    optional: bool = False
    description: str = ""


_ENGINES = [
    Engine(
        "blacklist",
        "Local blacklist",
        "blacklist",
        description="Compare the SHA-256 against iocs/blacklist.txt.",
    ),
    Engine(
        "virustotal",
        "VirusTotal",
        "virustotal",
        description="Query the VirusTotal API using the key from .env.",
    ),
    Engine(
        "magic_numbers",
        "File type & magic",
        "magic_numbers",
        description="Detect file type from header bytes and compare with the extension.",
    ),
    Engine(
        "entropy",
        "Entropy & packers",
        "entropy",
        description="Shannon entropy with PyInstaller/UPX packer context.",
    ),
    Engine(
        "strings",
        "Strings",
        "strings",
        description="Extract printable ASCII/UTF-16 strings and flag suspicious terms.",
    ),
    Engine(
        "pe_analysis",
        "PE sections",
        "pe_analysis",
        optional=True,
        description="PE header/section analysis (requires the optional pefile package).",
    ),
    Engine(
        "ioc_extract",
        "Structured IOCs",
        "ioc_extract",
        description="Extract URLs, IPs, domains, e-mails, paths and shell commands.",
    ),
    Engine(
        "deobfuscation",
        "Deobfuscation (Base64/XOR)",
        "deobfuscation",
        description="Detect and decode Base64 blobs and single-byte XOR content.",
    ),
    Engine(
        "fuzzy",
        "TLSH fuzzy similarity",
        "fuzzy",
        optional=True,
        description="Compare the file's TLSH fuzzy hash against iocs/tlsh_corpus.txt (requires py-tlsh).",
    ),
    Engine(
        "yara",
        "YARA rules",
        "yara",
        optional=True,
        description="Scan for YARA rule matches (requires the optional yara-python package).",
    ),
]


def _engine_list():
    return _ENGINES


def iter_engines():
    """Yield every registered engine in display order."""
    return iter(_ENGINES)


def get_engine(name):
    """Return the engine with ``name`` or ``None``."""
    return next((engine for engine in _engine_list() if engine.name == name), None)


def config_keys():
    """Return the config (settings) keys the registry owns."""
    return {engine.config_key for engine in _engine_list()}


def engine_defaults():
    """Map engine name to its default enabled state (used by settings)."""
    return {engine.name: engine.default for engine in _engine_list()}


def toggles():
    """``(label, name)`` pairs for GUI checkboxes."""
    return [(engine.label, engine.name) for engine in _engine_list()]


def enabled_names(config):
    """Names of engines that are enabled in ``config``."""
    return [
        engine.name for engine in _engine_list()
        if isinstance(config.get(engine.config_key), bool) and config[engine.config_key]
    ]


def validate_config(config):
    """Coerce engine toggles in ``config`` to booleans with safe defaults.

    Returns a new dict; unknown keys and runtime-only keys (starting with ``_``)
    are preserved untouched so this stays compatible with the analyzer config.
    """
    cleaned = dict(config)
    for engine in _engine_list():
        value = cleaned.get(engine.config_key, engine.default)
        cleaned[engine.config_key] = bool(value) if isinstance(value, (bool, int)) else engine.default
    return cleaned


def register(engine):
    """Plugin hook: register a new engine. ``engine`` is an ``Engine`` instance."""
    if not isinstance(engine, Engine):
        raise TypeError("engine must be an Engine instance")
    if get_engine(engine.name):
        raise ValueError(f"engine already registered: {engine.name}")
    if engine.config_key.startswith("_"):
        raise ValueError("config_key must not start with '_'")
    _ENGINES.append(engine)


def unregister(name):
    """Remove an engine by name. Raises ``KeyError`` if it does not exist."""
    for index, engine in enumerate(_ENGINES):
        if engine.name == name:
            del _ENGINES[index]
            return
    raise KeyError(name)