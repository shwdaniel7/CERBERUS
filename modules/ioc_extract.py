import ipaddress
import re


IOC_PATTERNS = {
    "urls": re.compile(
        rb"\b(?:https?|ftp)://[^\s\"'<>]+",
        re.IGNORECASE,
    ),
    "emails": re.compile(
        rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE,
    ),
    "windows_paths": re.compile(
        rb"(?<![A-Za-z0-9_])(?:[A-Z]:\\|\\\\)[^\r\n\"'<>|]{2,}",
        re.IGNORECASE,
    ),
    "unix_paths": re.compile(
        rb"(?<![A-Za-z0-9_])/(?:tmp|var/tmp|dev/shm|etc|usr/bin|bin|home|root)(?:/[^\s\"'<>|]*)?",
        re.IGNORECASE,
    ),
    "powershell_commands": re.compile(
        rb"\b(?:powershell|pwsh)(?:\.exe)?(?:\s+[^\r\n\"']*)?",
        re.IGNORECASE,
    ),
    "cmd_commands": re.compile(
        rb"\b(?:cmd(?:\.exe)?\s+(?:/c|/k)|command\.com\s+/c)(?:\s+[^\r\n\"']*)?",
        re.IGNORECASE,
    ),
}

DOMAIN_PATTERN = re.compile(
    rb"(?<![@\w])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    rb"[A-Z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(rb"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TRAILING_PUNCTUATION = ".,;:!?)]}\"'"


def _decode_unique(raw_values):
    """Decode byte captures (regex runs over the raw binary buffer) and
    deduplicate them while stripping trailing punctuation."""
    seen = set()
    result = []
    for value in raw_values:
        if isinstance(value, (bytes, bytearray, memoryview)):
            text = value.decode("utf-8", errors="ignore").strip(TRAILING_PUNCTUATION)
        else:
            text = value.strip(TRAILING_PUNCTUATION)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _valid_ips(values):
    valid = []
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        valid.append(value)
    return valid


def extract_iocs(filepath, content=None):
    """Extract observable network, path, and command indicators from a file.

    Accepts an optional ``content`` byte buffer (from a shared single read);
    otherwise the file is opened directly. Patterns run over raw bytes so the
    whole binary is never decoded to text.
    """
    if content is None:
        with open(filepath, "rb") as file_handle:
            data = file_handle.read()
    else:
        data = content

    urls = _decode_unique(IOC_PATTERNS["urls"].findall(data))
    emails = _decode_unique(IOC_PATTERNS["emails"].findall(data))
    domains = _decode_unique(DOMAIN_PATTERN.findall(data))
    ips = _valid_ips(_decode_unique(IP_PATTERN.findall(data)))
    windows_paths = _decode_unique(IOC_PATTERNS["windows_paths"].findall(data))
    unix_paths = _decode_unique(IOC_PATTERNS["unix_paths"].findall(data))
    powershell_commands = _decode_unique(IOC_PATTERNS["powershell_commands"].findall(data))
    cmd_commands = _decode_unique(IOC_PATTERNS["cmd_commands"].findall(data))

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": emails,
        "suspicious_paths": windows_paths + unix_paths,
        "powershell_commands": powershell_commands,
        "cmd_commands": cmd_commands,
    }


def count_iocs(iocs):
    return sum(len(values) for values in iocs.values())


def suspicious_ioc_count(iocs):
    return sum(
        len(iocs.get(category, []))
        for category in ("suspicious_paths", "powershell_commands", "cmd_commands")
    )
