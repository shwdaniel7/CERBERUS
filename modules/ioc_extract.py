import ipaddress
import re


IOC_PATTERNS = {
    "urls": re.compile(
        r"\b(?:https?|ftp)://[^\s\"'<>]+",
        re.IGNORECASE,
    ),
    "emails": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE,
    ),
    "windows_paths": re.compile(
        r"(?<![A-Za-z0-9_])(?:[A-Z]:\\|\\\\)[^\r\n\"'<>|]{2,}",
        re.IGNORECASE,
    ),
    "unix_paths": re.compile(
        r"(?<![A-Za-z0-9_])/(?:tmp|var/tmp|dev/shm|etc|usr/bin|bin|home|root)(?:/[^\s\"'<>|]*)?",
        re.IGNORECASE,
    ),
    "powershell_commands": re.compile(
        r"\b(?:powershell|pwsh)(?:\.exe)?(?:\s+[^\r\n\"']*)?",
        re.IGNORECASE,
    ),
    "cmd_commands": re.compile(
        r"\b(?:cmd(?:\.exe)?\s+(?:/c|/k)|command\.com\s+/c)(?:\s+[^\r\n\"']*)?",
        re.IGNORECASE,
    ),
}

DOMAIN_PATTERN = re.compile(
    r"(?<![@\w])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TRAILING_PUNCTUATION = ".,;:!?)]}\"'"


def _unique(values):
    return list(dict.fromkeys(value.strip(TRAILING_PUNCTUATION) for value in values if value.strip(TRAILING_PUNCTUATION)))


def _valid_ips(values):
    valid = []
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        valid.append(value)
    return valid


def extract_iocs(filepath):
    """Extract observable network, path, and command indicators from a file."""
    with open(filepath, "rb") as file_handle:
        text = file_handle.read().decode("utf-8", errors="ignore")

    urls = _unique(IOC_PATTERNS["urls"].findall(text))
    emails = _unique(IOC_PATTERNS["emails"].findall(text))
    domains = _unique(DOMAIN_PATTERN.findall(text))
    ips = _valid_ips(_unique(IP_PATTERN.findall(text)))
    windows_paths = _unique(IOC_PATTERNS["windows_paths"].findall(text))
    unix_paths = _unique(IOC_PATTERNS["unix_paths"].findall(text))
    powershell_commands = _unique(IOC_PATTERNS["powershell_commands"].findall(text))
    cmd_commands = _unique(IOC_PATTERNS["cmd_commands"].findall(text))

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
