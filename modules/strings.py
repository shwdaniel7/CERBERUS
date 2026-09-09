import re
from modules.iocs import load_suspect_terms


BENIGN_TERMS = {
    "http",
    "https",
    "kernel32",
    "kernel32.dll",
    "python",
    "python.exe",
    "python3.dll",
    "import",
    "os",
    "sys",
    "pathlib",
    "tkinter",
    "requests",
    "json",
    "re",
}

_ASCII_PATTERN = re.compile(rb"[A-Za-z0-9/\\\-.:_]{4,}")
_UTF16_PATTERN = re.compile(rb"(?:[^\x00-\x1f\x7f-\x9f]\x00){4,}")


def _build_suspect_pattern(suspect_terms):
    """Compile the suspect terms into a single alternation regex.

    Returns ``(pattern, ordered_terms)`` or ``None`` when no term survives
    the benign filter. One regex scan covers every term instead of compiling
    one regex per term per string.
    """
    terms = []
    for term in suspect_terms:
        normalized = term.strip()
        if not normalized or normalized.lower() in BENIGN_TERMS:
            continue
        terms.append(normalized)
    if not terms:
        return None
    ordered_terms = sorted(set(terms), key=len, reverse=True)
    body = "|".join(re.escape(term) for term in ordered_terms)
    pattern = re.compile(rf"(?<![A-Za-z0-9_])(?:{body})(?![A-Za-z0-9_])", re.IGNORECASE)
    return pattern, ordered_terms


def _extract_strings(binary_content):
    extracted = []

    for match in _ASCII_PATTERN.finditer(binary_content):
        extracted.append(match.group().decode("ascii", errors="ignore"))

    for match in _UTF16_PATTERN.finditer(binary_content):
        text = match.group().decode("utf-16le", errors="ignore").strip()
        if text:
            extracted.append(text)

    return list(dict.fromkeys(extracted))


def strings(filepath, content=None):
    suspect_terms, _, _ = load_suspect_terms()
    built = _build_suspect_pattern(suspect_terms)

    if content is None:
        with open(filepath, "rb") as f:
            binary_content = f.read()
    else:
        binary_content = content

    filtered_strings = _extract_strings(binary_content)
    found_alerts = []
    if built:
        pattern, ordered_terms = built
        for text in filtered_strings:
            matched_terms = {match.group(0) for match in pattern.finditer(text)}
            if not matched_terms:
                continue
            for term in ordered_terms:
                if term in matched_terms:
                    found_alerts.append(
                        f"Suspect term found: '{text}'. Trigger: '{term}'."
                    )

    return filtered_strings, found_alerts
