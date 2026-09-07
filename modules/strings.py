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


def _term_matches(text, term):
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def _extract_strings(binary_content):
    ascii_pattern = re.compile(rb"[A-Za-z0-9/\\\-.:_]{4,}")
    utf16_pattern = re.compile(rb"(?:[^\x00-\x1f\x7f-\x9f]\x00){4,}")
    extracted = []

    for match in ascii_pattern.finditer(binary_content):
        extracted.append(match.group().decode("ascii", errors="ignore"))

    for match in utf16_pattern.finditer(binary_content):
        text = match.group().decode("utf-16le", errors="ignore").strip()
        if text:
            extracted.append(text)

    return list(dict.fromkeys(extracted))


def strings(filepath):
    suspect_terms, _, db_path = load_suspect_terms()
    filtered_strings = []
    found_alerts = []

    with open(filepath, "rb") as f:
        binary_content = f.read()

        filtered_strings = _extract_strings(binary_content)
        for text in filtered_strings:

            for term in suspect_terms:
                normalized_term = term.strip().lower()
                if normalized_term in BENIGN_TERMS:
                    continue
                if _term_matches(text, term):
                    found_alerts.append(
                        f"Suspect term found: '{text}'. Trigger: '{term}'."
                    )

    return filtered_strings, found_alerts
