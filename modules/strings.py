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


def strings(filepath):
    suspect_terms, _, db_path = load_suspect_terms()
    if not suspect_terms and not db_path:
        return [], []

    text_pattern = re.compile(b"[A-Za-z0-9/\\-.:_]{4,}")
    filtered_strings = []
    found_alerts = []

    with open(filepath, "rb") as f:
        binary_content = f.read()

        for match in text_pattern.finditer(binary_content):
            text = match.group().decode("utf-8", errors="ignore")
            filtered_strings.append(text)

            for term in suspect_terms:
                normalized_term = term.strip().lower()
                if normalized_term in BENIGN_TERMS:
                    continue
                if _term_matches(text, term):
                    found_alerts.append(
                        f"Suspect term found: '{text}'. Trigger: '{term}'."
                    )

    return filtered_strings, found_alerts
