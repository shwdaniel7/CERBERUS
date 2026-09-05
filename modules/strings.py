import re
from modules.iocs import load_suspect_terms

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
                if term.lower() in text.lower():
                    found_alerts.append(
                        f"Suspect term found: '{text}'. Trigger: '{term}'."
                    )

    return filtered_strings, found_alerts
