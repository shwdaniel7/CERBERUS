import os
import re


IOC_FOLDER = "iocs"
BLACKLIST_FILE = "blacklist.txt"
SUSPECT_STRINGS_FILE = "suspect_strings.txt"
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def _read_lines(filename):
    path = os.path.join(IOC_FOLDER, filename)
    if not os.path.exists(path):
        return path, [], []

    valid_lines = []
    malformed_lines = []
    with open(path, "r", encoding="utf-8") as ioc_file:
        for line_number, raw_line in enumerate(ioc_file, start=1):
            value = raw_line.split("#", 1)[0].strip()
            if not value:
                continue
            valid_lines.append((line_number, value))
    return path, valid_lines, malformed_lines


def load_blacklist():
    path, lines, malformed_lines = _read_lines(BLACKLIST_FILE)
    valid_hashes = []
    for line_number, value in lines:
        if SHA256_PATTERN.fullmatch(value):
            valid_hashes.append(value.lower())
        else:
            malformed_lines.append((line_number, value))
    return set(valid_hashes), malformed_lines, path


def load_suspect_terms():
    path, lines, malformed_lines = _read_lines(SUSPECT_STRINGS_FILE)
    valid_terms = []
    for line_number, value in lines:
        if len(value) >= 2:
            valid_terms.append(value)
        else:
            malformed_lines.append((line_number, value))
    return valid_terms, malformed_lines, path


def inspect_ioc_lists():
    blacklist, invalid_hashes, blacklist_path = load_blacklist()
    suspect_terms, invalid_terms, strings_path = load_suspect_terms()
    return {
        "blacklist": {
            "path": blacklist_path,
            "valid_count": len(blacklist),
            "invalid": invalid_hashes,
        },
        "suspect_strings": {
            "path": strings_path,
            "valid_count": len(suspect_terms),
            "invalid": invalid_terms,
        },
    }


def print_ioc_integrity():
    report = inspect_ioc_lists()
    print("\n--- IOC Lists Integrity ---")
    for list_name, details in report.items():
        print(f"\n[+] {list_name}: {details['valid_count']} valid entrie(s)")
        print(f"    File: {details['path']}")
        if not os.path.exists(details["path"]):
            print("    Status: file not found")
        elif details["invalid"]:
            print(f"    Malformed entrie(s): {len(details['invalid'])}")
            for line_number, value in details["invalid"]:
                print(f"      -> Line {line_number}: {value}")
        else:
            print("    Malformed entries: 0")

    print("\n[*] Lists are reloaded automatically at the start of each analysis.")
    print("[*] Edit the IOC text files, then run this option again to verify changes.")