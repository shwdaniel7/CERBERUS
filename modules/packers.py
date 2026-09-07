import re


PACKER_SIGNATURES = {
    "PyInstaller": (
        re.compile(rb"MEI\x0c\x0b\x0a\x0b\x0e", re.IGNORECASE),
        re.compile(rb"_MEIPASS|pyimod|PYZ-\d+\.pyz|pyinstaller", re.IGNORECASE),
    ),
    "UPX": (
        re.compile(rb"UPX[0-9A-Z!]{0,3}", re.IGNORECASE),
        re.compile(rb"UPX0|UPX1|UPX2", re.IGNORECASE),
    ),
}


def detect_packers(filepath):
    """Detect known packer signatures and return evidence, not a malware verdict."""
    with open(filepath, "rb") as file_handle:
        data = file_handle.read()

    detected = {}
    for packer_name, signatures in PACKER_SIGNATURES.items():
        evidence = []
        for signature in signatures:
            matches = signature.findall(data)
            evidence.extend(
                match.decode("ascii", errors="replace")
                if isinstance(match, bytes) else match
                for match in matches
            )
        if evidence:
            detected[packer_name] = list(dict.fromkeys(evidence))

    return {
        "detected": bool(detected),
        "packers": detected,
        "note": "Packer signatures provide context for entropy and are not proof of malware.",
    }
