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


def detect_packers(filepath, content=None):
    """Detect known packer signatures and return evidence, not a malware verdict.

    Accepts an optional ``content`` byte buffer (from a shared single read);
    otherwise the file is opened directly.
    """
    if content is None:
        with open(filepath, "rb") as file_handle:
            data = file_handle.read()
    else:
        data = content

    detected = {}
    for packer_name, signatures in PACKER_SIGNATURES.items():
        evidence = []
        for signature in signatures:
            matches = signature.findall(data)
            evidence.extend(
                match.decode("ascii", errors="replace")
                if isinstance(match, (bytes, bytearray, memoryview)) else match
                for match in matches
            )
        if evidence:
            detected[packer_name] = list(dict.fromkeys(evidence))

    return {
        "detected": bool(detected),
        "packers": detected,
        "note": "Packer signatures provide context for entropy and are not proof of malware.",
    }
