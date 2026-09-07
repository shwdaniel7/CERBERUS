import os


SIGNATURES = (
    (b"MZ", "Windows Executable (EXE/DLL)", {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}),
    (b"\x7fELF", "Linux Executable (ELF)", {"", ".elf", ".so", ".bin"}),
    (b"%PDF", "PDF Document", {".pdf"}),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", {".png"}),
    (b"GIF8", "GIF Image", {".gif"}),
    (b"\xff\xd8\xff", "JPEG Image", {".jpg", ".jpeg"}),
    (b"PK\x03\x04", "ZIP/Office Archive", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"Rar!\x1a\x07\x00", "RAR Archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", {".7z"}),
    (b"\x1f\x8b", "GZIP Archive", {".gz", ".tgz"}),
    (b"BZh", "BZIP2 Archive", {".bz2"}),
    (b"\xfd7zXZ\x00", "XZ Archive", {".xz"}),
    (b"\x89HDF\r\n\x1a\n", "HDF5 Data File", {".h5", ".hdf5"}),
)


def _detect_signature(header_bytes):
    if header_bytes.startswith(b"RIFF") and header_bytes[8:12] == b"WAVE":
        return "WAV Audio", {".wav"}
    if header_bytes.startswith(b"RIFF") and header_bytes[8:12] == b"AVI ":
        return "AVI Video", {".avi"}
    if header_bytes.startswith(b"RIFF") and header_bytes[8:12] == b"WEBP":
        return "WebP Image", {".webp"}
    if header_bytes.startswith(b"ID3") or header_bytes[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "MP3 Audio", {".mp3"}
    if header_bytes.startswith(b"OggS"):
        return "OGG Multimedia", {".ogg", ".oga", ".ogv"}
    if header_bytes.startswith(b"fLaC"):
        return "FLAC Audio", {".flac"}
    if header_bytes.startswith(b"\x00\x00\x01\x00"):
        return "ICO Image", {".ico"}

    for signature, detected_type, compatible_extensions in SIGNATURES:
        if header_bytes.startswith(signature):
            return detected_type, compatible_extensions
    return "Unknown/Generic Type", set()


def analyze_file_type(filepath):
    declared_extension = os.path.splitext(os.path.basename(filepath))[1].lower()
    with open(filepath, "rb") as file_handle:
        header_bytes = file_handle.read(32)

    detected_type, compatible_extensions = _detect_signature(header_bytes)
    if detected_type == "Unknown/Generic Type":
        compatibility = "Unknown"
        compatible = None
    elif declared_extension in compatible_extensions:
        compatibility = "Compatible"
        compatible = True
    else:
        compatibility = "Mismatch"
        compatible = False

    alert = None
    if compatibility == "Mismatch":
        alert = (
            f"[!!!] TYPE MISMATCH: declared extension '{declared_extension or '(none)'}' "
            f"but detected type is '{detected_type}'."
        )

    return {
        "declared_extension": declared_extension or "(none)",
        "detected_type": detected_type,
        "compatibility": compatibility,
        "compatible": compatible,
        "alert": alert,
    }


def check_magic_number(filepath):
    """Backward-compatible tuple API for callers using the original engine."""
    result = analyze_file_type(filepath)
    return result["detected_type"], result["alert"]
