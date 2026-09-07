try:
    import pefile
except ImportError:
    pefile = None


def _empty_result(status, **extra):
    result = {
        "status": status,
        "available": pefile is not None,
        "is_mz": False,
        "has_pe_signature": False,
        "number_of_sections": 0,
        "sections": [],
        "note": "PE structure is descriptive evidence, not proof of malware.",
    }
    result.update(extra)
    return result


def analyze_pe(filepath):
    """Analyze PE headers and sections when pefile is installed."""
    with open(filepath, "rb") as file_handle:
        header = file_handle.read(2)

    if header != b"MZ":
        return _empty_result("not_mz")
    if pefile is None:
        return _empty_result("unavailable", is_mz=True)

    try:
        portable_executable = pefile.PE(filepath, fast_load=True)
        sections = []
        for section in portable_executable.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            sections.append({
                "name": name,
                "raw_size": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
                "entropy": round(section.get_entropy(), 2),
            })

        return {
            "status": "analyzed",
            "available": True,
            "is_mz": True,
            "has_pe_signature": portable_executable.NT_HEADERS.Signature == 0x4550,
            "number_of_sections": len(sections),
            "sections": sections,
            "note": "PE structure is descriptive evidence, not proof of malware.",
        }
    except (OSError, pefile.PEFormatError, AttributeError, ValueError) as error:
        return _empty_result("invalid_pe", is_mz=True, error=str(error))
