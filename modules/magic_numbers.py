import os

def check_magic_number(filepath):
    magic_signatures = {
        b"MZ": "Windows Executable (EXE/DLL)",
        b"\x7fELF": "Linux Executable (ELF)",
        b"%PDF": "PDF Document",
        b"\x89PNG": "PNG Image",
        b"GIF8": "GIF Image",
        b"\xff\xd8\xff": "JPEG Image",
        b"PK\x03\x04": "ZIP/Office Archive (DOCX/XLSX)"
    }
    
    base_name = os.path.basename(filepath)
    current_ext = os.path.splitext(base_name)[1].lower()
    
    with open(filepath, "rb") as f:
        header_bytes = f.read(4)
        
    real_type = "Unknown/Generic Type"
    
    for sig, name in magic_signatures.items():
        if header_bytes.startswith(sig):
            real_type = name
            break
            
    is_pe_disguised = header_bytes.startswith(b"MZ") and current_ext not in [".exe", ".dll", ".sys", ".scr"]
    
    if is_pe_disguised:
        alert = f"[!!!] MASQUERADE ALERT: File ends in '{current_ext}' but header says it's a '{real_type}'!"
    else:
        alert = None
        
    return real_type, alert
