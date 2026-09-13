//
// Embedded PE signature inside a non-PE container.
//
// Original CERBERUS rule. A file that does NOT start with the MZ magic but
// still contains an MZ header followed by a PE signature is a classic
// dropper/loader shape (installer, macro payload stub, packed blob).
//

rule cerberus_embedded_pe_signature : dropper {
    meta:
        description = "MZ + PE header present inside a file that does not start with MZ (embedded PE)"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1027/002/"

    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

    condition:
        uint16(0) != 0x5A4D
        and $mz in (1..filesize)
        and $pe in (1..filesize)
        and filesize < 20 * 1024 * 1024
}