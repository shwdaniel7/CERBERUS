//
// File staging via built-in Windows binaries (bitsadmin / certutil).
//
// Original CERBERUS rules. These tools are dual-use: the rules require the
// transfer-and-run combination, not the bare tool names.
//

rule cerberus_cmd_bitsadmin_stage : c2_execution {
    meta:
        description = "bitsadmin /transfer + powershell (LOLBin file staging)"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1059/003/"

    strings:
        $bits = "bitsadmin" nocase
        $tran = "/transfer" nocase
        $or = "/download" nocase
        $ps = "powershell" nocase

    condition:
        $bits and $tran and $or and $ps
}

rule cerberus_cmd_certutil_decode : c2_execution {
    meta:
        description = "certutil -urlcache + -decode LOBbin (certutil -decode / -urlcache)"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1140/"

    strings:
        $cert = "certutil" nocase
        $decode = "-decode" nocase
        $urlcache = "-urlcache" nocase

    condition:
        $cert and $decode and $urlcache
}