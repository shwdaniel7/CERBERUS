//
// Registry persistence keys and scheduled-task autostart (Windows).
//
// Original CERBERUS rules. Note the escaped backslashes: YARA strings follow
// C-style escaping, so `\\` inside the literal maps to a real `\`.
//

rule cerberus_reg_run_persistence : persistence {
    meta:
        description = "Registry Run/RunOnce persistence key reference"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1547/001/"

    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase

    condition:
        $run1 or $run2
}

rule cerberus_schtasks_onlogon : persistence {
    meta:
        description = "schtasks autostart (onlogon/onstart) command"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1053/005/"

    strings:
        $create = "/create" nocase
        $onlogon = "/sc onlogon" nocase
        $onstart = "/sc onstart" nocase

    condition:
        $create and ($onlogon or $onstart)
}