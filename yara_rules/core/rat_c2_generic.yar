//
// Generic RAT / C2 framework markers (informational).
//
// Original CERBERUS rule. Low severity on purpose: "meterpreter" can appear
// in tooling logs and docs, so this rule flags context for the analyst to
// weigh, it does not by itself decide the file is malicious.
//

rule cerberus_meterpreter_session : c2_framework {
    meta:
        description = "Metasploit Meterpreter string present (contextual)"
        author = "CERBERUS research"
        severity = "low"
        reference = "https://attack.mitre.org/techniques/T1219/"

    strings:
        $a = "meterpreter" nocase

    condition:
        $a and filesize < 5 * 1024 * 1024
}