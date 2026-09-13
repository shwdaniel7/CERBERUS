//
// Office/VBA macro auto-run stubs.
//
// Original CERBERUS rule. Matches the classic VBA entry points malware uses
// to run a payload when the document is opened. Benign docs normally do not
// define these subs; the rule stays cheap and context-light by design.
//

rule cerberus_vba_autostart_macro : macro_execution {
    meta:
        description = "Office VBA AutoOpen / Workbook_Open / Document_Open entry point"
        author = "CERBERUS research"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1059/007/"

    strings:
        $a = "Sub AutoOpen" nocase
        $b = "Sub Auto_Open" nocase
        $c = "Sub Workbook_Open" nocase
        $d = "Sub Document_Open" nocase

    condition:
        any of them
}