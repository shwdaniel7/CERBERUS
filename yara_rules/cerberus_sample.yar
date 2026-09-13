//
// CERBERUS example YARA rules.
//
// Drop your own .yar / .yara files anywhere under this folder (subfolders
// such as yara_rules/core/ are scanned too; yara_rules/templates/ holds
// commented skeletons, not live rules). Every valid file is compiled per
// scan and matched against each candidate. This example rule is
// deliberately inert for normal files: it only fires on the literal
// "CERBERUS-MARKER" string, so it is safe to keep checked by default.
//
// See docs/YARA_RULES.md for the beginner guide and rule-writing tips.
//
rule cerberus_example_marker {
    meta:
        description = "Example rule shipped with CERBERUS; replace with real rules."
    strings:
        $marker = "CERBERUS-MARKER"
    condition:
        $marker
}