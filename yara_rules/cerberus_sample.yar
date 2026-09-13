//
// CERBERUS example YARA rules.
//
// Drop your own .yar / .yara files in this folder; every valid file is
// compiled per scan and matched against each candidate. This example rule is
// deliberately inert for normal files: it only fires on the literal
// "CERBERUS-MARKER" string, so it is safe to keep checked by default.
//
rule cerberus_example_marker {
    meta:
        description = "Example rule shipped with CERBERUS; replace with real rules."
    strings:
        $marker = "CERBERUS-MARKER"
    condition:
        $marker
}