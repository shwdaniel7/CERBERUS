//
// Web-shell PHP scripts.
//
// Original CERBERUS rule. `eval`/`assert`/`system` fed directly from a
// request superglobal is the canonical one-line web shell; plain PHP code
// does not contain this shape.
//

rule cerberus_php_webshell : webshell {
    meta:
        description = "PHP one-line web shell (eval/assert/system over request superglobal)"
        author = "CERBERUS research"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1505/003/"

    strings:
        $a = "eval($_POST" nocase
        $b = "eval($_REQUEST" nocase
        $c = "assert($_POST" nocase
        $d = "assert($_REQUEST" nocase
        $e = "system($_POST" nocase
        $f = "system($_REQUEST" nocase

    condition:
        any of them
}