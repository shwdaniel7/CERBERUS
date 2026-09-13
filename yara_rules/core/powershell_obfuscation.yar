//
// PowerShell download-and-execute / obfuscated-cradle detection.
//
// Original CERBERUS rules. Each one fires only on combined evidence, so
// harmless mentions of DownloadString/FromBase64String or of -EncodedCommand
// alone do not trip them.
//

rule cerberus_ps_iex_downloader : c2_execution {
    meta:
        description = "PowerShell download-and-execute cradle (DownloadString/FromBase64String + IEX)"
        author = "CERBERUS research"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1059/001/"

    strings:
        $a = "DownloadString"
        $c = "FromBase64String"
        $b = "Invoke-Expression" nocase

    condition:
        ($a or $c) and $b
}

rule cerberus_ps_encoded_command : obfuscation {
    meta:
        description = "PowerShell -EncodedCommand/-enc switch present"
        author = "CERBERUS research"
        severity = "high"
        reference = "https://attack.mitre.org/techniques/T1027/010/"

    strings:
        $enc = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase

    condition:
        $enc or $enc2
}