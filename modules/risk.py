import re

HIGH_SIGNAL_TERMS = {
    "keylogger",
    "virtualalloc",
    "powershell",
    "cmd.exe",
}

DECODE_FLAGGED_POINTS = 10

DECODE_FLAG_LABEL = "Deobfuscation"

FUZZY_EXACT_DISTANCE = 10
FUZZY_CLOSE_DISTANCE = 30
FUZZY_EXACT_POINTS = 20
FUZZY_CLOSE_POINTS = 10
FUZZY_LOOSE_POINTS = 5
FUZZY_LABEL = "Fuzzy similarity"

ZIP_TRAVERSAL_POINTS = 15
ZIP_BOMB_POINTS = 15
ZIP_EXECUTABLE_POINTS = 10
ZIP_SCRIPT_POINTS = 5
ZIP_LABEL = "Archive (ZIP)"


def calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert, iocs=None, yara_matches=None, deobfuscation_analysis=None, fuzzy_analysis=None, zip_analysis=None):
    score = 0
    factors = []

    if in_blacklist:
        score += 40
        factors.append("Hash found in local blacklist (+40)")

    if isinstance(result_vt, dict):
        malicious_count = int(result_vt.get("malicious", 0))
        total_engines = sum(
            int(result_vt.get(category, 0))
            for category in ("malicious", "suspicious", "harmless", "undetected")
        )
    else:
        vt_match = re.search(r"Flagged by VirusTotal: (\d+)/(\d+)", result_vt or "")
        malicious_count = int(vt_match.group(1)) if vt_match else 0
        total_engines = int(vt_match.group(2)) if vt_match else 0
    if malicious_count or total_engines:
        if malicious_count and total_engines:
            virus_total_points = round(min(35, malicious_count / total_engines * 35))
            score += virus_total_points
            factors.append(
                f"VirusTotal flagged {malicious_count}/{total_engines} engines (+{virus_total_points})"
            )

    if "INDICATOR" in (entropy_status or ""):
        entropy_points = 5 if "Very high" in entropy_status else 3
        score += entropy_points
        factors.append(
            f"High entropy is an indicator of possible compression or packing, not proof of malware (+{entropy_points})"
        )

    if alerts:
        high_signal_alerts = sum(
            any(term in alert.lower() for term in HIGH_SIGNAL_TERMS)
            for alert in alerts
        )
        string_points = min(30, len(alerts) * 4 + high_signal_alerts * 16)
        score += string_points
        if high_signal_alerts:
            factors.append(
                f"{high_signal_alerts} high-signal string alert(s) (+{string_points})"
            )
        else:
            factors.append(f"{len(alerts)} suspicious string alert(s) (+{string_points})")

    if magic_alert:
        score += 15
        factors.append("File extension does not match its header (+15)")

    suspicious_iocs = sum(
        len(iocs.get(category, []))
        for category in ("suspicious_paths", "powershell_commands", "cmd_commands")
    ) if iocs else 0
    if suspicious_iocs:
        ioc_points = min(12, suspicious_iocs * 3)
        score += ioc_points
        factors.append(
            f"{suspicious_iocs} suspicious path/command IOC(s) (+{ioc_points})"
        )

    if deobfuscation_analysis and deobfuscation_analysis.get("flagged"):
        reasons = deobfuscation_analysis.get("flag_reasons") or []
        score += DECODE_FLAGGED_POINTS
        factors.append(
            f"{DECODE_FLAG_LABEL}: {reasons[0] if reasons else 'suspicious decoded payload'} "
            f"(+{DECODE_FLAGGED_POINTS})"
        )

    if fuzzy_analysis and fuzzy_analysis.get("match_count"):
        nearest = fuzzy_analysis.get("nearest_distance")
        if nearest is not None:
            if nearest <= FUZZY_EXACT_DISTANCE:
                fuzzy_points = FUZZY_EXACT_POINTS
            elif nearest <= FUZZY_CLOSE_DISTANCE:
                fuzzy_points = FUZZY_CLOSE_POINTS
            else:
                fuzzy_points = FUZZY_LOOSE_POINTS
            score += fuzzy_points
            label = fuzzy_analysis["matches"][0]["label"]
            factors.append(
                f"{FUZZY_LABEL}: close match to '{label}' (TLSH distance {nearest}, +{fuzzy_points})"
            )

    if zip_analysis:
        zip_findings = zip_analysis.get("findings") or {}
        if zip_findings.get("traversal_attempt"):
            score += ZIP_TRAVERSAL_POINTS
            factors.append(f"{ZIP_LABEL}: traversal / absolute-path member (+{ZIP_TRAVERSAL_POINTS})")
        if zip_findings.get("high_compression_ratio"):
            score += ZIP_BOMB_POINTS
            factors.append(f"{ZIP_LABEL}: high compression ratio (zip-bomb shape, +{ZIP_BOMB_POINTS})")
        if zip_findings.get("embedded_executable"):
            score += ZIP_EXECUTABLE_POINTS
            factors.append(f"{ZIP_LABEL}: executable member inside archive (+{ZIP_EXECUTABLE_POINTS})")
        if zip_findings.get("suspicious_script"):
            score += ZIP_SCRIPT_POINTS
            factors.append(f"{ZIP_LABEL}: script member inside archive (+{ZIP_SCRIPT_POINTS})")

    if yara_matches:
        from modules.yara_engine import MAX_YARA_RISK_POINTS, severity_points
        yara_points = min(MAX_YARA_RISK_POINTS, sum(
            int(match.get("points", severity_points(match.get("severity"))))
            if isinstance(match, dict) else severity_points(None)
            for match in yara_matches
        ))
        score += yara_points
        details = "; ".join(
            f"{(match.get('description') or match.get('rule') or 'YARA match')} "
            f"({match.get('severity', 'medium')}, +{match.get('points')})"
            for match in yara_matches if isinstance(match, dict)
        ) or f"{len(yara_matches)} YARA rule(s) matched"
        factors.append(f"YARA: {details} (+{yara_points})")

    score = min(100, score)
    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 20:
        level = "Moderate"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "factors": factors or ["No risk indicators were detected"],
    }