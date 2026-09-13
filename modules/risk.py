import re

HIGH_SIGNAL_TERMS = {
    "keylogger",
    "virtualalloc",
    "powershell",
    "cmd.exe",
}


def calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert, iocs=None, yara_matches=None):
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