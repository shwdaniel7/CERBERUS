import re

HIGH_SIGNAL_TERMS = {
    "keylogger",
    "virtualalloc",
    "powershell",
    "cmd.exe",
}


def calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert):
    score = 0
    factors = []

    if in_blacklist:
        score += 40
        factors.append("Hash found in local blacklist (+40)")

    vt_match = re.search(r"Flagged by VirusTotal: (\d+)/(\d+)", result_vt or "")
    if vt_match:
        malicious_count = int(vt_match.group(1))
        total_engines = int(vt_match.group(2))
        if malicious_count and total_engines:
            virus_total_points = round(min(35, malicious_count / total_engines * 35))
            score += virus_total_points
            factors.append(
                f"VirusTotal flagged {malicious_count}/{total_engines} engines (+{virus_total_points})"
            )

    if "CRITICAL" in (entropy_status or ""):
        score += 15
        factors.append("Very high entropy, possible packing or encryption (+15)")
    elif "SUSPICIOUS" in (entropy_status or ""):
        score += 8
        factors.append("High entropy, possible compression or obfuscation (+8)")

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