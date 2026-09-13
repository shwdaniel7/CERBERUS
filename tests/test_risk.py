"""Unit tests for the transparent risk score."""

from modules.risk import HIGH_SIGNAL_TERMS, calculate_risk


def _risk(in_blacklist=False, result_vt=None, entropy_status=None, alerts=None,
          magic_alert=None, iocs=None):
    return calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert, iocs)


def test_clean_file_is_low():
    risk = _risk()
    assert risk["score"] == 0
    assert risk["level"] == "Low"
    assert risk["factors"] == ["No risk indicators were detected"]


def test_blacklist_adds_40():
    risk = _risk(in_blacklist=True)
    assert risk["score"] == 40
    assert risk["level"] == "Moderate"
    assert "local blacklist (+40)" in risk["factors"][0]


def test_virustotal_ratio_is_fractional():
    risk = _risk(result_vt={"malicious": 10, "suspicious": 0, "harmless": 0, "undetected": 10})
    assert risk["score"] == 18  # round(10/20*35)
    assert risk["level"] == "Low"  # 18 < 20


def test_virustotal_string_form_parsed():
    risk = _risk(result_vt="Flagged by VirusTotal: 5/10")
    assert risk["score"] == 18


def test_virustotal_capped_at_35():
    risk = _risk(result_vt={"malicious": 20, "suspicious": 0, "harmless": 0, "undetected": 0})
    assert risk["score"] == 35


def test_virustotal_zero_malicious_no_points():
    risk = _risk(result_vt={"malicious": 0, "suspicious": 5, "harmless": 10, "undetected": 5})
    assert risk["score"] == 0


def test_virustotal_missing_fields_no_points():
    assert _risk(result_vt={"status": "error"})["score"] == 0


def test_entropy_indicator_points():
    assert _risk(entropy_status="Very high entropy INDICATOR")["score"] == 5
    assert _risk(entropy_status="High entropy INDICATOR")["score"] == 3
    assert _risk(entropy_status="NORMAL: 0.1234")["score"] == 0


def test_high_signal_string_alert_weights_more():
    risk = _risk(alerts=["powershell.exe -enc"])
    assert risk["score"] == 20  # 4 + 16
    factor = risk["factors"][0]
    assert "high-signal" in factor


def test_string_alerts_capped_at_30():
    alerts = [f"generic thing {index}" for index in range(10)]
    risk = _risk(alerts=alerts)
    assert risk["score"] == 30


def test_magic_mismatch_adds_15():
    risk = _risk(magic_alert="[!!!] TYPE MISMATCH")
    assert risk["score"] == 15


def test_suspicious_iocs_capped_at_12():
    iocs = {
        "suspicious_paths": ["/tmp/x", "/etc/passwd"],
        "powershell_commands": ["powershell -enc AAAA"],
        "cmd_commands": ["cmd /c whoami"],
        "urls": ["https://benign.example/x"],  # not counted
    }
    risk = _risk(iocs=iocs)
    assert risk["score"] == 12  # 4 suspicious * 3, capped at 12


def test_suspicious_ioc_count_rules():
    assert _risk(iocs=None)["score"] == 0
    iocs = {"suspicious_paths": ["/tmp/x"]}
    assert _risk(iocs=iocs)["score"] == 3


def test_combined_score_caps_at_100_critical():
    risk = _risk(
        in_blacklist=True,
        result_vt={"malicious": 30, "suspicious": 0, "harmless": 0, "undetected": 10},
        entropy_status="Very high entropy INDICATOR",
        alerts=["keylogger detected", "unknown thing"],
        magic_alert="mismatch",
        iocs={"powershell_commands": ["powershell -w hidden -e AAAAAA"]},
    )
    assert risk["score"] == 100
    assert risk["level"] == "Critical"


def test_level_boundaries():
    assert _risk(in_blacklist=True)["level"] == "Moderate"            # 40
    assert _risk(magic_alert="x", alerts=["a", "b"])["level"] == "Moderate"  # 23
    high = _risk(in_blacklist=True, magic_alert="x")
    assert high["level"] == "High" and high["score"] == 55
    critical = _risk(in_blacklist=True, result_vt={"malicious": 20, "undetected": 0, "suspicious": 0, "harmless": 0})
    assert critical["level"] == "Critical" and critical["score"] == 75


def test_high_signal_terms_are_defined():
    assert HIGH_SIGNAL_TERMS <= {"keylogger", "virtualalloc", "powershell", "cmd.exe"}