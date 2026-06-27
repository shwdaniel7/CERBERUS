import json
import os
from datetime import datetime

def save_report(filepath, kb_size, file_hash, result_vt, alerts, detected_bl, config_choices, entropy_score, entropy_status, real_type, magic_alert):
    reports_folder = "reports"
    if not os.path.exists(reports_folder):
        os.makedirs(reports_folder)

    base_name = os.path.basename(filepath)

    report_data = {
        "metadata": {
            "archive_name": base_name,
            "full_path": filepath,
            "kb_size": round(kb_size, 2),
            "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }

    if config_choices["blacklist"] or config_choices["virustotal"]:
        report_data["signatures"] = {"sha256": file_hash}
    else:
        report_data["signatures"] = "Not executed"

    if config_choices["virustotal"]:
        report_data["virustotal_analysis"] = {"virustotal": result_vt}
    else:
        report_data["virustotal_analysis"] = "Not executed"

    static_analysis = {}

    if config_choices["blacklist"]:
        static_analysis["blacklist_local"] = "DETECTED (Known Malware)" if detected_bl else "Clean / Not found"
    else:
        static_analysis["blacklist_local"] = "Not executed"

    if config_choices["entropy"]:
        static_analysis["entropy_analysis"] = {
            "score": entropy_score,
            "status": entropy_status
        }
    else:
        static_analysis["entropy_analysis"] = "Not executed"

    if config_choices["magic_numbers"]:
        static_analysis["magic_number_analysis"] = {
            "detected_type": real_type,
            "masquerade_alert": magic_alert if magic_alert else "None (Extension matches header)"
        }
    else:
        static_analysis["magic_number_analysis"] = "Not executed"

    if config_choices["strings"]:
        static_analysis["total_alerts"] = len(alerts)
        static_analysis["alerts"] = alerts
    else:
        static_analysis["total_alerts"] = "Not executed"
        static_analysis["alerts"] = []

    report_data["statistics_analysis"] = static_analysis

    short_hash = file_hash[:8] if file_hash else "no_hash"
    json_name = f"report_{base_name}_{short_hash}.json"
    finalpath = os.path.join(reports_folder, json_name)

    with open(finalpath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
        
    return finalpath
