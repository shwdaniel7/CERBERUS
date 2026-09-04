import csv
import html
import json
import os
import re
from datetime import datetime

CERBERUS_VERSION = "1.0.0"


def save_report(filepath, kb_size, file_hash, result_vt, alerts, all_strings, detected_bl, config_choices, entropy_score, entropy_status, real_type, magic_alert, risk, analysis_duration):
    reports_folder = "reports"
    if not os.path.exists(reports_folder):
        os.makedirs(reports_folder)

    base_name = os.path.basename(filepath)
    extension = os.path.splitext(base_name)[1].lower()
    byte_size = os.path.getsize(filepath)

    report_data = {
        "metadata": {
            "archive_name": base_name,
            "full_path": filepath,
            "kb_size": round(kb_size, 2),
            "byte_size": byte_size,
            "extension": extension,
            "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cerberus_version": CERBERUS_VERSION,
            "analysis_duration_seconds": analysis_duration
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
        static_analysis["all_strings"] = all_strings
    else:
        static_analysis["total_alerts"] = "Not executed"
        static_analysis["alerts"] = []
        static_analysis["all_strings"] = []

    vt_match = re.search(r"Flagged by VirusTotal: (\d+)/(\d+)", result_vt or "")
    vt_indicators = int(vt_match.group(1)) if vt_match else 0
    indicator_count = len(alerts) + int(bool(detected_bl)) + int(bool(magic_alert)) + vt_indicators
    if "CRITICAL" in (entropy_status or "") or "SUSPICIOUS" in (entropy_status or ""):
        indicator_count += 1
    static_analysis["indicator_count"] = indicator_count

    report_data["statistics_analysis"] = static_analysis
    report_data["risk_summary"] = risk

    short_hash = file_hash[:8] if file_hash else "no_hash"
    json_name = f"report_{base_name}_{short_hash}.json"
    finalpath = os.path.join(reports_folder, json_name)

    with open(finalpath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)

    save_csv_report(report_data, reports_folder, base_name, short_hash)
    save_html_report(report_data, reports_folder, base_name, short_hash)
        
    return finalpath


def save_csv_report(report_data, reports_folder, base_name, short_hash):
    metadata = report_data["metadata"]
    statistics = report_data["statistics_analysis"]
    risk = report_data["risk_summary"]
    csv_name = f"report_{base_name}_{short_hash}.csv"
    csv_path = os.path.join(reports_folder, csv_name)
    row = {
        "file_name": metadata["archive_name"],
        "full_path": metadata["full_path"],
        "extension": metadata["extension"],
        "byte_size": metadata["byte_size"],
        "sha256": report_data["signatures"].get("sha256", "") if isinstance(report_data["signatures"], dict) else "",
        "indicator_count": statistics["indicator_count"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "detected_type": statistics["magic_number_analysis"].get("detected_type", "") if isinstance(statistics["magic_number_analysis"], dict) else "",
        "entropy_score": statistics["entropy_analysis"].get("score", "") if isinstance(statistics["entropy_analysis"], dict) else "",
        "string_alert_count": statistics["total_alerts"] if isinstance(statistics["total_alerts"], int) else 0,
        "analysis_duration_seconds": metadata["analysis_duration_seconds"],
    }
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=row.keys())
        writer.writeheader()
        writer.writerow(row)


def save_html_report(report_data, reports_folder, base_name, short_hash):
    metadata = report_data["metadata"]
    statistics = report_data["statistics_analysis"]
    risk = report_data["risk_summary"]
    html_name = f"report_{base_name}_{short_hash}.html"
    html_path = os.path.join(reports_folder, html_name)
    risk_class = risk["level"].lower()
    factors = "".join(f"<li>{html.escape(factor)}</li>" for factor in risk["factors"])
    alerts = html.escape(json.dumps(statistics["alerts"], indent=2, ensure_ascii=False))
    all_strings = html.escape(json.dumps(statistics["all_strings"], indent=2, ensure_ascii=False))
    technical_data = html.escape(json.dumps(statistics, indent=2, ensure_ascii=False))

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CERBERUS Report - {html.escape(metadata['archive_name'])}</title>
    <style>
        :root {{ font-family: Arial, sans-serif; color: #17202a; background: #eef2f5; }}
        body {{ max-width: 960px; margin: 32px auto; padding: 0 20px; }}
        header, section {{ background: #fff; border: 1px solid #d8dee4; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
        h1, h2 {{ margin-top: 0; }}
        .risk {{ border-left: 8px solid #2e7d32; }}
        .risk.moderate {{ border-left-color: #c58b00; }}
        .risk.high, .risk.critical {{ border-left-color: #c62828; }}
        .score {{ font-size: 2rem; font-weight: bold; }}
        dl {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
        dt {{ color: #59636e; font-size: .85rem; }}
        dd {{ margin: 4px 0 0; font-weight: bold; overflow-wrap: anywhere; }}
        pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f5f7f9; padding: 12px; border-radius: 4px; }}
    </style>
</head>
<body>
    <header>
        <h1>CERBERUS Static Analysis Report</h1>
        <p>{html.escape(metadata['archive_name'])}</p>
    </header>
    <section class="risk {html.escape(risk_class)}">
        <h2>Risk Summary</h2>
        <div class="score">{risk['level']} ({risk['score']}/100)</div>
        <ul>{factors}</ul>
    </section>
    <section>
        <h2>File Metadata</h2>
        <dl>
            <div><dt>Extension</dt><dd>{html.escape(metadata['extension'])}</dd></div>
            <div><dt>Size</dt><dd>{metadata['byte_size']} bytes</dd></div>
            <div><dt>SHA-256</dt><dd>{html.escape(report_data['signatures'].get('sha256', 'Not executed') if isinstance(report_data['signatures'], dict) else 'Not executed')}</dd></div>
            <div><dt>Detected type</dt><dd>{html.escape(statistics['magic_number_analysis'].get('detected_type', 'Not executed') if isinstance(statistics['magic_number_analysis'], dict) else 'Not executed')}</dd></div>
            <div><dt>Indicators</dt><dd>{statistics['indicator_count']}</dd></div>
            <div><dt>Analysis duration</dt><dd>{metadata['analysis_duration_seconds']} seconds</dd></div>
        </dl>
    </section>
    <section>
        <details><summary>Suspicious alerts ({statistics['total_alerts']})</summary><pre>{alerts}</pre></details>
        <details><summary>Extracted strings ({len(statistics['all_strings'])})</summary><pre>{all_strings}</pre></details>
        <details><summary>Technical analysis</summary><pre>{technical_data}</pre></details>
    </section>
</body>
</html>
"""
    with open(html_path, "w", encoding="utf-8") as html_file:
        html_file.write(document)


def list_analysis_history(reports_folder="reports"):
    if not os.path.isdir(reports_folder):
        print("\n[-] No analysis history found.")
        return

    search_term = input(
        "\n[?] Filter by file name, SHA-256, or risk level (leave blank for all): "
    ).strip().lower()
    reports = []

    for filename in os.listdir(reports_folder):
        if not filename.lower().endswith(".json"):
            continue
        report_path = os.path.join(reports_folder, filename)
        try:
            with open(report_path, "r", encoding="utf-8") as report_file:
                report_data = json.load(report_file)
        except (OSError, json.JSONDecodeError):
            continue

        metadata = report_data.get("metadata", {})
        signatures = report_data.get("signatures", {})
        risk = report_data.get("risk_summary", {})
        searchable_values = [
            str(metadata.get("archive_name", "")),
            str(signatures.get("sha256", "")) if isinstance(signatures, dict) else "",
            str(risk.get("level", "")),
        ]
        if search_term and not any(search_term in value.lower() for value in searchable_values):
            continue
        reports.append((metadata, signatures, risk, filename))

    reports.sort(key=lambda item: item[0].get("analysis_date", ""), reverse=True)
    print(f"\n--- Analysis History ({len(reports)} result(s)) ---")
    if not reports:
        print("[-] No reports matched the selected filter.")
        return

    for metadata, signatures, risk, filename in reports:
        file_name = metadata.get("archive_name", "Unknown file")
        date = metadata.get("analysis_date", "Unknown date")
        sha256 = signatures.get("sha256", "Not available") if isinstance(signatures, dict) else "Not available"
        level = risk.get("level", "Unknown")
        score = risk.get("score", "-")
        print(f"\n[+] {file_name}")
        print(f"    Date: {date} | Risk: {level} ({score}/100)")
        print(f"    SHA-256: {sha256}")
        print(f"    Report: {os.path.join(reports_folder, filename)}")


def save_batch_summary(folder_path, results, duration_seconds, reports_folder="reports", skipped=None):
    os.makedirs(reports_folder, exist_ok=True)
    skipped = skipped or []
    summary = {
        "folder": folder_path,
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files_found": len(results) + len(skipped),
        "files_selected": len(results),
        "files_analyzed": sum(1 for result in results if result.get("success")),
        "files_failed": sum(1 for result in results if not result.get("success")),
        "reports_generated": sum(1 for result in results if result.get("report_generated")),
        "reports_skipped_by_risk": sum(
            1 for result in results
            if result.get("success") and not result.get("report_generated")
        ),
        "files_skipped": len(skipped),
        "duration_seconds": duration_seconds,
        "risk_levels": {},
        "skipped_files": skipped,
        "files": results,
    }
    for result in results:
        level = result.get("risk_level", "Unknown")
        summary["risk_levels"][level] = summary["risk_levels"].get(level, 0) + 1

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(reports_folder, f"batch_summary_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=4, ensure_ascii=False)
    return json_path
