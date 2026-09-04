import os
import time
import tkinter as tk
from tkinter.filedialog import askdirectory, askopenfilename

from modules.strings import strings 
from modules.hashes import calc_sha256, check_local_blacklist, virustotal_check
from modules.reports import list_analysis_history, save_batch_summary, save_report
from modules.risk import calculate_risk
from modules.menu import optionsMenu
from modules.colors import paint_red, paint_green, paint_yellow, paint_cyan, paint_bold

root = tk.Tk()
root.withdraw()

def uploadFile():
    filepath = askopenfilename(
        title="Select a file", initialdir="C:/", filetypes=[("All", "*.*")]
    )
    return filepath


def upload_folder():
    return askdirectory(title="Select a folder to analyze", initialdir="C:/")


def analyze_file(selected_file, config, show_details=True):
    byte_size = os.path.getsize(selected_file)
    kb_size = byte_size / 1024
    if show_details:
        print(f"\n[+] File: {paint_bold(selected_file)}")
        print(f"[+] Size: {paint_yellow(f'{kb_size:.2f} KB')}")

    analysis_start = time.perf_counter()
    hash_result = None
    in_blacklist = None
    result_vt = "Not selected in the configuration."
    all_strings = []
    alerts = []
    entropy_score = 0.0
    entropy_status = "Not executed"
    real_type = "Not executed"
    magic_alert = None

    if config["blacklist"] or config["virustotal"]:
        if show_details:
            print(paint_cyan("\n--- Generating a File Signature ---"))
        hash_result = calc_sha256(selected_file)
        if show_details:
            print(f"[+] SHA256: {paint_yellow(hash_result)}")

    if config["blacklist"]:
        if show_details:
            print(paint_cyan("\n--- Consulting Local Blacklist ---"))
        in_blacklist = check_local_blacklist(hash_result)
        if show_details:
            if in_blacklist:
                print(paint_red("[!!!] CRITICAL ALERT: This hash is in the local blacklist!"))
            else:
                print(paint_green("[+] Hash is clean in the local control list."))

    if config["virustotal"]:
        if show_details:
            print(paint_cyan("\n--- Consulting VirusTotal API ---"))
        result_vt = virustotal_check(hash_result)
        if show_details:
            output_color = paint_red if "Flagged" in result_vt else paint_green
            print(f"[->] {output_color(result_vt)}")

    if config["magic_numbers"]:
        if show_details:
            print(paint_cyan("\n--- Consulting Magic Signature ---"))
        from modules.magic_numbers import check_magic_number
        real_type, magic_alert = check_magic_number(selected_file)
        if show_details:
            print(f"[+] Real Type Detected: {paint_yellow(real_type)}")
            if magic_alert:
                print(paint_red(magic_alert))

    if config["entropy"]:
        if show_details:
            print(paint_cyan("\n--- Calculating Shannon Entropy ---"))
        from modules.entropy import calculate_entropy
        entropy_score, entropy_status = calculate_entropy(selected_file)
        if show_details:
            print(f"[+] Shannon Entropy Score: {paint_yellow(f'{entropy_score}/8.0')}")
            status_color = paint_red if "CRITICAL" in entropy_status or "SUSPICIOUS" in entropy_status else paint_green
            print(f"[->] Status: {status_color(entropy_status)}")

    if config["strings"]:
        if show_details:
            print(paint_cyan("\n--- Consulting File Strings ---"))
        all_strings, alerts = strings(selected_file)
        if show_details:
            print(f"Total of strings: {paint_yellow(len(all_strings))}")
            print(f"Alerts found: {paint_red(len(alerts)) if alerts else paint_green('0')}")
            for alert in alerts:
                print(f"  -> {paint_red(alert)}")

    risk = calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert)
    analysis_duration = round(time.perf_counter() - analysis_start, 3)
    report_path = None
    if config["gerar_report"]:
        report_path = save_report(
            selected_file, kb_size, hash_result, result_vt, alerts, all_strings,
            in_blacklist, config, entropy_score, entropy_status, real_type,
            magic_alert, risk, analysis_duration
        )
    return {
        "file": os.path.basename(selected_file),
        "path": selected_file,
        "success": True,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk": risk,
        "analysis_duration": analysis_duration,
        "report": report_path,
    }


def analyze_folder(folder_path, config):
    files = []
    for root_path, _, filenames in os.walk(folder_path):
        files.extend(os.path.join(root_path, name) for name in filenames)
    files.sort()
    if not files:
        print(paint_yellow("[-] No files found in the selected folder."))
        return

    print(paint_cyan(f"\n--- Batch Analysis: {len(files)} file(s) ---"))
    batch_start = time.perf_counter()
    results = []
    for index, filepath in enumerate(files, start=1):
        print(paint_cyan(f"\n[{index}/{len(files)}] Analyzing {filepath}"))
        try:
            result = analyze_file(filepath, config, show_details=False)
            results.append(result)
            print(f"[+] Risk: {result['risk_level']} ({result['risk_score']}/100)")
        except (OSError, ValueError) as error:
            results.append({"file": os.path.basename(filepath), "path": filepath, "success": False, "error": str(error)})
            print(paint_red(f"[-] Analysis failed: {error}"))

    duration = round(time.perf_counter() - batch_start, 3)
    summary_path = save_batch_summary(folder_path, results, duration)
    print(paint_green(f"\n[+] Batch summary generated at: {summary_path}"))

def main():
    print(paint_cyan("\n======================================="))
    print(paint_bold("          CERBERUS"))
    print(paint_cyan("======================================="))

    config = optionsMenu()

    if config.get("history"):
        list_analysis_history()
        return

    if config.get("batch"):
        selected_folder = upload_folder()
        if not selected_folder:
            print(paint_red("[-] No folder selected. Closing the program."))
            return
        analyze_folder(selected_folder, config)
        return

    print("[*] Select a file to begin.")
    selected_file = uploadFile()

    if not selected_file:
        print(paint_red("[-] No files selected. Closing the program."))
        return

    result = analyze_file(selected_file, config)
    risk = result["risk"]
    risk_color = paint_red if risk["score"] >= 50 else paint_yellow if risk["score"] >= 20 else paint_green
    print(paint_cyan("\n--- Risk Summary ---"))
    risk_label = f"{risk['level']} ({risk['score']}/100)"
    print(f"[!] Risk: {risk_color(risk_label)}")
    print("[+] Factors:")
    for factor in risk["factors"]:
        print(f"  -> {factor}")

    if config["gerar_report"]:
        print(paint_cyan("\n--- Exporting Results ---"))
        caminho_salvo = result["report"]
        print(paint_green(f"[+] Dynamic report generated at: {caminho_salvo}"))
        report_base = os.path.splitext(caminho_salvo)[0]
        print(paint_green(f"[+] CSV report generated at: {report_base}.csv"))
        print(paint_green(f"[+] HTML report generated at: {report_base}.html"))
    else:
        print(paint_yellow("\n[+] Analysis completed without generating a report."))


main()
