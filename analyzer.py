import os
import tkinter as tk
from tkinter.filedialog import askopenfilename

from modules.strings import strings 
from modules.hashes import calc_sha256, check_local_blacklist, virustotal_check
from modules.reports import save_report
from modules.menu import optionsMenu
from modules.colors import paint_red, paint_green, paint_yellow, paint_cyan, paint_bold

root = tk.Tk()
root.withdraw()

def uploadFile():
    filepath = askopenfilename(
        title="Select a file", initialdir="C:/", filetypes=[("All", "*.*")]
    )
    return filepath

def main():
    print(paint_cyan("\n======================================="))
    print(paint_bold("          CERBERUS"))
    print(paint_cyan("======================================="))
    
    print("[*] Select a file to begin.")
    selected_file = uploadFile()

    if not selected_file:
        print(paint_red("[-] No files selected. Closing the program."))
        return
    
    byte_size = os.path.getsize(selected_file)
    kb_size = byte_size / 1024
    print(f"\n[+] File: {paint_bold(selected_file)}")
    print(f"[+] Size: {paint_yellow(f'{kb_size:.2f} KB')}")
    
    config = optionsMenu()

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
        print(paint_cyan("\n--- Generating a File Signature ---"))
        hash_result = calc_sha256(selected_file)
        print(f"[+] SHA256: {paint_yellow(hash_result)}")

    if config["blacklist"]:
        print(paint_cyan("\n--- Consulting Local Blacklist ---"))
        in_blacklist = check_local_blacklist(hash_result)
        if in_blacklist:
            print(paint_red("[!!!] CRITICAL ALERT: This hash is in the local blacklist!"))
        else:
            print(paint_green("[+] Hash is clean in the local control list."))

    if config["virustotal"]:
        print(paint_cyan("\n--- Consulting VirusTotal API ---"))
        result_vt = virustotal_check(hash_result)
        # Se contiver a palavra "Flagged", pinta de vermelho, senão deixa verde/padrão
        if "Flagged" in result_vt:
            print(f"[->] {paint_red(result_vt)}")
        else:
            print(f"[->] {paint_green(result_vt)}")

    if config["magic_numbers"]:
        print(paint_cyan("\n--- Consulting Magic Signature ---"))
        from modules.magic_numbers import check_magic_number
        real_type, magic_alert = check_magic_number(selected_file)
        print(f"[+] Real Type Detected: {paint_yellow(real_type)}")
        if magic_alert:
            print(paint_red(magic_alert))

    if config["entropy"]:
        print(paint_cyan("\n--- Calculating Shannon Entropy ---"))
        from modules.entropy import calculate_entropy
        entropy_score, entropy_status = calculate_entropy(selected_file)
        print(f"[+] Shannon Entropy Score: {paint_yellow(f'{entropy_score}/8.0')}")
        
        if "CRITICAL" in entropy_status or "SUSPICIOUS" in entropy_status:
            print(f"[->] Status: {paint_red(entropy_status)}")
        else:
            print(f"[->] Status: {paint_green(entropy_status)}")

    if config["strings"]:
        print(paint_cyan("\n--- Consulting File Strings ---"))
        all_strings, alerts = strings(selected_file)
        print(f"Total of strings: {paint_yellow(len(all_strings))}")
        print(f"Alerts found: {paint_red(len(alerts)) if alerts else paint_green('0')}")
        for alert in alerts:
            print(f"  -> {paint_red(alert)}")

    if config["gerar_report"]:
        print(paint_cyan("\n--- Exporting Results ---"))
        caminho_salvo = save_report(
            selected_file, kb_size, hash_result, result_vt, alerts, in_blacklist, config, entropy_score, entropy_status, real_type, magic_alert
        )
        print(paint_green(f"[+] Dynamic report generated at: {caminho_salvo}"))
    else:
        print(paint_yellow("\n[+] Analysis completed without generating a report."))


main()
