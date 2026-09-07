import argparse
import os
import sys
import threading
import time

from modules.strings import strings 
from modules.ioc_extract import extract_iocs, count_iocs
from modules.packers import detect_packers
from modules.pe_analysis import analyze_pe
from modules.hashes import calc_sha256, check_local_blacklist, virustotal_available, virustotal_check
from modules.iocs import print_ioc_integrity
from modules.reports import list_analysis_history, save_batch_summary, save_report
from modules.risk import calculate_risk
from modules.menu import optionsMenu
from modules.colors import paint_red, paint_green, paint_yellow, paint_cyan, paint_bold

BATCH_ASSET_EXTENSIONS = {
    ".apng", ".avi", ".bmp", ".css", ".eot", ".flac", ".gif", ".ico",
    ".jpeg", ".jpg", ".m4a", ".mkv", ".mov", ".mp3", ".mp4", ".ogg",
    ".otf", ".png", ".scss", ".svg", ".tif", ".tiff", ".ttf", ".wav",
    ".webm", ".webp", ".woff", ".woff2",
}
BATCH_IGNORED_DIRECTORIES = {".git", ".venv", "__pycache__", "node_modules"}


class ProgressTracker:
    """Animated progress bar for the sequential analysis engines."""

    SPINNER = "|/-\\"

    def __init__(self, total, enabled=True):
        self.total = max(total, 1)
        self.enabled = enabled
        self.completed = 0
        self.current_engine = "Preparing"
        self.current_started = None
        self.analysis_started = time.perf_counter()
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._frame = 0

    def _render(self, final=False):
        if not self.enabled:
            return
        with self._lock:
            completed = self.completed
            current_engine = self.current_engine
            current_started = self.current_started
            frame = self._frame
            self._frame += 1
        percent = min(100, int(completed / self.total * 100))
        filled = int(percent / 5)
        bar = "#" * filled + "." * (20 - filled)
        elapsed = time.perf_counter() - self.analysis_started
        current_elapsed = elapsed if current_started is None else time.perf_counter() - current_started
        if final:
            marker = "done"
        else:
            marker = self.SPINNER[frame % len(self.SPINNER)]
        line = (
            f"\r[{bar}] {percent:3d}% | {marker} {current_engine}"
            f" | engine: {current_elapsed:.1f}s | total: {elapsed:.1f}s"
        )
        sys.stdout.write(line + ("\n" if final else ""))
        sys.stdout.flush()

    def _animate(self):
        while not self._stop_event.wait(0.1):
            self._render()

    def start_engine(self, name):
        if self.current_started is not None:
            self.finish_engine()
        with self._lock:
            self.current_engine = name
            self.current_started = time.perf_counter()
        if self.enabled:
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
            self._render()

    def finish_engine(self):
        if self.current_started is None:
            return 0.0
        duration = time.perf_counter() - self.current_started
        self._stop_event.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=0.2)
        with self._lock:
            self.completed += 1
            self.current_started = None
        self._render()
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()
        return round(duration, 3)

    def finish(self):
        self.finish_engine()
        self.current_engine = "Analysis complete"
        self._render(final=True)

def uploadFile():
    from tkinter.filedialog import askopenfilename
    filepath = askopenfilename(
        title="Select a file", initialdir="C:/", filetypes=[("All", "*.*")]
    )
    return filepath


def upload_folder():
    from tkinter.filedialog import askdirectory
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
    result_vt = {"status": "not_selected", "message": "VirusTotal not selected in the configuration."}
    all_strings = []
    alerts = []
    entropy_score = 0.0
    entropy_status = "Not executed"
    real_type = "Not executed"
    magic_alert = None
    file_type_analysis = {
        "declared_extension": os.path.splitext(selected_file)[1].lower() or "(none)",
        "detected_type": "Not executed",
        "compatibility": "Not executed",
        "compatible": None,
        "alert": None,
    }
    extracted_iocs = {}
    packer_analysis = {"detected": False, "packers": {}, "note": "Not executed"}
    pe_analysis = {"status": "not_executed", "sections": []}

    engine_times = {}
    enabled_engines = sum((
        bool(config["blacklist"] or config["virustotal"]),
        bool(config["blacklist"]),
        bool(config["magic_numbers"]),
        bool(config["entropy"]),
        bool(config["strings"]),
        bool(config.get("pe_analysis")),
        bool(config.get("ioc_extract")),
        bool(config["virustotal"] and virustotal_available()),
    ))
    progress = ProgressTracker(
        enabled_engines,
        enabled=show_details and not config.get("quiet"),
    )

    def engine_start(name):
        progress.start_engine(name)
        return time.perf_counter()

    def engine_done(name, started):
        duration = round(time.perf_counter() - started, 3)
        engine_times[name] = duration
        progress.finish_engine()

    if config["blacklist"] or config["virustotal"]:
        engine_started = engine_start("SHA-256")
        if show_details:
            print(paint_cyan("\n--- Generating a File Signature ---"))
        hash_result = calc_sha256(selected_file)
        if show_details:
            print(f"[+] SHA256: {paint_yellow(hash_result)}")
        engine_done("SHA-256", engine_started)

    if config["blacklist"]:
        engine_started = engine_start("Local blacklist")
        if show_details:
            print(paint_cyan("\n--- Consulting Local Blacklist ---"))
        in_blacklist = check_local_blacklist(hash_result)
        if show_details:
            if in_blacklist:
                print(paint_red("[!!!] CRITICAL ALERT: This hash is in the local blacklist!"))
            else:
                print(paint_green("[+] Hash is clean in the local control list."))
        engine_done("Local blacklist", engine_started)

    if config["magic_numbers"]:
        engine_started = engine_start("File type and magic numbers")
        if show_details:
            print(paint_cyan("\n--- Consulting Magic Signature ---"))
        from modules.magic_numbers import analyze_file_type
        file_type_analysis = analyze_file_type(selected_file)
        real_type = file_type_analysis["detected_type"]
        magic_alert = file_type_analysis["alert"]
        if show_details:
            print(f"[+] Declared Extension: {paint_yellow(file_type_analysis['declared_extension'])}")
            print(f"[+] Detected Type: {paint_yellow(real_type)}")
            compatibility_color = paint_green if file_type_analysis["compatibility"] == "Compatible" else paint_yellow
            print(f"[+] Compatibility: {compatibility_color(file_type_analysis['compatibility'])}")
            if magic_alert:
                print(paint_red(magic_alert))
        engine_done("File type and magic numbers", engine_started)

    if config["entropy"]:
        engine_started = engine_start("Entropy and packers")
        packer_analysis = detect_packers(selected_file)
        if show_details:
            print(paint_cyan("\n--- Calculating Shannon Entropy ---"))
        from modules.entropy import calculate_entropy
        entropy_score, entropy_status = calculate_entropy(selected_file, packer_analysis)
        if show_details:
            print(f"[+] Shannon Entropy Score: {paint_yellow(f'{entropy_score}/8.0')}")
            status_color = paint_yellow if "INDICATOR" in entropy_status else paint_green
            print(f"[->] Status: {status_color(entropy_status)}")
            if packer_analysis["detected"]:
                print(f"[->] Packer context: {paint_yellow(', '.join(packer_analysis['packers']))}")
        engine_done("Entropy and packers", engine_started)

    if config["strings"]:
        engine_started = engine_start("Strings")
        if show_details:
            print(paint_cyan("\n--- Consulting File Strings ---"))
        all_strings, alerts = strings(selected_file)
        if show_details:
            print(f"Total of strings: {paint_yellow(len(all_strings))}")
            print(f"Alerts found: {paint_red(len(alerts)) if alerts else paint_green('0')}")
            for alert in alerts:
                print(f"  -> {paint_red(alert)}")
        engine_done("Strings", engine_started)

    if config.get("pe_analysis"):
        engine_started = engine_start("PE sections")
        if show_details:
            print(paint_cyan("\n--- Analyzing PE Sections ---"))
        pe_analysis = analyze_pe(selected_file)
        if show_details:
            print(f"[->] PE analysis: {paint_yellow(pe_analysis['status'])}")
            if pe_analysis.get("has_pe_signature"):
                print(f"[->] Sections: {paint_yellow(pe_analysis['number_of_sections'])}")
        engine_done("PE sections", engine_started)

    if config.get("ioc_extract"):
        engine_started = engine_start("IOC extraction")
        if show_details:
            print(paint_cyan("\n--- Extracting URLs, IPs, Domains, E-mails and Commands ---"))
        extracted_iocs = extract_iocs(selected_file)
        if show_details:
            print(f"Extracted IOC values: {paint_yellow(count_iocs(extracted_iocs))}")
            for category, values in extracted_iocs.items():
                if values:
                    print(f"  -> {category}: {paint_yellow(len(values))}")
            engine_done("IOC extraction", engine_started)

    suspicious_locally = bool(
        in_blacklist
        or alerts
        or magic_alert
        or any(extracted_iocs.get(category) for category in ("suspicious_paths", "powershell_commands", "cmd_commands"))
    )
    should_query_virustotal = config["virustotal"] and virustotal_available() and (
        not config.get("virustotal_suspicious_only") or suspicious_locally
    )
    if should_query_virustotal:
        engine_started = engine_start("VirusTotal")
        if show_details:
            print(paint_cyan("\n--- Consulting VirusTotal API ---"))
        result_vt = virustotal_check(hash_result)
        if show_details:
            output_color = (
                paint_red
                if result_vt.get("malicious", 0) or result_vt.get("status") == "rate_limited"
                else paint_yellow if result_vt.get("status") == "suspicious" else paint_green
            )
            print(f"[->] {output_color(result_vt['message'])}")
        engine_done("VirusTotal", engine_started)
    elif config["virustotal"]:
        if virustotal_available():
            result_vt = {"status": "skipped", "message": "VirusTotal: skipped because no local indicators were found."}
        else:
            result_vt = {"status": "not_configured", "message": "VirusTotal: API key not configured; request not sent."}

    risk = calculate_risk(in_blacklist, result_vt, entropy_status, alerts, magic_alert, extracted_iocs)
    analysis_duration = round(time.perf_counter() - analysis_start, 3)
    progress.finish()
    report_path = None
    minimum_report_score = config.get("minimum_report_score", 0)
    should_generate_report = config["gerar_report"] and risk["score"] >= minimum_report_score
    if should_generate_report:
        report_path = save_report(
            selected_file, kb_size, hash_result, result_vt, alerts, all_strings,
            in_blacklist, config, entropy_score, entropy_status, real_type,
            magic_alert, risk, analysis_duration, extracted_iocs, packer_analysis,
            pe_analysis, file_type_analysis, engine_times=engine_times
        )
    return {
        "file": os.path.basename(selected_file),
        "path": selected_file,
        "success": True,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk": risk,
        "analysis_duration": analysis_duration,
        "engine_times": engine_times,
        "report": report_path,
        "report_generated": should_generate_report,
    }


def analyze_folder(folder_path, config):
    files = []
    skipped = []
    for root_path, directories, filenames in os.walk(folder_path):
        directories[:] = [
            directory for directory in directories
            if directory.lower() not in BATCH_IGNORED_DIRECTORIES
        ]
        files.extend(os.path.join(root_path, name) for name in filenames)
    files.sort()
    if not files:
        print(paint_yellow("[-] No files found in the selected folder."))
        return

    candidate_files = []
    for filepath in files:
        extension = os.path.splitext(filepath)[1].lower()
        if extension in BATCH_ASSET_EXTENSIONS:
            skipped.append({
                "file": os.path.basename(filepath),
                "path": filepath,
                "reason": "asset extension excluded",
            })
        else:
            candidate_files.append(filepath)

    print(paint_cyan(
        f"\n--- Batch Analysis: {len(candidate_files)} candidate file(s) "
        f"({len(skipped)} asset(s) skipped) ---"
    ))
    batch_start = time.perf_counter()
    results = []
    for index, filepath in enumerate(candidate_files, start=1):
        print(paint_cyan(f"\n[{index}/{len(candidate_files)}] Analyzing {filepath}"))
        try:
            result = analyze_file(filepath, config, show_details=not config.get("quiet", False))
            results.append(result)
            report_status = "report generated" if result["report_generated"] else "report skipped"
            print(f"[+] Risk: {result['risk_level']} ({result['risk_score']}/100) - {report_status}")
        except (OSError, ValueError) as error:
            results.append({"file": os.path.basename(filepath), "path": filepath, "success": False, "error": str(error)})
            print(paint_red(f"[-] Analysis failed: {error}"))

    duration = round(time.perf_counter() - batch_start, 3)
    summary_path = save_batch_summary(folder_path, results, duration, reports_folder=config.get("output_dir", "reports"), skipped=skipped)
    print(paint_green(f"\n[+] Batch summary generated at: {summary_path}"))

def build_cli_parser():
    parser = argparse.ArgumentParser(
        description="CERBERUS static malware analysis toolkit"
    )
    parser.add_argument("file", nargs="?", help="file to analyze without opening Tkinter")
    scan_mode = parser.add_mutually_exclusive_group()
    scan_mode.add_argument("--full", action="store_true", help="run all analysis engines")
    scan_mode.add_argument("--quick", action="store_true", help="run blacklist and file-type checks")
    parser.add_argument("--no-virustotal", action="store_true", help="disable VirusTotal queries")
    parser.add_argument("--report", choices=("all", "json", "csv", "html"), default="all", help="report format")
    parser.add_argument("--output", default="reports", help="report output directory")
    parser.add_argument("--quiet", action="store_true", help="suppress progress and detailed output")
    return parser


def cli_config(args):
    quick = args.quick
    return {
        "blacklist": True,
        "virustotal": not args.no_virustotal and not quick,
        "strings": not quick,
        "ioc_extract": not quick,
        "entropy": not quick,
        "magic_numbers": True,
        "pe_analysis": not quick,
        "gerar_report": True,
        "report_format": args.report,
        "output_dir": args.output,
        "quiet": args.quiet,
        "virustotal_suspicious_only": False,
    }


def print_result_summary(result, config):
    if config.get("quiet"):
        print(f"{result['file']}: {result['risk_level']} ({result['risk_score']}/100) - {result['analysis_duration']:.3f}s")
        return
    risk = result["risk"]
    risk_color = paint_red if risk["score"] >= 50 else paint_yellow if risk["score"] >= 20 else paint_green
    print(paint_cyan("\n--- Risk Summary ---"))
    risk_label = f"{risk['level']} ({risk['score']}/100)"
    print(f"[!] Risk: {risk_color(risk_label)}")
    print("[+] Factors:")
    for factor in risk["factors"]:
        print(f"  -> {factor}")
    print(f"[+] Total execution time: {result['analysis_duration']:.3f}s")
    if result.get("report"):
        print(paint_green(f"[+] Report generated at: {result['report']}"))


def main():
    if len(sys.argv) > 1:
        parser = build_cli_parser()
        args = parser.parse_args()
        if not args.file:
            parser.error("a file path is required in CLI mode")
        config = cli_config(args)
        result = analyze_file(args.file, config, show_details=not args.quiet)
        print_result_summary(result, config)
        return

    print(paint_cyan("\n======================================="))
    print(paint_bold("          CERBERUS"))
    print(paint_cyan("======================================="))

    config = optionsMenu()

    if config.get("history"):
        list_analysis_history()
        return

    if config.get("ioc_integrity"):
        print_ioc_integrity()
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
    print_result_summary(result, config)

    if config["gerar_report"]:
        print(paint_cyan("\n--- Exporting Results ---"))
        caminho_salvo = result["report"]
        print(paint_green(f"[+] Dynamic report generated at: {caminho_salvo}"))
        if config.get("report_format", "all") == "all":
            report_base = os.path.splitext(caminho_salvo)[0]
            print(paint_green(f"[+] CSV report generated at: {report_base}.csv"))
            print(paint_green(f"[+] HTML report generated at: {report_base}.html"))
    else:
        print(paint_yellow("\n[+] Analysis completed without generating a report."))


main()
