import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
import threading
import time

from modules.strings import strings 
from modules.ioc_extract import extract_iocs, count_iocs
from modules.packers import detect_packers
from modules.pe_analysis import analyze_pe
from modules.hashes import calc_sha256, check_local_blacklist, virustotal_available, virustotal_check
from modules.reports import list_analysis_history, save_batch_summary, clear_history, save_report
from modules.risk import calculate_risk
from modules.analysis_cache import AnalysisCache
from modules.analysis_events import AnalysisEvent, emit_event
from modules.file_metrics import read_analysis_buffer
from modules.reports import CERBERUS_VERSION
from modules.colors import (
    paint_red, paint_green, paint_yellow, paint_cyan, paint_bold,
    paint_blue, paint_dim, paint_magenta,
)

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
        bar = paint_blue("#" * filled) + paint_dim("." * (20 - filled))
        elapsed = time.perf_counter() - self.analysis_started
        current_elapsed = elapsed if current_started is None else time.perf_counter() - current_started
        if final:
            marker = "done"
        else:
            marker = self.SPINNER[frame % len(self.SPINNER)]
        line = (
            f"\r{paint_cyan('[' + bar + ']')} {paint_bold(f'{percent:3d}%')}"
            f" | {paint_magenta(marker)} {paint_bold(current_engine)}"
            f" | engine: {paint_yellow(f'{current_elapsed:.1f}s')}"
            f" | total: {paint_dim(f'{elapsed:.1f}s')}"
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
            print("\n" + paint_blue(f"[>] Starting {name}"))
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
            sys.stdout.write(paint_green(f"[OK] {self.current_engine} completed\n\n"))
            sys.stdout.flush()
        return round(duration, 3)

    def finish(self):
        self.finish_engine()
        self.current_engine = "Analysis complete"
        self._render(final=True)

def print_banner():
    frame = paint_red
    print(frame("\n+--------------------------------------------------+"))
    print(frame("| ") + paint_red(paint_bold("CERBERUS")) + paint_dim("  /  STATIC MALWARE ANALYSIS ENGINE") + frame(" |"))
    print(frame("| ") + paint_dim("Three heads. One purpose. Nothing gets past.") + frame("     |"))
    print(frame("+--------------------------------------------------+"))
    print()


def print_watermark():
    print(paint_dim("\n                         made by daniel • @shwdaniel7"))


def print_section(title):
    print(paint_red(f"\n[ {title.upper()} ]") + paint_dim(" " + "-" * max(2, 42 - len(title))))
    print()


def analyze_file(selected_file, config, show_details=True):
    byte_size = os.path.getsize(selected_file)
    max_file_size = config.get("max_file_size")
    if max_file_size and byte_size > max_file_size:
        raise ValueError(
            f"File exceeds configured limit ({byte_size} > {max_file_size} bytes)"
        )

    cache = config.get("_cache")
    cache_key = None
    cache_stat = None
    if cache is None and config.get("cache_enabled", True):
        cache = AnalysisCache(config.get("output_dir", "reports"), CERBERUS_VERSION)
        config["_cache"] = cache
    if cache:
        cache_key, cache_stat = cache.key_for(selected_file, config)
        cached_result = cache.get(selected_file, config, cache_key=cache_key)
        if cached_result and (not cached_result.get("report") or os.path.exists(cached_result["report"])):
            emit_event(config, AnalysisEvent(
                "file_completed", selected_file, status="cached", progress=1.0,
                message="Analysis restored from cache.", data=cached_result,
            ))
            return cached_result
    kb_size = byte_size / 1024
    if show_details:
        print_section("Target")
        print(f"  {paint_dim('File')}  {paint_bold(selected_file)}")
        print(f"  {paint_dim('Size')}  {paint_yellow(f'{kb_size:.2f} KB')}")
        print()

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
    shared_metrics = None
    shared_content = None

    engine_times = {}
    enabled_engines = sum((
        bool(config["blacklist"] or config["virustotal"]),
        bool(config["blacklist"]),
        bool(config["magic_numbers"]),
        bool(config["entropy"]),
        bool(config["strings"]),
        bool(config.get("pe_analysis")),
        bool(config.get("ioc_extract")),
        bool(config["virustotal"]),
    ))
    progress = ProgressTracker(
        enabled_engines,
        enabled=show_details and not config.get("quiet"),
    )

    def engine_start(name):
        progress.start_engine(name)
        emit_event(config, AnalysisEvent(
            "engine_started", selected_file, engine=name, status="running",
            message=f"Started {name}.",
        ))
        return time.perf_counter()

    def engine_done(name, started):
        duration = round(time.perf_counter() - started, 3)
        engine_times[name] = duration
        progress.finish_engine()
        emit_event(config, AnalysisEvent(
            "engine_completed", selected_file, engine=name, status="completed",
            elapsed_seconds=duration, message=f"Completed {name}.",
        ))

    if config["blacklist"] or config["virustotal"]:
        engine_started = engine_start("SHA-256")
        if show_details:
            print_section("Identity")
            print(paint_dim("  Generating SHA-256 signature"))
        if config["entropy"] or config["strings"] or config.get("ioc_extract"):
            if shared_content is None and shared_metrics is None:
                shared_content, shared_metrics = read_analysis_buffer(
                    selected_file, compute_histogram=config["entropy"]
                )
            hash_result = shared_metrics["sha256"]
        else:
            hash_result = calc_sha256(selected_file)
        if show_details:
            print(f"[+] SHA256: {paint_yellow(hash_result)}")
        engine_done("SHA-256", engine_started)

    if config["blacklist"]:
        engine_started = engine_start("Local blacklist")
        if show_details:
            print_section("Reputation")
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
            print_section("File Type")
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
            print()
        engine_done("File type and magic numbers", engine_started)

    if config["entropy"]:
        engine_started = engine_start("Entropy and packers")
        if shared_content is None and shared_metrics is None:
            shared_content, shared_metrics = read_analysis_buffer(
                selected_file, compute_histogram=True
            )
        packer_analysis = detect_packers(selected_file, content=shared_content)
        if show_details:
            print_section("Entropy and Packers")
        from modules.entropy import calculate_entropy
        entropy_score, entropy_status = calculate_entropy(
            selected_file, packer_analysis, metrics=shared_metrics
        )
        if show_details:
            print(f"[+] Shannon Entropy Score: {paint_yellow(f'{entropy_score}/8.0')}")
            status_color = paint_yellow if "INDICATOR" in entropy_status else paint_green
            print(f"[->] Status: {status_color(entropy_status)}")
            if packer_analysis["detected"]:
                print(f"[->] Packer context: {paint_yellow(', '.join(packer_analysis['packers']))}")
            print()
        engine_done("Entropy and packers", engine_started)

    if config["strings"]:
        engine_started = engine_start("Strings")
        if show_details:
            print_section("Embedded Strings")
        if shared_content is None and shared_metrics is None:
            shared_content, shared_metrics = read_analysis_buffer(
                selected_file, compute_histogram=config["entropy"]
            )
        all_strings, alerts = strings(selected_file, content=shared_content)
        if show_details:
            print(f"Total of strings: {paint_yellow(len(all_strings))}")
            print(f"Alerts found: {paint_red(len(alerts)) if alerts else paint_green('0')}")
            for alert in alerts:
                print(f"  -> {paint_red(alert)}")
            print()
        engine_done("Strings", engine_started)

    if config.get("pe_analysis"):
        engine_started = engine_start("PE sections")
        if show_details:
            print_section("PE Structure")
        pe_analysis = analyze_pe(selected_file)
        if show_details:
            print(f"[->] PE analysis: {paint_yellow(pe_analysis['status'])}")
            if pe_analysis.get("has_pe_signature"):
                print(f"[->] Sections: {paint_yellow(pe_analysis['number_of_sections'])}")
            print()
        engine_done("PE sections", engine_started)

    if config.get("ioc_extract"):
        engine_started = engine_start("IOC extraction")
        if show_details:
            print_section("Structured IOCs")
        if shared_content is None and shared_metrics is None:
            shared_content, shared_metrics = read_analysis_buffer(
                selected_file, compute_histogram=config["entropy"]
            )
        extracted_iocs = extract_iocs(selected_file, content=shared_content)
        if show_details:
            print(f"Extracted IOC values: {paint_yellow(count_iocs(extracted_iocs))}")
            for category, values in extracted_iocs.items():
                if values:
                    print(f"  -> {category}: {paint_yellow(len(values))}")
            print()
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
            print_section("VirusTotal")
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
        engine_started = engine_start("VirusTotal (skipped)")
        if virustotal_available():
            result_vt = {"status": "skipped", "message": "VirusTotal: skipped because no local indicators were found."}
        else:
            result_vt = {"status": "not_configured", "message": "VirusTotal: API key not configured; request not sent."}
        engine_done("VirusTotal (skipped)", engine_started)

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
    result = {
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
        "details": {
            "sha256": hash_result,
            "size_bytes": byte_size,
            "file_type": file_type_analysis,
            "alerts": alerts,
            "strings_count": len(all_strings),
            "iocs": extracted_iocs,
            "entropy_score": entropy_score,
            "entropy_status": entropy_status,
            "packers": packer_analysis,
            "pe_analysis": pe_analysis,
            "virustotal": result_vt,
            "blacklist_match": bool(in_blacklist),
            "magic_alert": magic_alert,
        },
    }
    emit_event(config, AnalysisEvent(
        "file_completed", selected_file, status="completed", progress=1.0,
        elapsed_seconds=analysis_duration, data=result,
    ))
    if cache:
        cache.put(selected_file, config, result, cache_key=cache_key, cache_stat=cache_stat)
    return result


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

    print_section("Batch Analysis")
    print(
        f"  {paint_dim('Candidates')} {paint_bold(len(candidate_files))}"
        f"   {paint_dim('Skipped assets')} {paint_yellow(len(skipped))}"
    )
    batch_start = time.perf_counter()
    results = []
    if config.get("cache_enabled", True) and not config.get("_cache"):
        config["_cache"] = AnalysisCache(config.get("output_dir", "reports"), CERBERUS_VERSION)

    worker_count = max(1, min(int(config.get("workers", 1)), len(candidate_files) or 1))
    chunk_size = max(1, int(config.get("batch_chunk_size", worker_count * 4)))

    def analyze_candidate(filepath):
        return analyze_file(filepath, config, show_details=False)

    def process_chunk(chunk_files, start_index):
        chunk_results = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(analyze_candidate, filepath): filepath for filepath in chunk_files}
            for local_index, future in enumerate(as_completed(futures), start=1):
                filepath = futures[future]
                global_index = start_index + local_index
                print(paint_cyan(f"\n[{global_index}/{len(candidate_files)}] ") + paint_bold(os.path.basename(filepath)))
                try:
                    result = future.result()
                    chunk_results.append(result)
                    report_status = "report generated" if result["report_generated"] else "report skipped"
                    cache_status = " / cached" if result.get("cache_hit") else ""
                    score_label = f"({result['risk_score']}/100)"
                    duration_label = f"{result['analysis_duration']:.3f}s"
                    print(
                        f"  {paint_dim('Risk')} {paint_bold(result['risk_level'])} "
                        f"{paint_dim(score_label)}"
                        f"  {paint_dim('Time')} {paint_yellow(duration_label)}"
                        f"  {paint_dim(report_status + cache_status)}"
                    )
                except (OSError, ValueError) as error:
                    chunk_results.append({"file": os.path.basename(filepath), "path": filepath, "success": False, "error": str(error)})
                    print(paint_red(f"[-] Analysis failed: {error}"))
        return chunk_results

    for chunk_start in range(0, len(candidate_files), chunk_size):
        chunk = candidate_files[chunk_start:chunk_start + chunk_size]
        results.extend(process_chunk(chunk, chunk_start))

    cache = config.get("_cache")
    if cache:
        cache.close()

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
    scan_mode.add_argument("--clear-history", action="store_true", help="clear all analysis reports and history")
    parser.add_argument("--no-virustotal", action="store_true", help="disable VirusTotal queries")
    parser.add_argument("--report", choices=("all", "json", "csv", "html"), default="all", help="report format")
    parser.add_argument("--output", default="reports", help="report output directory")
    parser.add_argument("--quiet", action="store_true", help="suppress progress and detailed output")
    parser.add_argument("--workers", type=int, default=1, help="parallel workers for batch mode")
    parser.add_argument("--no-cache", action="store_true", help="disable the persistent analysis cache")
    parser.add_argument("--max-file-size", type=int, help="skip files larger than this many bytes")
    parser.add_argument("--include-cache", action="store_true", help="also clear the analysis cache when using --clear-history")
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
        "workers": max(1, args.workers),
        "cache_enabled": not args.no_cache,
        "max_file_size": args.max_file_size,
        "virustotal_suspicious_only": False,
    }


def print_result_summary(result, config):
    if config.get("quiet"):
        print(f"{result['file']}: {result['risk_level']} ({result['risk_score']}/100) - {result['analysis_duration']:.3f}s")
        return
    risk = result["risk"]
    risk_color = paint_red if risk["score"] >= 50 else paint_yellow if risk["score"] >= 20 else paint_green
    print_section("Analysis Complete")
    risk_label = f"{risk['level']} ({risk['score']}/100)"
    indicator_count = 0 if risk["factors"] == ["No risk indicators were detected"] else len(risk["factors"])
    print(paint_red("  [VERDICT]"))
    print(f"  {paint_dim('Risk')}       {risk_color(risk_label)}")
    print(f"  {paint_dim('Indicators')} {paint_yellow(indicator_count)}")
    duration_label = f"{result['analysis_duration']:.3f}s"
    print(f"  {paint_dim('Duration')}   {paint_yellow(duration_label)}")
    print(paint_red("\n  [EVIDENCE]"))
    for factor in risk["factors"]:
        print(f"    {paint_dim('>')} {factor}")
    if result.get("report"):
        print(paint_red("\n  [IDENTITY]"))
        print(f"  {paint_dim('Report')} {paint_green(result['report'])}")


def main():
    if len(sys.argv) > 1:
        parser = build_cli_parser()
        args = parser.parse_args()
        
        if args.clear_history:
            if not args.quiet:
                print_banner()
            result = clear_history(args.output, include_cache=args.include_cache)
            print(f"[+] Deleted {result['deleted']} report file(s)")
            if result['cache_cleared']:
                print("[+] Analysis cache cleared")
            if result['errors']:
                for error in result['errors']:
                    print(f"[-] Error: {error}")
            if not args.quiet:
                print_watermark()
            return

        if not args.file:
            parser.error("a file path is required in CLI mode")
        config = cli_config(args)
        if not args.quiet:
            print_banner()
        result = analyze_file(args.file, config, show_details=not args.quiet)
        print_result_summary(result, config)
        cache = config.get("_cache")
        if cache:
            cache.close()
        if not args.quiet:
            print_watermark()
        return

    from modules.gui import launch_gui
    launch_gui(sys.modules[__name__])


if __name__ == "__main__":
    main()
