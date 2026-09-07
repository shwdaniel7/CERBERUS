import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


COLORS = {
    "bg": "#101217",
    "surface": "#171a20",
    "surface_alt": "#20242c",
    "border": "#303640",
    "crimson": "#9f2026",
    "red": "#e05252",
    "cyan": "#64c4d4",
    "green": "#6ac487",
    "yellow": "#e2b85b",
    "text": "#edf0f4",
    "muted": "#929aa8",
}


class CerberusApp(tk.Tk):
    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer
        self.selected_file = None
        self.analysis_thread = None
        self.events = queue.Queue()
        self.engine_names = []
        self.completed_engines = 0
        self.last_result = None
        self.engine_states = {}

        self.title("CERBERUS / Static Malware Analysis Engine")
        self.geometry("1240x780")
        self.minsize(980, 650)
        self.configure(background=COLORS["bg"])
        self._configure_styles()
        self._build_layout()
        self.after(100, self._drain_events)

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("App.TFrame", background=COLORS["bg"])
        style.configure("Surface.TFrame", background=COLORS["surface"])
        style.configure("Panel.TFrame", background=COLORS["surface_alt"])
        style.configure("Title.TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 17, "bold"))
        style.configure("Subtitle.TLabel", background=COLORS["bg"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("PanelTitle.TLabel", background=COLORS["surface_alt"], foreground=COLORS["red"], font=("Segoe UI", 10, "bold"))
        style.configure("Body.TLabel", background=COLORS["surface_alt"], foreground=COLORS["text"], font=("Segoe UI", 9))
        style.configure("Muted.TLabel", background=COLORS["surface_alt"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Metric.TLabel", background=COLORS["surface_alt"], foreground=COLORS["text"], font=("Segoe UI", 12, "bold"))
        style.configure("Stage.TLabel", background=COLORS["surface_alt"], foreground=COLORS["muted"], font=("Segoe UI", 8, "bold"))
        style.configure("Action.TButton", background=COLORS["crimson"], foreground="white", borderwidth=0, padding=(14, 8), font=("Segoe UI", 9, "bold"))
        style.map("Action.TButton", background=[("active", COLORS["red"]), ("disabled", COLORS["border"])])
        style.configure("Secondary.TButton", background=COLORS["surface_alt"], foreground=COLORS["text"], borderwidth=1, padding=(12, 7), font=("Segoe UI", 9))
        style.map("Secondary.TButton", background=[("active", COLORS["border"])])
        style.configure("Accent.Horizontal.TProgressbar", troughcolor=COLORS["border"], background=COLORS["red"], bordercolor=COLORS["border"], lightcolor=COLORS["red"], darkcolor=COLORS["red"])
        style.configure("Treeview", background=COLORS["surface"], fieldbackground=COLORS["surface"], foreground=COLORS["text"], borderwidth=0, rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=COLORS["surface_alt"], foreground=COLORS["muted"], relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Treeview", background=[("selected", COLORS["crimson"])])

    def _build_layout(self):
        root = ttk.Frame(self, style="App.TFrame", padding=24)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="App.TFrame")
        header.pack(fill="x", pady=(0, 18))
        title_box = ttk.Frame(header, style="App.TFrame")
        title_box.pack(side="left")
        ttk.Label(title_box, text="CERBERUS", style="Title.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="STATIC MALWARE ANALYSIS ENGINE", style="Subtitle.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(title_box, text="Three heads. One purpose. Nothing gets past.", style="Subtitle.TLabel").pack(anchor="w", pady=(5, 0))
        controls = ttk.Frame(header, style="App.TFrame")
        controls.pack(side="right", anchor="n")
        self.open_button = ttk.Button(controls, text="Open file", command=self._choose_file, style="Secondary.TButton")
        self.open_button.pack(side="left", padx=(0, 8))
        self.quick_button = ttk.Button(controls, text="Quick scan", command=lambda: self._start_scan(True), style="Secondary.TButton")
        self.quick_button.pack(side="left", padx=(0, 8))
        self.full_button = ttk.Button(controls, text="Full scan", command=lambda: self._start_scan(False), style="Action.TButton")
        self.full_button.pack(side="left")

        target = ttk.Frame(root, style="Surface.TFrame", padding=(16, 12))
        target.pack(fill="x", pady=(0, 16))
        ttk.Label(target, text="TARGET", foreground=COLORS["red"], background=COLORS["surface"], font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.target_label = ttk.Label(target, text="Choose a file to begin analysis.", foreground=COLORS["muted"], background=COLORS["surface"], font=("Consolas", 10))
        self.target_label.pack(anchor="w", pady=(5, 0))
        self.status_label = ttk.Label(target, text="READY", foreground=COLORS["green"], background=COLORS["surface"], font=("Segoe UI", 8, "bold"))
        self.status_label.pack(anchor="e")

        content = ttk.Frame(root, style="App.TFrame")
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=5)
        content.columnconfigure(2, weight=3)
        content.rowconfigure(0, weight=1)

        self.identity_panel = self._panel(content, 0, "01 / IDENTITY")
        self.evidence_panel = self._panel(content, 1, "02 / EVIDENCE")
        self.verdict_panel = self._panel(content, 2, "03 / VERDICT")
        self._build_identity()
        self._build_evidence()
        self._build_verdict()

        footer = ttk.Frame(root, style="App.TFrame")
        footer.pack(fill="x", pady=(14, 0))
        self.footer_label = ttk.Label(footer, text="Static evidence only. No behavioral execution performed.", style="Subtitle.TLabel")
        self.footer_label.pack(side="left")
        ttk.Label(footer, text="made by daniel • @shwdaniel7", style="Subtitle.TLabel").pack(side="right")

    def _panel(self, parent, column, title):
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=16)
        panel.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 8 if column < 2 else 0))
        ttk.Label(panel, text=title, style="PanelTitle.TLabel").pack(anchor="w", pady=(0, 14))
        return panel

    def _build_identity(self):
        self.identity_values = {}
        for key, label in (("file", "Filename"), ("type", "Detected type"), ("extension", "Declared extension"), ("compatibility", "Compatibility"), ("hash", "SHA-256"), ("size", "Size")):
            row = ttk.Frame(self.identity_panel, style="Panel.TFrame")
            row.pack(fill="x", pady=6)
            ttk.Label(row, text=label, style="Muted.TLabel").pack(anchor="w")
            value = ttk.Label(row, text="-", style="Body.TLabel", wraplength=260)
            value.pack(anchor="w", pady=(2, 0))
            self.identity_values[key] = value
        self.path_label = ttk.Label(self.identity_panel, text="Path: -", style="Muted.TLabel", wraplength=260)
        self.path_label.pack(anchor="w", pady=(12, 4))
        self.copy_hash_button = ttk.Button(self.identity_panel, text="Copy SHA-256", command=self._copy_hash, style="Secondary.TButton")
        self.copy_hash_button.pack(anchor="w", pady=(4, 0))

    def _build_evidence(self):
        self.progress_label = ttk.Label(self.evidence_panel, text="Waiting for analysis", style="Muted.TLabel")
        self.progress_label.pack(anchor="w")
        stages = ttk.Frame(self.evidence_panel, style="Panel.TFrame")
        stages.pack(fill="x", pady=(10, 8))
        self.stage_labels = {}
        for stage in ("IDENTITY", "EVIDENCE", "VERDICT"):
            label = ttk.Label(stages, text=f"○ {stage}", style="Stage.TLabel")
            label.pack(side="left", expand=True, anchor="w")
            self.stage_labels[stage] = label
        self.progress = ttk.Progressbar(self.evidence_panel, style="Accent.Horizontal.TProgressbar", maximum=1, value=0)
        self.progress.pack(fill="x", pady=(8, 16))
        self.evidence_notebook = ttk.Notebook(self.evidence_panel)
        self.evidence_notebook.pack(fill="both", expand=True)

        overview_tab = ttk.Frame(self.evidence_notebook, style="Panel.TFrame", padding=(4, 8))
        self.evidence_notebook.add(overview_tab, text="Overview")
        self._build_engine_table(overview_tab)

        self.evidence_tabs = {}
        for tab_name in ("Strings", "IOCs", "PE", "Entropy", "Reputation"):
            tab = ttk.Frame(self.evidence_notebook, style="Panel.TFrame", padding=8)
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(1, weight=1)
            self.evidence_notebook.add(tab, text=tab_name)
            ttk.Label(tab, text="No analysis data yet.", style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
            text = tk.Text(tab, background=COLORS["surface"], foreground=COLORS["text"], insertbackground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Consolas", 9), state="disabled")
            text.grid(row=1, column=0, sticky="nsew")
            self.evidence_tabs[tab_name] = (tab, text)

    def _build_engine_table(self, parent):
        columns = ("status", "engine", "detail")
        self.evidence_tree = ttk.Treeview(parent, columns=columns, show="headings", height=15)
        self.evidence_tree.heading("status", text="STATE")
        self.evidence_tree.heading("engine", text="ENGINE")
        self.evidence_tree.heading("detail", text="DETAIL")
        self.evidence_tree.column("status", width=82, anchor="center", stretch=False)
        self.evidence_tree.column("engine", width=150, anchor="w", stretch=False)
        self.evidence_tree.column("detail", width=260, anchor="w")
        self.evidence_tree.tag_configure("running", foreground=COLORS["cyan"])
        self.evidence_tree.tag_configure("completed", foreground=COLORS["green"])
        self.evidence_tree.tag_configure("warning", foreground=COLORS["yellow"])
        self.evidence_tree.tag_configure("skipped", foreground=COLORS["muted"])
        self.evidence_tree.tag_configure("cached", foreground=COLORS["cyan"])
        self.evidence_tree.tag_configure("failed", foreground=COLORS["red"])
        self.evidence_tree.pack(fill="both", expand=True)

    def _build_verdict(self):
        self.risk_label = ttk.Label(self.verdict_panel, text="--", style="Metric.TLabel")
        self.risk_label.pack(anchor="w", pady=(4, 2))
        self.score_label = ttk.Label(self.verdict_panel, text="No analysis yet", style="Muted.TLabel")
        self.score_label.pack(anchor="w")
        ttk.Separator(self.verdict_panel).pack(fill="x", pady=18)
        ttk.Label(self.verdict_panel, text="FACTORS", style="Muted.TLabel").pack(anchor="w")
        self.factors_text = tk.Text(self.verdict_panel, height=12, background=COLORS["surface_alt"], foreground=COLORS["text"], insertbackground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Segoe UI", 9), state="disabled")
        self.factors_text.pack(fill="both", expand=True, pady=(8, 0))

    def _choose_file(self):
        filepath = filedialog.askopenfilename(title="Select a file to analyze")
        if filepath:
            self.selected_file = filepath
            self.target_label.configure(text=filepath, foreground=COLORS["text"])
            self.status_label.configure(text="READY", foreground=COLORS["green"])

    def _copy_hash(self):
        value = self.identity_values["hash"].cget("text")
        if value and value not in ("-", "Not calculated"):
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_label.configure(text="HASH COPIED", foreground=COLORS["cyan"])

    def _start_scan(self, quick):
        if not self.selected_file:
            self._choose_file()
        if not self.selected_file or (self.analysis_thread and self.analysis_thread.is_alive()):
            return

        self._reset_view()
        self._set_controls(False)
        self.status_label.configure(text="ANALYZING", foreground=COLORS["yellow"])
        config = {
            "blacklist": True,
            "virustotal": not quick,
            "strings": not quick,
            "ioc_extract": not quick,
            "entropy": not quick,
            "magic_numbers": True,
            "pe_analysis": not quick,
            "gerar_report": True,
            "report_format": "all",
            "output_dir": "reports",
            "quiet": True,
            "workers": 1,
            "cache_enabled": True,
            "virustotal_suspicious_only": False,
            "event_callback": self.events.put,
        }
        self.engine_names = self._engine_names(config)
        self.engine_states = {name: "QUEUED" for name in self.engine_names}
        for name in self.engine_names:
            self._upsert_engine(name, "QUEUED", "Waiting", "skipped")
        self._set_stage("IDENTITY", "RUNNING")
        self._set_stage("EVIDENCE", "QUEUED")
        self._set_stage("VERDICT", "QUEUED")
        self.progress.configure(maximum=max(1, len(self.engine_names)), value=0)
        self.analysis_thread = threading.Thread(target=self._run_analysis, args=(config,), daemon=True)
        self.analysis_thread.start()

    def _engine_names(self, config):
        names = []
        if config["blacklist"] or config["virustotal"]:
            names.append("SHA-256")
        if config["blacklist"]:
            names.append("Local blacklist")
        if config["magic_numbers"]:
            names.append("File type and magic numbers")
        if config["entropy"]:
            names.append("Entropy and packers")
        if config["strings"]:
            names.append("Strings")
        if config["pe_analysis"]:
            names.append("PE sections")
        if config["ioc_extract"]:
            names.append("IOC extraction")
        if config["virustotal"]:
            names.append("VirusTotal")
        return names

    def _run_analysis(self, config):
        try:
            result = self.analyzer.analyze_file(self.selected_file, config, show_details=False)
            self.events.put(("result", result))
        except Exception as error:
            self.events.put(("error", error))

    def _drain_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if isinstance(event, tuple):
                    self._handle_result_event(event)
                else:
                    self._handle_analysis_event(event)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _handle_analysis_event(self, event):
        if event.event_type == "file_completed" and event.status == "cached":
            for engine in self.engine_names:
                self._upsert_engine(engine, "CACHED", "Restored from cache", "cached")
            self.completed_engines = len(self.engine_names)
            self.progress.configure(value=self.completed_engines)
            self._set_stage("IDENTITY", "COMPLETE")
            self._set_stage("EVIDENCE", "COMPLETE")
            self._set_stage("VERDICT", "COMPLETE")
            self._handle_result_event(("result", event.data))
            return
        if event.event_type == "engine_started":
            self.engine_states[event.engine] = "RUNNING"
            self.progress_label.configure(text=f"Running: {event.engine}")
            self._upsert_engine(event.engine, "RUNNING", event.message, "running")
            self._update_stages(event.engine)
        elif event.event_type == "engine_completed":
            self.engine_states[event.engine] = "COMPLETE"
            self.completed_engines += 1
            self.progress.configure(value=self.completed_engines)
            self.progress_label.configure(text=f"Completed: {event.engine} ({event.elapsed_seconds:.3f}s)")
            self._upsert_engine(event.engine, "COMPLETE", f"{event.elapsed_seconds:.3f}s", "completed")
            self._update_stages(event.engine)

    def _upsert_engine(self, engine, status, detail, tag):
        for item in self.evidence_tree.get_children():
            values = self.evidence_tree.item(item, "values")
            if len(values) > 1 and values[1] == engine:
                self.evidence_tree.item(item, values=(status, engine, detail), tags=(tag,))
                return
        self.evidence_tree.insert("", "end", values=(status, engine, detail), tags=(tag,))

    def _handle_result_event(self, event):
        kind, payload = event
        if kind == "error":
            self.status_label.configure(text="FAILED", foreground=COLORS["red"])
            self._set_stage("VERDICT", "FAILED")
            self._upsert_engine("Analysis", "FAILED", str(payload), "failed")
            messagebox.showerror("Analysis failed", str(payload))
            self._set_controls(True)
            return
        self.last_result = payload
        self.status_label.configure(text="COMPLETE", foreground=COLORS["green"])
        self.progress.configure(value=self.progress["maximum"])
        self.progress_label.configure(text=f"Analysis complete in {payload['analysis_duration']:.3f}s")
        self._render_result(payload)
        self._set_stage("IDENTITY", "COMPLETE")
        self._set_stage("EVIDENCE", "COMPLETE")
        self._set_stage("VERDICT", "COMPLETE")
        self._set_controls(True)

    def _render_result(self, result):
        details = result.get("details", {})
        file_type = details.get("file_type", {})
        self.identity_values["file"].configure(text=result.get("file", "-"))
        self.identity_values["type"].configure(text=file_type.get("detected_type", "-"))
        self.identity_values["extension"].configure(text=file_type.get("declared_extension", "-"))
        self.identity_values["compatibility"].configure(text=file_type.get("compatibility", "-"))
        self.identity_values["hash"].configure(text=details.get("sha256", "Not calculated"), font=("Consolas", 8))
        self.identity_values["size"].configure(text=f"{details.get('size_bytes', 0)} bytes")
        self.path_label.configure(text=f"Path: {result.get('path', '-')}")
        risk = result["risk"]
        self.risk_label.configure(text=f"{risk['level'].upper()} RISK", foreground=self._risk_color(risk["level"]))
        self.score_label.configure(text=f"{risk['score']} / 100  |  {result['analysis_duration']:.3f}s")
        self.factors_text.configure(state="normal")
        self.factors_text.delete("1.0", "end")
        for factor in risk["factors"]:
            self.factors_text.insert("end", f"> {factor}\n\n")
        self.factors_text.configure(state="disabled")
        self._render_evidence(result)

    def _set_evidence_text(self, tab_name, heading, lines):
        _, text = self.evidence_tabs[tab_name]
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("end", f"{heading}\n\n")
        text.insert("end", "\n".join(lines) if lines else "No evidence collected.")
        text.configure(state="disabled")

    def _render_evidence(self, result):
        details = result.get("details", {})
        alerts = details.get("alerts", [])
        strings_count = details.get("strings_count", 0)
        self._set_evidence_text(
            "Strings",
            "OBSERVED / EMBEDDED STRINGS",
            [f"Extracted strings: {strings_count}", "", *[f"[SUSPICIOUS] {alert}" for alert in alerts]],
        )

        iocs = details.get("iocs", {}) or {}
        ioc_lines = []
        for category, values in iocs.items():
            if values:
                ioc_lines.append(f"{category.upper()} ({len(values)})")
                ioc_lines.extend(f"  {value}" for value in values)
                ioc_lines.append("")
        self._set_evidence_text("IOCs", "OBSERVED / STRUCTURED INDICATORS", ioc_lines)

        pe = details.get("pe_analysis", {}) or {}
        pe_lines = [
            f"Status: {pe.get('status', 'not executed')}",
            f"PE signature: {pe.get('has_pe_signature', 'not available')}",
            f"Sections: {pe.get('number_of_sections', 0)}",
        ]
        for section in pe.get("sections", []):
            pe_lines.append(
                f"{section.get('name', '?')} | raw {section.get('raw_size', 0)} | "
                f"virtual {section.get('virtual_size', 0)} | entropy {section.get('entropy', 0)}"
            )
        self._set_evidence_text("PE", "OBSERVED / PE STRUCTURE", pe_lines)

        entropy_lines = [
            f"Score: {details.get('entropy_score', 'not executed')}",
            f"Status: {details.get('entropy_status', 'not executed')}",
        ]
        packers = details.get("packers", {}) or {}
        if packers.get("detected"):
            entropy_lines.append("",)
            entropy_lines.extend(f"[CONTEXT] {name}: {', '.join(values)}" for name, values in packers.get("packers", {}).items())
        entropy_lines.append("")
        entropy_lines.append("High entropy and packing are contextual indicators, not proof of malware.")
        self._set_evidence_text("Entropy", "CONTEXT / ENTROPY AND PACKERS", entropy_lines)

        vt = details.get("virustotal", {}) or {}
        reputation_lines = [
            f"VirusTotal: {vt.get('status', 'not executed')}",
            vt.get("message", "No VirusTotal result."),
            f"Malicious: {vt.get('malicious', 0)}",
            f"Suspicious: {vt.get('suspicious', 0)}",
            f"Harmless: {vt.get('harmless', 0)}",
            f"Undetected: {vt.get('undetected', 0)}",
            "",
            f"Local blacklist: {'MATCH' if details.get('blacklist_match') else 'No match'}",
        ]
        self._set_evidence_text("Reputation", "REPUTATION / EXTERNAL CONTEXT", reputation_lines)

    def _risk_color(self, level):
        return {"Critical": COLORS["red"], "High": COLORS["red"], "Moderate": COLORS["yellow"], "Low": COLORS["green"]}.get(level, COLORS["muted"])

    def _reset_view(self):
        self.completed_engines = 0
        self.progress.configure(value=0)
        self.progress_label.configure(text="Preparing analysis")
        self.path_label.configure(text="Path: -")
        for value in self.identity_values.values():
            value.configure(text="-")
        self._set_stage("IDENTITY", "QUEUED")
        self._set_stage("EVIDENCE", "QUEUED")
        self._set_stage("VERDICT", "QUEUED")
        for item in self.evidence_tree.get_children():
            self.evidence_tree.delete(item)
        self.risk_label.configure(text="ANALYZING", foreground=COLORS["cyan"])
        self.score_label.configure(text="Evidence is being collected")
        self.factors_text.configure(state="normal")
        self.factors_text.delete("1.0", "end")
        self.factors_text.configure(state="disabled")
        for _, text in self.evidence_tabs.values():
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("end", "No analysis data yet.")
            text.configure(state="disabled")

    def _set_stage(self, stage, state):
        symbols = {"QUEUED": "○", "RUNNING": "●", "COMPLETE": "✓", "FAILED": "✕"}
        colors = {"QUEUED": COLORS["muted"], "RUNNING": COLORS["cyan"], "COMPLETE": COLORS["green"], "FAILED": COLORS["red"]}
        self.stage_labels[stage].configure(text=f"{symbols.get(state, '○')} {stage}", foreground=colors.get(state, COLORS["muted"]))

    def _update_stages(self, current_engine):
        evidence_engines = set(self.engine_names) - {"SHA-256", "Local blacklist"}
        identity_done = all(self.engine_states.get(name) == "COMPLETE" for name in ("SHA-256", "Local blacklist") if name in self.engine_states)
        evidence_running = current_engine in evidence_engines
        evidence_done = evidence_engines and all(self.engine_states.get(name) == "COMPLETE" for name in evidence_engines)
        self._set_stage("IDENTITY", "COMPLETE" if identity_done else "RUNNING")
        self._set_stage("EVIDENCE", "COMPLETE" if evidence_done else "RUNNING" if evidence_running else "QUEUED")
        self._set_stage("VERDICT", "QUEUED")

    def _set_controls(self, enabled):
        state = "normal" if enabled else "disabled"
        for button in (self.open_button, self.quick_button, self.full_button):
            button.configure(state=state)


def launch_gui(analyzer):
    app = CerberusApp(analyzer)
    app.mainloop()
