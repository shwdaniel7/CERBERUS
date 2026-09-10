import os
import json
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from modules.iocs import inspect_ioc_lists
from modules.reports import save_batch_summary
from modules.batch import collect_candidates, run_batch_analysis
from modules.magic_numbers import analyze_file_type
from modules.hashes import calc_sha256


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


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.window = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _event=None):
        if self.window or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.window,
            text=self.text,
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=4,
            font=("Segoe UI", 8),
        )
        label.pack()

    def _hide(self, _event=None):
        if self.window:
            self.window.destroy()
            self.window = None


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
        self._pulse_jobs = {}
        self._result_reveal_job = None
        self._identity_hash_thread = None
        self._selected_hash = None
        self._identity_wrap_widgets = []
        self.active_view = "analysis"
        self.view_widgets = {}

        self.title("CERBERUS / Static Malware Analysis Engine")
        self.geometry("1240x780")
        self.minsize(980, 650)
        self.configure(background=COLORS["bg"])
        self._configure_styles()
        self._build_layout()
        self._bind_shortcuts()
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
        self._add_button_behavior(self.open_button, "Open a file for static analysis (Ctrl+O)")
        self._add_button_behavior(self.quick_button, "Run the lightweight local scan (F5)")
        self._add_button_behavior(self.full_button, "Run the complete evidence scan (Ctrl+Enter)")

        navigation = ttk.Frame(root, style="Surface.TFrame", padding=(10, 8))
        navigation.pack(fill="x", pady=(0, 14))
        for view, label in (("analysis", "New Analysis"), ("batch", "Batch Scan"), ("history", "History"), ("reports", "Reports"), ("iocs", "IOC Lists"), ("settings", "Settings")):
            button = ttk.Button(navigation, text=label, command=lambda selected=view: self._show_view(selected), style="Secondary.TButton")
            button.pack(side="left", padx=(0, 8))
            self._add_button_behavior(button, f"Open {label.lower()} view")

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

        self.view_widgets["analysis"] = (target, content)

        footer = ttk.Frame(root, style="App.TFrame")
        footer.pack(fill="x", pady=(14, 0))
        self.footer_label = ttk.Label(footer, text="Static evidence only. No behavioral execution performed.", style="Subtitle.TLabel")
        self.footer_label.pack(side="left")
        ttk.Label(footer, text="made by daniel • @shwdaniel7", style="Subtitle.TLabel").pack(side="right")

        self._build_auxiliary_views(root)

    def _build_auxiliary_views(self, parent):
        self.batch_view = ttk.Frame(parent, style="Surface.TFrame", padding=18)
        self.view_widgets["batch"] = (self.batch_view,)
        ttk.Label(self.batch_view, text="BATCH SCAN", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(self.batch_view, text="Analyze a folder with the configured analysis core.", style="Muted.TLabel").pack(anchor="w", pady=(4, 14))
        batch_controls = ttk.Frame(self.batch_view, style="Surface.TFrame")
        batch_controls.pack(fill="x", pady=(0, 12))
        ttk.Button(batch_controls, text="Choose folder", command=self._choose_batch_folder, style="Action.TButton").pack(side="left")
        self.batch_status = ttk.Label(batch_controls, text="No folder selected.", style="Muted.TLabel")
        self.batch_status.pack(side="left", padx=12)
        self.batch_tree = ttk.Treeview(self.batch_view, columns=("file", "status", "risk", "time", "cache"), show="headings")
        for column, title, width in (("file", "FILE", 260), ("status", "STATUS", 100), ("risk", "RISK", 100), ("time", "TIME", 100), ("cache", "CACHE", 80)):
            self.batch_tree.heading(column, text=title)
            self.batch_tree.column(column, width=width, anchor="w")
        self.batch_tree.pack(fill="both", expand=True)

        self.history_view = self._build_history_view(parent)
        self.view_widgets["history"] = (self.history_view,)
        self.reports_view = self._build_reports_view(parent)
        self.view_widgets["reports"] = (self.reports_view,)
        self.iocs_view = self._simple_view(parent, "IOC LISTS", "Local indicator list integrity")
        self.iocs_text = self.iocs_view[1]
        self.view_widgets["iocs"] = (self.iocs_view[0],)
        self.settings_view = self._build_settings_view(parent)
        self.view_widgets["settings"] = (self.settings_view,)
        self._show_view("analysis")

    def _build_history_view(self, parent):
        view = ttk.Frame(parent, style="Surface.TFrame", padding=18)
        header = ttk.Frame(view, style="Surface.TFrame")
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="HISTORY", style="PanelTitle.TLabel").pack(side="left")
        ttk.Label(header, text="Previous JSON analyses", style="Muted.TLabel").pack(side="left", padx=(12, 0))
        ttk.Button(header, text="Clear History", command=self._clear_history, style="Secondary.TButton").pack(side="right")
        self.history_text = tk.Text(view, background=COLORS["surface"], foreground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Consolas", 9), state="disabled")
        self.history_text.pack(fill="both", expand=True)
        return view

    def _build_reports_view(self, parent):
        view = ttk.Frame(parent, style="Surface.TFrame", padding=18)
        header = ttk.Frame(view, style="Surface.TFrame")
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="REPORTS", style="PanelTitle.TLabel").pack(side="left")
        ttk.Label(header, text="Generated JSON, CSV, and HTML reports", style="Muted.TLabel").pack(side="left", padx=(12, 0))
        ttk.Button(header, text="Clear Reports", command=self._clear_reports, style="Secondary.TButton").pack(side="right")
        self.reports_text = tk.Text(view, background=COLORS["surface"], foreground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Consolas", 9), state="disabled")
        self.reports_text.pack(fill="both", expand=True)
        return view

    def _build_settings_view(self, parent):
        view = ttk.Frame(parent, style="Surface.TFrame", padding=18)
        ttk.Label(view, text="SETTINGS", style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(view, text="Operational settings for the analysis core", style="Muted.TLabel").pack(anchor="w", pady=(4, 14))
        self.settings_text = tk.Text(view, background=COLORS["surface"], foreground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Consolas", 9), state="disabled")
        self.settings_text.pack(fill="both", expand=True)
        self.settings_text.configure(state="normal")
        self.settings_text.insert("end", "Cache: enabled by default\nBatch workers: configured by the analysis profile\nVirusTotal: controlled by VT_API_KEY\n\nUse CLI flags for advanced automation settings.")
        self.settings_text.configure(state="disabled")
        return view

    def _add_button_behavior(self, button, tooltip):
        Tooltip(button, tooltip)
        button.bind("<Enter>", lambda _event: button.configure(cursor="hand2"), add="+")
        button.bind("<Leave>", lambda _event: button.configure(cursor=""), add="+")

    def _bind_shortcuts(self):
        self.bind("<Control-o>", lambda _event: self._choose_file())
        self.bind("<F5>", lambda _event: self._start_scan(True))
        self.bind("<Control-Return>", lambda _event: self._start_scan(False))

    def _simple_view(self, parent, title, subtitle):
        view = ttk.Frame(parent, style="Surface.TFrame", padding=18)
        ttk.Label(view, text=title, style="PanelTitle.TLabel").pack(anchor="w")
        ttk.Label(view, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(4, 14))
        text = tk.Text(view, background=COLORS["surface"], foreground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Consolas", 9), state="disabled")
        text.pack(fill="both", expand=True)
        return view, text

    def _show_view(self, view_name):
        for widgets in self.view_widgets.values():
            for widget in widgets:
                widget.pack_forget()
        if view_name == "analysis":
            self.view_widgets["analysis"][0].pack(fill="x", pady=(0, 16))
            self.view_widgets["analysis"][1].pack(fill="both", expand=True)
        else:
            self.view_widgets[view_name][0].pack(fill="both", expand=True)
        self.active_view = view_name
        self.status_label.configure(text=view_name.upper().replace("_", " "), foreground=COLORS["muted"])
        if view_name == "history":
            self._load_history()
        elif view_name == "reports":
            self._load_reports()
        elif view_name == "iocs":
            self._load_iocs()

    def _write_view_text(self, text_widget, content):
        text_widget.configure(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("end", content)
        text_widget.configure(state="disabled")

    def _load_history(self):
        reports_dir = "reports"
        entries = []
        if os.path.isdir(reports_dir):
            for filename in sorted(os.listdir(reports_dir), reverse=True):
                if not filename.endswith(".json") or filename.startswith("batch_summary"):
                    continue
                try:
                    with open(os.path.join(reports_dir, filename), encoding="utf-8") as report_file:
                        data = json.load(report_file)
                    risk = data.get("risk_summary", {})
                    metadata = data.get("metadata", {})
                    entries.append(f"{metadata.get('analysis_date', '-')}  |  {metadata.get('archive_name', filename)}  |  {risk.get('level', 'Unknown')} ({risk.get('score', '-')}/100)")
                except (OSError, json.JSONDecodeError):
                    continue
        self._write_view_text(self.history_text, "\n".join(entries) if entries else "No analysis history found.")

    def _load_reports(self):
        reports_dir = "reports"
        entries = sorted(os.listdir(reports_dir)) if os.path.isdir(reports_dir) else []
        self._write_view_text(self.reports_text, "\n".join(entries) if entries else "No reports found.")

    def _load_iocs(self):
        details = inspect_ioc_lists()
        lines = []
        for name, data in details.items():
            lines.append(f"{name}: {data['valid_count']} valid")
            lines.append(f"  file: {data['path']}")
            lines.append(f"  malformed: {len(data['invalid'])}")
        self._write_view_text(self.iocs_text, "\n".join(lines))

    def _clear_history(self):
        if not messagebox.askyesno("Clear History", "Delete all analysis history (JSON reports)?\nThis cannot be undone."):
            return
        from modules.reports import clear_history
        result = clear_history("reports", include_cache=False)
        self._load_history()
        messagebox.showinfo("History Cleared", f"Deleted {result['deleted']} history file(s).")

    def _clear_reports(self):
        if not messagebox.askyesno("Clear Reports", "Delete ALL reports (JSON, CSV, HTML) and batch summaries?\nThis cannot be undone."):
            return
        from modules.reports import clear_history
        result = clear_history("reports", include_cache=False)
        self._load_reports()
        self._load_history()
        messagebox.showinfo("Reports Cleared", f"Deleted {result['deleted']} report file(s).")

    def _choose_batch_folder(self):
        folder = filedialog.askdirectory(title="Select a folder for batch analysis")
        if not folder:
            return
        for item in self.batch_tree.get_children():
            self.batch_tree.delete(item)
        self.batch_status.configure(text=f"Scanning {folder}...")
        self._set_controls(False)
        self.analysis_thread = threading.Thread(target=self._run_batch, args=(folder,), daemon=True)
        self.analysis_thread.start()

    def _run_batch(self, folder):
        candidates, skipped = collect_candidates(folder)

        worker_count = min(4, max(1, os.cpu_count() or 1))

        config = {
            "blacklist": True,
            "virustotal": False,
            "strings": True,
            "ioc_extract": True,
            "entropy": True,
            "magic_numbers": True,
            "pe_analysis": True,
            "gerar_report": True,
            "report_format": "json",
            "output_dir": "reports",
            "quiet": True,
            "workers": worker_count,
            "cache_enabled": True,
            "minimum_report_score": 50,
            "virustotal_suspicious_only": True,
        }

        self.events.put(("batch_started", len(candidates)))
        batch_started = time.perf_counter()
        batch_results, _, _ = run_batch_analysis(
            folder,
            config,
            on_progress=lambda result, index, total: self.events.put(
                ("batch_result", index, total, result)
            ),
            on_error=lambda filepath, error, index, total: self.events.put(
                ("batch_error", index, total, filepath, str(error))
            ),
        )

        summary_path = save_batch_summary(
            folder,
            batch_results,
            round(time.perf_counter() - batch_started, 3),
            reports_folder=config["output_dir"],
            skipped=skipped,
        )
        self.events.put(("batch_summary", summary_path))
        self.events.put(("batch_complete", len(candidates)))

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
            value = ttk.Label(row, text="-", style="Body.TLabel", wraplength=220)
            value.pack(anchor="w", pady=(2, 0))
            self.identity_values[key] = value
        self.path_label = ttk.Label(self.identity_panel, text="Path: -", style="Muted.TLabel", wraplength=220)
        self.path_label.pack(anchor="w", pady=(12, 4))
        self.copy_hash_button = ttk.Button(self.identity_panel, text="Copy SHA-256", command=self._copy_hash, style="Secondary.TButton")
        self.copy_hash_button.pack(anchor="w", pady=(4, 0))
        self._identity_wrap_widgets = [value for value in self.identity_values.values()]
        self._identity_wrap_widgets.append(self.path_label)
        self.identity_panel.bind("<Configure>", self._fit_identity_wrap)

    def _fit_identity_wrap(self, event=None):
        width = (event.width if event else self.identity_panel.winfo_width()) - 24
        wrap = min(520, max(140, width))
        for widget in self._identity_wrap_widgets:
            widget.configure(wraplength=wrap)

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
        self.evidence_tree.column("status", width=70, anchor="center", stretch=False)
        self.evidence_tree.column("engine", width=130, anchor="w", stretch=False)
        self.evidence_tree.column("detail", width=220, anchor="w")
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
        self.factors_text = tk.Text(self.verdict_panel, height=12, width=2, background=COLORS["surface_alt"], foreground=COLORS["text"], insertbackground=COLORS["text"], relief="flat", borderwidth=0, wrap="word", font=("Segoe UI", 9), state="disabled")
        self.factors_text.pack(fill="both", expand=True, pady=(8, 0))

    def _choose_file(self):
        filepath = filedialog.askopenfilename(title="Select a file to analyze")
        if filepath:
            self.selected_file = filepath
            self.target_label.configure(text=filepath, foreground=COLORS["text"])
            self.status_label.configure(text="READY", foreground=COLORS["green"])
            self._populate_identity(filepath)

    def _populate_identity(self, filepath):
        try:
            size_bytes = os.path.getsize(filepath)
        except OSError:
            size_bytes = None
        declared_extension = os.path.splitext(filepath)[1].lower() or "(none)"
        self.identity_values["file"].configure(text=os.path.basename(filepath))
        self.identity_values["extension"].configure(text=declared_extension)
        self.identity_values["size"].configure(
            text=f"{size_bytes:,} bytes" if size_bytes is not None else "Unavailable"
        )
        self.path_label.configure(text=self._format_path(filepath))

        try:
            file_type = analyze_file_type(filepath)
            detected_type = file_type["detected_type"]
            compatibility = file_type["compatibility"]
        except OSError:
            detected_type = "Unavailable"
            compatibility = "Unknown"
        self.identity_values["type"].configure(text=detected_type)
        self.identity_values["compatibility"].configure(
            text=compatibility,
            foreground={
                "Compatible": COLORS["green"],
                "Mismatch": COLORS["red"],
                "Unknown": COLORS["yellow"],
            }.get(compatibility, COLORS["muted"]),
        )

        self.identity_values["hash"].configure(
            text="Calculating...", foreground=COLORS["muted"], font=("Segoe UI", 9)
        )
        self._selected_hash = None
        self._identity_hash_thread = threading.Thread(
            target=self._compute_identity_hash, args=(filepath,), daemon=True
        )
        self._identity_hash_thread.start()

    def _compute_identity_hash(self, filepath):
        try:
            value = calc_sha256(filepath)
        except Exception:
            value = None
        self.events.put(("identity", filepath, "hash", value))

    @staticmethod
    def _chunk_hex(value, size=16):
        return "\n".join(value[index:index + size] for index in range(0, len(value), size))

    @staticmethod
    def _format_path(filepath):
        path = str(filepath)
        if not path:
            return "Path: -"
        parts = path.replace("/", os.sep).split(os.sep)
        return "Path: " + "\n".join(parts)

    def _copy_hash(self):
        value = self._selected_hash
        if not value:
            value = self.identity_values["hash"].cget("text")
        if value and value not in ("-", "Not calculated", "Calculating...", "Hash not available"):
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
        kind = event[0]
        if kind == "identity":
            _, token, field, value = event
            if token != self.selected_file or field != "hash":
                return
            if value:
                self._selected_hash = value
                self.identity_values["hash"].configure(text=self._chunk_hex(value), foreground=COLORS["text"], font=("Consolas", 8))
            else:
                self.identity_values["hash"].configure(text="Hash not available", foreground=COLORS["muted"], font=("Segoe UI", 9))
            return
        if kind == "batch_started":
            self.batch_status.configure(text=f"0 / {event[1]} files complete")
            return
        if kind == "batch_result":
            _, index, total, result = event
            cache_label = "HIT" if result.get("cache_hit") else "-"
            self.batch_tree.insert("", "end", values=(result["file"], "COMPLETE", f"{result['risk_level']} ({result['risk_score']})", f"{result['analysis_duration']:.3f}s", cache_label))
            self.batch_status.configure(text=f"{index} / {total} files complete")
            return
        if kind == "batch_error":
            _, index, total, filepath, error = event
            self.batch_tree.insert("", "end", values=(os.path.basename(filepath), "FAILED", "-", "-", error))
            self.batch_status.configure(text=f"{index} / {total} files complete")
            return
        if kind == "batch_complete":
            self.batch_status.configure(text=f"Batch complete: {event[1]} files analyzed")
            self._set_controls(True)
            return
        if kind == "batch_summary":
            self.batch_status.configure(text=f"Batch summary: {event[1]}")
            return
        if kind == "result":
            payload = event[1]
        elif kind == "error":
            payload = event[1]
        else:
            return
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
        compatibility_color = {
            "Compatible": COLORS["green"],
            "Mismatch": COLORS["red"],
            "Unknown": COLORS["yellow"],
        }.get(file_type.get("compatibility"), COLORS["muted"])
        self.identity_values["compatibility"].configure(foreground=compatibility_color)
        sha256_value = details.get("sha256", "Not calculated")
        self._selected_hash = sha256_value if sha256_value and sha256_value != "Not calculated" else None
        self.identity_values["hash"].configure(text=self._chunk_hex(sha256_value) if sha256_value else "Not calculated", font=("Consolas", 8), foreground=COLORS["text"])
        self.identity_values["size"].configure(text=f"{details.get('size_bytes', 0)} bytes")
        self.path_label.configure(text=self._format_path(result.get("path", "-")))
        risk = result["risk"]
        self.risk_label.configure(text=f"{risk['level'].upper()} RISK", foreground=self._risk_color(risk["level"]))
        self.score_label.configure(text=f"{risk['score']} / 100  |  {result['analysis_duration']:.3f}s")
        self.factors_text.configure(state="normal")
        self.factors_text.delete("1.0", "end")
        self.factors_text.configure(state="disabled")
        self._reveal_factors(risk["factors"], 0)
        self._render_evidence(result)

    def _reveal_factors(self, factors, index):
        if index >= len(factors):
            self._result_reveal_job = None
            return
        self.factors_text.configure(state="normal")
        self.factors_text.insert("end", f"> {factors[index]}\n\n")
        self.factors_text.configure(state="disabled")
        self._result_reveal_job = self.after(90, self._reveal_factors, factors, index + 1)

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
        if self._result_reveal_job:
            self.after_cancel(self._result_reveal_job)
            self._result_reveal_job = None
        for _, text in self.evidence_tabs.values():
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("end", "No analysis data yet.")
            text.configure(state="disabled")

    def _set_stage(self, stage, state):
        symbols = {"QUEUED": "○", "RUNNING": "●", "COMPLETE": "✓", "FAILED": "✕"}
        colors = {"QUEUED": COLORS["muted"], "RUNNING": COLORS["cyan"], "COMPLETE": COLORS["green"], "FAILED": COLORS["red"]}
        self.stage_labels[stage].configure(text=f"{symbols.get(state, '○')} {stage}", foreground=colors.get(state, COLORS["muted"]))
        if state == "RUNNING":
            if stage in self._pulse_jobs:
                self.after_cancel(self._pulse_jobs.pop(stage))
            self._pulse_stage(stage)
        elif stage in self._pulse_jobs:
            self.after_cancel(self._pulse_jobs.pop(stage))

    def _pulse_stage(self, stage):
        if not self.stage_labels[stage].cget("text").endswith(stage):
            return
        label = self.stage_labels[stage]
        if label.cget("foreground") == COLORS["cyan"]:
            label.configure(foreground=COLORS["crimson"])
        else:
            label.configure(foreground=COLORS["cyan"])
        self._pulse_jobs[stage] = self.after(650, self._pulse_stage, stage)

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
