# vulnradar/gui - GUI implementation using Tkinter

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import asyncio
import threading
from typing import Dict, Any
import queue
from datetime import datetime

from .core import VulnRadar

class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    def __init__(self, parent, text, command, bg="#2196F3", fg="white", hover_bg="#1976D2", **kwargs):
        super().__init__(parent, height=40, bg=parent.cget('bg'), highlightthickness=0, **kwargs)
        self.command = command
        self.bg = bg
        self.hover_bg = hover_bg
        self.fg = fg
        self.text = text
        
        self.rect = self.create_rectangle(0, 0, 200, 40, fill=bg, outline="", tags="btn")
        self.text_id = self.create_text(50, 20, text=text, fill=fg, font=("Segoe UI", 10, "bold"), tags="btn")
        
        self.bind("<Button-1>", lambda e: command())
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, e):
        self.itemconfig(self.rect, fill=self.hover_bg)
        
    def on_leave(self, e):
        self.itemconfig(self.rect, fill=self.bg)
        
    def configure_state(self, state):
        if state == "disabled":
            self.itemconfig(self.rect, fill="#CCCCCC")
            self.unbind("<Button-1>")
            self.unbind("<Enter>")
            self.unbind("<Leave>")
        else:
            self.itemconfig(self.rect, fill=self.bg)
            self.bind("<Button-1>", lambda e: self.command())
            self.bind("<Enter>", self.on_enter)
            self.bind("<Leave>", self.on_leave)


class VulnRadarGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnRadar - Web Vulnerability Scanner")
        
        # Color scheme - Dark security theme
        self.colors = {
            'bg': '#0D1117',
            'secondary_bg': '#161B22',
            'accent': '#58A6FF',
            'success': '#3FB950',
            'warning': '#D29922',
            'danger': '#F85149',
            'text': '#C9D1D9',
            'text_secondary': '#8B949E',
            'border': '#30363D'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Configure custom styles
        self.setup_styles()
        
        # Create main layout
        self.create_header()
        self.create_main_container()
        
        # Initialize variables
        self.scan_running = False
        self.log_queue = queue.Queue()
        self.current_scan = None
        self.scan_stats = {'endpoints': 0, 'vulns': 0, 'severity': {}}
        
    def setup_styles(self):
        """Setup custom ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure base colors
        style.configure('.', background=self.colors['bg'], foreground=self.colors['text'])
        
        # Notebook style
        style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=self.colors['secondary_bg'],
                       foreground=self.colors['text'],
                       padding=[20, 10],
                       borderwidth=0)
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['accent'])],
                 foreground=[('selected', 'white')])
        
        # Frame style
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('Card.TFrame', background=self.colors['secondary_bg'], relief='flat')
        
        # Label styles
        style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['text'])
        style.configure('Header.TLabel', font=('Segoe UI', 24, 'bold'), foreground=self.colors['accent'])
        style.configure('Section.TLabel', font=('Segoe UI', 14, 'bold'), foreground=self.colors['text'])
        style.configure('Card.TLabel', background=self.colors['secondary_bg'], foreground=self.colors['text'])
        
        # Entry style
        style.configure('TEntry', fieldbackground=self.colors['secondary_bg'], 
                       foreground=self.colors['text'], borderwidth=1,
                       relief='flat', insertcolor=self.colors['text'])
        
        # Checkbutton style
        style.configure('TCheckbutton', background=self.colors['secondary_bg'],
                       foreground=self.colors['text'])
        style.map('TCheckbutton', background=[('active', self.colors['secondary_bg'])])
        
        # LabelFrame style
        style.configure('TLabelframe', background=self.colors['secondary_bg'],
                       foreground=self.colors['text'], borderwidth=1,
                       relief='solid', bordercolor=self.colors['border'])
        style.configure('TLabelframe.Label', background=self.colors['secondary_bg'],
                       foreground=self.colors['accent'], font=('Segoe UI', 11, 'bold'))
        
        # Progressbar style
        style.configure('TProgressbar', background=self.colors['accent'],
                       troughcolor=self.colors['secondary_bg'], borderwidth=0)
        
    def create_header(self):
        """Create application header"""
        header_frame = tk.Frame(self.root, bg=self.colors['secondary_bg'], height=80)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Logo/Title
        title = tk.Label(header_frame, text="VULNRADAR", 
                        font=('Segoe UI', 30, 'bold'),
                        bg=self.colors['secondary_bg'],
                        fg=self.colors['accent'])
        title.pack(side=tk.LEFT, padx=30, pady=20)
        
        subtitle = tk.Label(header_frame, text="Web Vulnerability Scanner",
                          font=('Segoe UI', 10, 'bold'),
                          bg=self.colors['secondary_bg'],
                          fg=self.colors['text_secondary'])
        subtitle.pack(side=tk.LEFT, padx=(0, 20))
        
        # Status indicator
        self.status_frame = tk.Frame(header_frame, bg=self.colors['secondary_bg'])
        self.status_frame.pack(side=tk.RIGHT, padx=30)
        
        self.status_indicator = tk.Canvas(self.status_frame, width=12, height=12,
                                         bg=self.colors['secondary_bg'],
                                         highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        self.status_circle = self.status_indicator.create_oval(2, 2, 10, 10,
                                                              fill=self.colors['success'],
                                                              outline="")
        
        self.status_label = tk.Label(self.status_frame, text="Ready",
                                     font=('Segoe UI', 10),
                                     bg=self.colors['secondary_bg'],
                                     fg=self.colors['text'])
        self.status_label.pack(side=tk.LEFT)
        
    def create_main_container(self):
        """Create main container with notebook"""
        container = tk.Frame(self.root, bg=self.colors['bg'])
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Create notebook
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.scan_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.recon_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.results_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.settings_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        self.logs_tab = tk.Frame(self.notebook, bg=self.colors['bg'])
        
        self.notebook.add(self.scan_tab, text="🎯 Scan")
        self.notebook.add(self.recon_tab, text="🔍 Reconnaissance")
        self.notebook.add(self.results_tab, text="📊 Results")
        self.notebook.add(self.settings_tab, text="⚙️ Settings")
        self.notebook.add(self.logs_tab, text="📝 Logs")
        
        # Setup tabs
        self.setup_scan_tab()
        self.setup_recon_tab()
        self.setup_settings_tab()
        self.setup_results_tab()
        self.setup_logs_tab()

    def bind_mousewheel(self, canvas):
        """Enable mouse wheel scrolling only when mouse is over the canvas"""
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
        
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)

    def create_card(self, parent, title, row, column, columnspan=1, rowspan=1):
        """Create a card-style frame"""
        card = tk.Frame(parent, bg=self.colors['secondary_bg'],
                       highlightbackground=self.colors['border'],
                       highlightthickness=1)
        card.grid(row=row, column=column, columnspan=columnspan, rowspan=rowspan,
                 sticky='nsew', padx=10, pady=10)
        
        if title:
            header = tk.Label(card, text=title, font=('Segoe UI', 12, 'bold'),
                            bg=self.colors['secondary_bg'], fg=self.colors['accent'])
            header.pack(anchor=tk.W, padx=15, pady=(15, 10))
            
        return card
        
    def setup_scan_tab(self):
        """Setup scan tab with modern layout"""
        canvas = tk.Canvas(self.scan_tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.scan_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['bg'])

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="center")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.bind_mousewheel(canvas)

        # Configure grid
        scrollable_frame.columnconfigure(0, weight=1)
        scrollable_frame.columnconfigure(1, weight=1)
        scrollable_frame.columnconfigure(2, weight=1) 
        scrollable_frame.rowconfigure(2, weight=1)
        
        # Target Card
        target_card = self.create_card(scrollable_frame, "🎯 Target Configuration", 0, 0, columnspan=2)
        
        target_frame = tk.Frame(target_card, bg=self.colors['secondary_bg'])
        target_frame.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(target_frame, text="Target URL:", bg=self.colors['secondary_bg'],
                fg=self.colors['text'], font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.url_entry = tk.Entry(target_frame, bg=self.colors['bg'],
                                 fg=self.colors['text'], font=('Segoe UI', 11),
                                 insertbackground=self.colors['text'], relief='flat',
                                 highlightthickness=1, highlightbackground=self.colors['border'])
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        self.url_entry.insert(0, "https://target-site.com")
        
        # Scan Options Card
        options_card = self.create_card(scrollable_frame, "🔧 Scan Options", 1, 0)
        
        options_inner = tk.Frame(options_card, bg=self.colors['secondary_bg'])
        options_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # Vulnerability options
        self.vuln_vars = {}
        vulns = [
            ("SQL Injection", "sqli"),
            ("Cross-Site Scripting (XSS)", "xss"),
            ("CSRF", "csrf"),
            ("SSRF", "ssrf"),
            ("Path Traversal", "path"),
            ("File Inclusion", "file"),
            ("Command Injection", "cmd")
        ]
        
        for i, (label, key) in enumerate(vulns):
            var = tk.BooleanVar(value=True)
            self.vuln_vars[key] = var
            cb = tk.Checkbutton(options_inner, text=label, variable=var,
                              bg=self.colors['secondary_bg'], fg=self.colors['text'],
                              selectcolor=self.colors['bg'], activebackground=self.colors['secondary_bg'],
                              font=('Segoe UI', 9))
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=5, pady=5)
            
        # Advanced Options Card
        advanced_card = self.create_card(scrollable_frame, "⚡ Advanced Options", 1, 1)
        
        adv_inner = tk.Frame(advanced_card, bg=self.colors['secondary_bg'])
        adv_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        options = [
            ("Crawl Depth:", "depth_var", "3"),
            ("Timeout (s):", "timeout_var", "10"),
            ("Max Workers:", "workers_var", "5"),
            ("Max Pages:", "max_pages_var", "1000")
        ]
        
        for i, (label, var_name, default) in enumerate(options):
            tk.Label(adv_inner, text=label, bg=self.colors['secondary_bg'],
                    fg=self.colors['text'], font=('Segoe UI', 9)).grid(row=i, column=0, sticky=tk.W, pady=5)
            
            var = tk.StringVar(value=default)
            setattr(self, var_name, var)
            
            entry = tk.Entry(adv_inner, textvariable=var, width=8,
                           bg=self.colors['bg'], fg=self.colors['text'],
                           insertbackground=self.colors['text'], relief='flat')
            entry.grid(row=i, column=1, sticky=tk.W, padx=10, pady=5)
            
        self.selenium_var = tk.BooleanVar(value=False)
        tk.Checkbutton(adv_inner, text="Use Selenium", variable=self.selenium_var,
                      bg=self.colors['secondary_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg']).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.port_scan_var = tk.BooleanVar(value=False)
        tk.Checkbutton(adv_inner, text="Port Scan", variable=self.port_scan_var,
                      bg=self.colors['secondary_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg']).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Reconnaissance Mode Card
        recon_mode_card = self.create_card(scrollable_frame, "🔍 Reconnaissance Mode", 1, 2)

        recon_mode_inner = tk.Frame(recon_mode_card, bg=self.colors['secondary_bg'])
        recon_mode_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.advanced_recon_only_var = tk.BooleanVar(value=False)
        tk.Checkbutton(recon_mode_inner, text="Advanced Recon Only (Skip Vulnerability Scanning)", 
                    variable=self.advanced_recon_only_var,
                    bg=self.colors['secondary_bg'], fg=self.colors['text'],
                    selectcolor=self.colors['bg'], font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W, pady=5)

        tk.Label(recon_mode_inner, text="Select reconnaissance modules to run:",
                bg=self.colors['secondary_bg'], fg=self.colors['text_secondary'],
                font=('Segoe UI', 8)).pack(anchor=tk.W, pady=(10, 5))

        self.recon_all_var = tk.BooleanVar(value=False)
        tk.Checkbutton(recon_mode_inner, text="All Modules", 
                    variable=self.recon_all_var,
                    bg=self.colors['secondary_bg'], fg=self.colors['warning'],
                    selectcolor=self.colors['bg'], font=('Segoe UI', 9)).pack(anchor=tk.W, pady=2)

        self.recon_module_vars = {}
        modules = [
            ("Network Infrastructure", "recon_network"),
            ("Security Infrastructure", "recon_security"),
            ("Web Application", "recon_webapp"),
            ("Infrastructure Mapping", "recon_infrastructure"),
            ("Miscellaneous", "recon_misc")
        ]

        for label, key in modules:
            var = tk.BooleanVar(value=False)
            self.recon_module_vars[key] = var
            tk.Checkbutton(recon_mode_inner, text=label, variable=var,
                        bg=self.colors['secondary_bg'], fg=self.colors['text'],
                        selectcolor=self.colors['bg'], font=('Segoe UI', 8)).pack(anchor=tk.W, pady=2, padx=10)
    
        # Progress Card
        progress_card = self.create_card(scrollable_frame, "📊 Scan Progress", 2, 0, columnspan=2)
        
        progress_inner = tk.Frame(progress_card, bg=self.colors['secondary_bg'])
        progress_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = tk.Label(progress_inner, textvariable=self.progress_var,
                                 bg=self.colors['secondary_bg'], fg=self.colors['text'],
                                 font=('Segoe UI', 10))
        progress_label.pack(anchor=tk.W, pady=(0, 10))
        
        self.progress_bar = ttk.Progressbar(progress_inner, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 20))
        
        # Stats frame
        stats_frame = tk.Frame(progress_inner, bg=self.colors['secondary_bg'])
        stats_frame.pack(fill=tk.X)
        
        self.stat_labels = {}
        stats = [("Endpoints", "endpoints"), ("Vulnerabilities", "vulns")]
        
        for i, (label, key) in enumerate(stats):
            frame = tk.Frame(stats_frame, bg=self.colors['bg'],
                           highlightbackground=self.colors['border'], highlightthickness=1)
            frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
            
            tk.Label(frame, text=label, bg=self.colors['bg'],
                    fg=self.colors['text_secondary'], font=('Segoe UI', 9)).pack(pady=(10, 5))
            
            value_label = tk.Label(frame, text="0", bg=self.colors['bg'],
                                  fg=self.colors['accent'], font=('Segoe UI', 20, 'bold'))
            value_label.pack(pady=(0, 10))
            self.stat_labels[key] = value_label
            
        # Control Buttons
        button_frame = tk.Frame(progress_inner, bg=self.colors['secondary_bg'])
        button_frame.pack(pady=20)
        
        self.start_btn = ModernButton(button_frame, "▶ Start Scan", self.start_scan,
                                      bg=self.colors['success'], hover_bg='#2EA043', width=150)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ModernButton(button_frame, "⏹ Stop Scan", self.stop_scan,
                                     bg=self.colors['danger'], hover_bg='#DA3633', width=150)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn.configure_state("disabled")
        
    def setup_recon_tab(self):
        """Setup reconnaissance tab"""
        canvas = tk.Canvas(self.recon_tab, bg=self.colors['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.recon_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['bg'])
        
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="center")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.bind_mousewheel(canvas)

        self.recon_tab.columnconfigure(0, weight=1)
        self.recon_tab.rowconfigure(0, weight=1)
        
        # Recon modules
        self.recon_vars = {}
        
        modules = [
            ("Network Infrastructure", [
                ("Port Scanning", "port_scan"),
                ("WAF Detection", "waf"),
                ("Load Balancer Detection", "load_bal"),
                ("Service Detection", "service_detect"),
                ("OS Detection", "os_detect"),
                ("Script Scanning", "script_scan")
            ]),
            ("Web Application", [
                ("Content Discovery", "content_disc"),
                ("JavaScript Analysis", "js_analysis"),
                ("Directory Enumeration", "dir_enum")
            ]),
            ("Infrastructure", [
                ("Subdomain Enumeration", "subdomain"),
                ("Cloud Infrastructure", "cloud"),
                ("DNS Bruteforce", "dns_brute")
            ]),
            ("Security", [
                ("SSL/TLS Analysis", "ssl"),
                ("Security Headers", "sec_headers")
            ]),
            ("Miscellaneous", [
                ("Error Analysis", "error_analysis"),
                ("Cache Analysis", "cache_analysis"),
                ("Debug Mode Check", "debug_check"),
                ("Check Dev Artifacts", "check_dev_artifacts"),
                ("Backend Testing", "backend_tests"),
            ])
        ]
        
        for i, (category, options) in enumerate(modules):
            card = self.create_card(scrollable_frame, f"🔍 {category}", i, 0)
            
            inner = tk.Frame(card, bg=self.colors['secondary_bg'])
            inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
            
            for j, (label, key) in enumerate(options):
                var = tk.BooleanVar(value=True)
                self.recon_vars[key] = var
                
                cb = tk.Checkbutton(inner, text=label, variable=var,
                                  bg=self.colors['secondary_bg'], fg=self.colors['text'],
                                  selectcolor=self.colors['bg'], font=('Segoe UI', 9))
                cb.grid(row=j//2, column=j%2, sticky=tk.W, padx=5, pady=5)
                
    def setup_results_tab(self):
        """Setup results display tab"""
        self.results_tab.columnconfigure(0, weight=1)
        self.results_tab.rowconfigure(0, weight=1)
        
        # Results tree
        tree_frame = tk.Frame(self.results_tab, bg=self.colors['bg'])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview with scrollbar
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.results_tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set,
                                        selectmode='browse')
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        tree_scroll.config(command=self.results_tree.yview)
        
        # Define columns
        self.results_tree['columns'] = ("Type", "Severity", "Endpoint", "Description")
        self.results_tree.column("#0", width=50, minwidth=50)
        self.results_tree.column("Type", width=150, minwidth=100)
        self.results_tree.column("Severity", width=100, minwidth=80)
        self.results_tree.column("Endpoint", width=300, minwidth=200)
        self.results_tree.column("Description", width=400, minwidth=200)
        
        # Define headings
        self.results_tree.heading("#0", text="ID")
        self.results_tree.heading("Type", text="Vulnerability Type")
        self.results_tree.heading("Severity", text="Severity")
        self.results_tree.heading("Endpoint", text="Endpoint")
        self.results_tree.heading("Description", text="Description")
        
        # Style the treeview
        style = ttk.Style()
        style.configure("Treeview",
                       background=self.colors['secondary_bg'],
                       foreground=self.colors['text'],
                       fieldbackground=self.colors['secondary_bg'],
                       borderwidth=0)
        style.map('Treeview', background=[('selected', self.colors['accent'])])
        
    def setup_settings_tab(self):
        """Setup settings tab"""
        self.settings_tab.columnconfigure(0, weight=1)
        
        # Output Options
        output_card = self.create_card(self.settings_tab, "📁 Output Options", 0, 0)
        output_inner = tk.Frame(output_card, bg=self.colors['secondary_bg'])
        output_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.output_vars = {}
        formats = [("HTML Report", "html", True), ("PDF Report", "pdf", True),
                  ("JSON Report", "json", True), ("Excel Report", "excel", False)]
        
        for i, (label, key, default) in enumerate(formats):
            var = tk.BooleanVar(value=default)
            self.output_vars[key] = var
            cb = tk.Checkbutton(output_inner, text=label, variable=var,
                              bg=self.colors['secondary_bg'], fg=self.colors['text'],
                              selectcolor=self.colors['bg'], font=('Segoe UI', 9))
            cb.grid(row=i//2, column=i%2, sticky=tk.W, padx=5, pady=5)
            
        # Output directory
        dir_frame = tk.Frame(output_inner, bg=self.colors['secondary_bg'])
        dir_frame.grid(row=3, column=0, columnspan=2, sticky=tk.EW, pady=10)
        
        tk.Label(dir_frame, text="Output Directory:", bg=self.colors['secondary_bg'],
                fg=self.colors['text'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.output_dir_var = tk.StringVar(value="scan_results")
        entry = tk.Entry(dir_frame, textvariable=self.output_dir_var,
                        bg=self.colors['bg'], fg=self.colors['text'],
                        insertbackground=self.colors['text'], relief='flat')
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = ModernButton(dir_frame, "Browse", self.browse_output_dir,
                                 bg=self.colors['accent'], width=80)
        browse_btn.pack(side=tk.LEFT)
        
        # Database Options
        db_card = self.create_card(self.settings_tab, "💾 Database Options", 1, 0)
        db_inner = tk.Frame(db_card, bg=self.colors['secondary_bg'])
        db_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        self.use_db_var = tk.BooleanVar(value=False)
        tk.Checkbutton(db_inner, text="Store Results in Database", variable=self.use_db_var,
                      bg=self.colors['secondary_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg'], font=('Segoe UI', 9)).pack(anchor=tk.W, pady=5)
        
        db_path_frame = tk.Frame(db_inner, bg=self.colors['secondary_bg'])
        db_path_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(db_path_frame, text="Database Path:", bg=self.colors['secondary_bg'],
                fg=self.colors['text'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.db_path_var = tk.StringVar(value="vulnradar.db")
        tk.Entry(db_path_frame, textvariable=self.db_path_var,
                bg=self.colors['bg'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief='flat').pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Cache Options
        cache_card = self.create_card(self.settings_tab, "🗂️ Cache Options", 2, 0)
        cache_inner = tk.Frame(cache_card, bg=self.colors['secondary_bg'])
        cache_inner.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        cache_ttl_frame = tk.Frame(cache_inner, bg=self.colors['secondary_bg'])
        cache_ttl_frame.pack(fill=tk.X, pady=3)
        cache_dir_frame = tk.Frame(cache_inner, bg=self.colors['secondary_bg'])
        cache_dir_frame.pack(fill=tk.X, pady=3)

        self.no_cache_var = tk.BooleanVar(value=False)
        self.clear_cache_var = tk.BooleanVar(value=False)
        self.cache_ttl_var = tk.StringVar(value=3600)
        self.cache_dir_var = tk.StringVar(value="cache")

        tk.Label(cache_dir_frame, text="Cache Path:", bg=self.colors['secondary_bg'],
                fg=self.colors['text'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 10))
        tk.Entry(cache_dir_frame, textvariable=self.cache_dir_var,
                bg=self.colors['bg'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief='flat').pack(side=tk.LEFT, fill=tk.X)
        
        tk.Label(cache_ttl_frame, text="Cache time-to-live (secs):", bg=self.colors['secondary_bg'],
                fg=self.colors['text'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0, 10))
        tk.Entry(cache_ttl_frame, textvariable=self.cache_ttl_var,
                bg=self.colors['bg'], fg=self.colors['text'],
                insertbackground=self.colors['text'], relief='flat').pack(side=tk.LEFT, fill=tk.X)
        
        tk.Checkbutton(cache_inner, text="Disable Cache", variable=self.no_cache_var,
                      bg=self.colors['secondary_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg'], font=('Segoe UI', 9)).pack(anchor=tk.W, pady=3)
        
        tk.Checkbutton(cache_inner, text="Clear Cache Before Scan", variable=self.clear_cache_var,
                      bg=self.colors['secondary_bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg'], font=('Segoe UI', 9)).pack(anchor=tk.W, pady=3)
        
    def setup_logs_tab(self):
        """Setup logs tab"""
        self.logs_tab.columnconfigure(0, weight=1)
        self.logs_tab.rowconfigure(0, weight=1)
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(
            self.logs_tab, bg=self.colors['secondary_bg'],
            fg=self.colors['text'], font=('Consolas', 9),
            insertbackground=self.colors['text'], relief='flat',
            highlightthickness=1, highlightbackground=self.colors['border']
        )
        self.log_text.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        
        # Configure tags for colored logs
        self.log_text.tag_config("info", foreground=self.colors['accent'])
        self.log_text.tag_config("success", foreground=self.colors['success'])
        self.log_text.tag_config("warning", foreground=self.colors['warning'])
        self.log_text.tag_config("error", foreground=self.colors['danger'])
        
        # Button frame
        btn_frame = tk.Frame(self.logs_tab, bg=self.colors['bg'])
        btn_frame.grid(row=1, column=0, pady=10)
        
        clear_btn = ModernButton(btn_frame, "Clear Logs", self.clear_logs,
                                bg=self.colors['warning'], width=120)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = ModernButton(btn_frame, "Save Logs", self.save_logs,
                               bg=self.colors['accent'], width=120)
        save_btn.pack(side=tk.LEFT, padx=5)
        
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(initialdir=".", title="Select Output Directory")
        if directory:
            self.output_dir_var.set(directory)
            
    def clear_logs(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
        
    def save_logs(self):
        """Save logs to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))
            self.log_message("Logs saved successfully", "success")
                
    def log_message(self, message: str, level: str = "info"):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, formatted_msg, level)
        self.log_text.see(tk.END)
        
    def update_status(self, message: str, color: str = None):
        """Update status indicator"""
        self.status_label.config(text=message)
        if color:
            self.status_indicator.itemconfig(self.status_circle, fill=color)
        
    def update_stats(self, endpoints: int = None, vulns: int = None):
        """Update statistics display"""
        if endpoints is not None:
            self.stat_labels['endpoints'].config(text=str(endpoints))
        if vulns is not None:
            self.stat_labels['vulns'].config(text=str(vulns))
            
    def add_vulnerability_to_tree(self, vuln: Dict[str, Any]):
        """Add vulnerability to results tree"""
        vuln_id = len(self.results_tree.get_children()) + 1
        severity_colors = {
            'High': self.colors['danger'],
            'Medium': self.colors['warning'],
            'Low': self.colors['accent']
        }
        
        self.results_tree.insert("", tk.END, text=str(vuln_id),
                                values=(vuln.get('type', 'Unknown'),
                                       vuln.get('severity', 'Unknown'),
                                       vuln.get('endpoint', 'N/A'),
                                       vuln.get('description', 'No description')))
        
    def start_scan(self):
        """Start vulnerability scan"""
        if not self.url_entry.get().strip():
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        # Validate URL format
        url = self.url_entry.get().strip()
        if not url.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return
            
        self.scan_running = True
        self.start_btn.configure_state("disabled")
        self.stop_btn.configure_state("normal")
        self.progress_var.set("Initializing scan...")
        self.progress_bar.start(10)
        self.update_status("Scanning", self.colors['warning'])
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.update_stats(0, 0)
        
        # Prepare scan options
        options = {
            "crawl_depth": int(self.depth_var.get()),
            "timeout": int(self.timeout_var.get()),
            "max_workers": int(self.workers_var.get()),
            "max_crawl_pages": int(self.max_pages_var.get()),
            "use_selenium": self.selenium_var.get(),
            "port_scan": self.port_scan_var.get(),
            "scan_sqli": self.vuln_vars['sqli'].get(),
            "scan_xss": self.vuln_vars['xss'].get(),
            "scan_csrf": self.vuln_vars['csrf'].get(),
            "scan_ssrf": self.vuln_vars['ssrf'].get(),
            "scan_path_traversal": self.vuln_vars['path'].get(),
            "scan_file_inclusion": self.vuln_vars['file'].get(),
            "scan_command_injection": self.vuln_vars['cmd'].get(),
            "advanced_recon_only": self.advanced_recon_only_var.get(),
            "recon_all": self.recon_all_var.get(),
            "recon_network": self.recon_module_vars['recon_network'].get(),
            "recon_security": self.recon_module_vars['recon_security'].get(),
            "recon_webapp": self.recon_module_vars['recon_webapp'].get(),
            "recon_infrastructure": self.recon_module_vars['recon_infrastructure'].get(),
            "recon_misc": self.recon_module_vars['recon_misc'].get(),
            "advanced_port_scan": self.recon_vars.get('port_scan', tk.BooleanVar(value=True)).get(),
            "detect_waf": self.recon_vars.get('waf', tk.BooleanVar(value=True)).get(),
            "detect_load_balancers": self.recon_vars.get('load_bal', tk.BooleanVar(value=True)).get(),
            "service_detection": self.recon_vars.get('service_detect', tk.BooleanVar(value=True)).get(),
            "os_detection": self.recon_vars.get('os_detect', tk.BooleanVar(value=True)).get(),
            "script_scan": self.recon_vars.get('script_scan', tk.BooleanVar(value=True)).get(),
            "content_discovery": self.recon_vars.get('content_disc', tk.BooleanVar(value=True)).get(),
            "js_analysis": self.recon_vars.get('js_analysis', tk.BooleanVar(value=True)).get(),
            "dir_enum": self.recon_vars.get('dir_enum', tk.BooleanVar(value=False)).get(),
            "subdomain_enum": self.recon_vars.get('subdomain', tk.BooleanVar(value=True)).get(),
            "cloud_mapping": self.recon_vars.get('cloud', tk.BooleanVar(value=True)).get(),
            "dns_bruteforce": self.recon_vars.get('dns_brute', tk.BooleanVar(value=True)).get(),
            "ssl_analysis": self.recon_vars.get('ssl', tk.BooleanVar(value=True)).get(),
            "security_headers": self.recon_vars.get('sec_headers', tk.BooleanVar(value=True)).get(),
            "error_analysis": self.recon_vars.get('error_analysis', tk.BooleanVar(value=True)).get(),
            "cache_analysis": self.recon_vars.get('cache_analysis', tk.BooleanVar(value=True)).get(),
            "check_debug_mode": self.recon_vars.get('debug_check', tk.BooleanVar(value=True)).get(),
            "check_dev_artifacts": self.recon_vars.get('check_dev_artifacts', tk.BooleanVar(value=True)).get(),
            "backend_tests": self.recon_vars.get('backend_tests', tk.BooleanVar(value=True)).get(),
            "output_dir": self.output_dir_var.get(),
            "use_db": self.use_db_var.get(),
            "db_path": self.db_path_var.get(),
            "html_report": self.output_vars['html'].get(),
            "pdf_report": self.output_vars['pdf'].get(),
            "json_report": self.output_vars['json'].get(),
            "excel_report": self.output_vars['excel'].get(),
            "cache": self.cache_dir_var.get(),
            "cache_ttl": int(self.cache_ttl_var.get()),
            "no_cache": self.no_cache_var.get(),
            "clear_cache": self.clear_cache_var.get(),
        }
        
        self.log_message("Starting scan against: " + url, "info")
        
        # Start scan in separate thread
        threading.Thread(target=self.run_scan, args=(url, options), daemon=True).start()
        
    def stop_scan(self):
        """Stop running scan"""
        if self.scan_running:
            self.scan_running = False
            self.progress_var.set("Stopping scan...")
            self.log_message("Scan stop requested", "warning")
            
    def run_scan(self, url: str, options: Dict[str, Any]):
        """Run scan in background thread"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            scanner = VulnRadar(url, options)
            self.current_scan = scanner
            
            self.progress_var.set("Validating target...")
            self.log_message("Validating target accessibility...", "info")
            
            self.progress_var.set("Running Vulnerability Scan...")
            results = loop.run_until_complete(scanner.scan())
            
            if not self.scan_running:
                self.log_message("Scan stopped by user", "warning")
                return
                
            if results.get("error"):
                self.log_message(f"Error: {results['error']}", "error")
                messagebox.showerror("Scan Error", results['error'])
            else:
                self.log_message("Scan completed successfully!", "success")
                self.log_message(f"Target: {results['target']}", "info")
                self.log_message(f"Scan time: {results['scan_time']}", "info")
                
                endpoints_count = len(results.get('endpoints', []))
                vulns_count = len(results.get('vulnerabilities', []))
                
                self.log_message(f"Endpoints discovered: {endpoints_count}", "info")
                self.log_message(f"Vulnerabilities found: {vulns_count}", "success" if vulns_count == 0 else "warning")
                
                self.update_stats(endpoints_count, vulns_count)
                
                # Add vulnerabilities to tree
                for vuln in results.get('vulnerabilities', []):
                    self.add_vulnerability_to_tree(vuln)
                    severity_color = "error" if vuln.get('severity') == 'High' else "warning"
                    self.log_message(
                        f"Found: {vuln.get('type')} ({vuln.get('severity')}) at {vuln.get('endpoint')}", 
                        severity_color
                    )
                
                # Show summary
                if vulns_count > 0:
                    severity_summary = {}
                    for vuln in results.get('vulnerabilities', []):
                        sev = vuln.get('severity', 'Unknown')
                        severity_summary[sev] = severity_summary.get(sev, 0) + 1
                    
                    summary = "Vulnerability Summary:\n"
                    for sev, count in severity_summary.items():
                        summary += f"  {sev}: {count}\n"
                    
                    self.log_message(summary, "warning")
                else:
                    self.log_message("No vulnerabilities detected!", "success")
                
                self.progress_var.set(f"Scan complete - {vulns_count} vulnerabilities found")
                
                # Switch to results tab
                self.notebook.select(2)
                
                messagebox.showinfo("Scan Complete", 
                                  f"Scan completed successfully!\n\n"
                                  f"Endpoints: {endpoints_count}\n"
                                  f"Vulnerabilities: {vulns_count}\n\n"
                                  f"Reports saved to: {options['output_dir']}")
                
        except Exception as e:
            self.log_message(f"Error during scan: {str(e)}", "error")
            self.progress_var.set("Scan failed")
            messagebox.showerror("Scan Error", f"An error occurred:\n{str(e)}")
            
        finally:
            self.scan_running = False
            self.start_btn.configure_state("normal")
            self.stop_btn.configure_state("disabled")
            self.progress_bar.stop()
            self.update_status("Ready", self.colors['success'])
            loop.close()
