#!/usr/bin/env python3
"""
Hash Generator & Verifier - Graphical User Interface (GUI)
Built with Python Tkinter & TTK.
"""

import os
import sys

import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Import core functionality and VirusTotal client
from hash_tool import (
    SUPPORTED_ALGOS,
    is_valid_hash,
    compute_hash,
    compute_text_hash,
    generate_hash_file,
    verify_file,
    verify_from_hash_file,
    hash_directory,
)
import vt_client


class HashToolGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Hash Generator & Verifier (VirusTotal Integrated)")
        self.geometry("860x720")
        self.minsize(780, 620)

        # Apply modern dark theme colors
        self.colors = {
            "bg": "#1e1e2e",
            "card": "#24273a",
            "fg": "#cdd6f4",
            "subtext": "#a6adc8",
            "accent": "#89b4fa",
            "accent_hover": "#74c7ec",
            "success": "#a6e3a1",
            "success_bg": "#1c3326",
            "danger": "#f38ba8",
            "danger_bg": "#3c1f28",
            "border": "#313244",
            "input_bg": "#181825",
        }

        self.configure(bg=self.colors["bg"])
        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Configure frame & notebook styles
        self.style.configure(".", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 10))
        self.style.configure("TFrame", background=self.colors["bg"])
        self.style.configure("Card.TFrame", background=self.colors["card"], relief="flat")
        self.style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        self.style.configure(
            "TNotebook.Tab",
            background=self.colors["border"],
            foreground=self.colors["subtext"],
            padding=[16, 8],
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["accent"]), ("active", self.colors["card"])],
            foreground=[("selected", "#11111b"), ("active", self.colors["fg"])],
        )

        # Label styles
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.colors["accent"], background=self.colors["bg"])
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 11, "bold"), foreground=self.colors["fg"], background=self.colors["card"])
        self.style.configure("Muted.TLabel", font=("Segoe UI", 9), foreground=self.colors["subtext"], background=self.colors["card"])
        self.style.configure("Card.TLabel", background=self.colors["card"], foreground=self.colors["fg"])

        # Button styles
        self.style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            background=self.colors["accent"],
            foreground="#11111b",
            padding=[12, 6],
            borderwidth=0,
        )
        self.style.map("Accent.TButton", background=[("active", self.colors["accent_hover"])])

        self.style.configure(
            "Action.TButton",
            font=("Segoe UI", 9),
            background=self.colors["border"],
            foreground=self.colors["fg"],
            padding=[10, 5],
            borderwidth=0,
        )
        self.style.map("Action.TButton", background=[("active", self.colors["accent"])])

        # Entry & Combobox
        self.style.configure(
            "TEntry",
            fieldbackground=self.colors["input_bg"],
            foreground=self.colors["fg"],
            insertcolor=self.colors["fg"],
            padding=6,
        )
        self.style.configure(
            "TCombobox",
            fieldbackground=self.colors["input_bg"],
            background=self.colors["border"],
            foreground=self.colors["fg"],
            padding=6,
        )

        # Treeview (for Directory table)
        self.style.configure(
            "Treeview",
            background=self.colors["input_bg"],
            foreground=self.colors["fg"],
            fieldbackground=self.colors["input_bg"],
            rowheight=26,
            borderwidth=0,
        )
        self.style.configure(
            "Treeview.Heading",
            background=self.colors["border"],
            foreground=self.colors["fg"],
            font=("Segoe UI", 9, "bold"),
            padding=5,
        )
        self.style.map("Treeview", background=[("selected", self.colors["accent"])], foreground=[("selected", "#11111b")])

        # Progressbar
        self.style.configure(
            "TProgressbar",
            thickness=6,
            troughcolor=self.colors["input_bg"],
            background=self.colors["accent"],
            borderwidth=0,
        )

    def _build_ui(self):
        # Header banner
        header_frame = ttk.Frame(self, padding=(20, 15, 20, 10))
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="🔒 Hash Generator & Verifier", style="Header.TLabel").pack(side="left")
        ttk.Label(header_frame, text="v1.2 (VirusTotal)", style="Muted.TLabel").pack(side="left", padx=10, pady=(6, 0))

        # Main Tab Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Build tabs
        self._build_file_tab()
        self._build_text_tab()
        self._build_dir_tab()
        self._build_vt_tab()

        # Status Bar
        self.status_bar = tk.Label(
            self,
            text="Ready",
            bd=0,
            relief="flat",
            anchor="w",
            bg=self.colors["card"],
            fg=self.colors["subtext"],
            font=("Segoe UI", 9),
            padx=15,
            pady=6,
        )
        self.status_bar.pack(fill="x", side="bottom")

    def _reset_verify_badge(self):
        if hasattr(self, "verify_badge"):
            self.verify_badge.config(
                text="STATUS: PENDING VERIFICATION",
                bg=self.colors["border"],
                fg=self.colors["subtext"],
            )

    # -------------------------------------------------------------------
    # TAB 1: FILE HASHER & VERIFIER
    # -------------------------------------------------------------------
    def _build_file_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text=" File Hasher & Verifier ")

        # File Selection Card
        file_card = ttk.Frame(tab, style="Card.TFrame", padding=15)
        file_card.pack(fill="x", pady=(0, 15))

        ttk.Label(file_card, text="Select File", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        file_input_frame = ttk.Frame(file_card, style="Card.TFrame")
        file_input_frame.pack(fill="x")

        self.file_path_var = tk.StringVar()
        self.file_path_var.trace_add("write", lambda *args: self._reset_verify_badge())
        file_entry = ttk.Entry(file_input_frame, textvariable=self.file_path_var, font=("Segoe UI", 10))
        file_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(file_input_frame, text="Browse...", style="Action.TButton", command=self._browse_file).pack(side="right")

        # Algorithm & Actions Card
        algo_card = ttk.Frame(tab, style="Card.TFrame", padding=15)
        algo_card.pack(fill="x", pady=(0, 15))

        ctrl_frame = ttk.Frame(algo_card, style="Card.TFrame")
        ctrl_frame.pack(fill="x")

        ttk.Label(ctrl_frame, text="Algorithm:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.file_algo_var = tk.StringVar(value="sha256")
        self.file_algo_var.trace_add("write", lambda *args: self._reset_verify_badge())
        algo_cb = ttk.Combobox(ctrl_frame, textvariable=self.file_algo_var, values=SUPPORTED_ALGOS, state="readonly", width=12)
        algo_cb.pack(side="left", padx=(0, 15))

        ttk.Button(ctrl_frame, text="⚡ Compute Hash", style="Accent.TButton", command=self._start_compute_file_hash).pack(side="left", padx=(0, 10))
        ttk.Button(ctrl_frame, text="💾 Save Checksum File", style="Action.TButton", command=self._save_file_checksum).pack(side="left", padx=(0, 10))
        ttk.Button(ctrl_frame, text="🦠 VirusTotal Scan", style="Action.TButton", command=self._quick_scan_vt_from_file_tab).pack(side="left")

        # Hash Output Box
        ttk.Label(algo_card, text="Calculated Hash:", style="Card.TLabel").pack(anchor="w", pady=(12, 4))
        out_frame = ttk.Frame(algo_card, style="Card.TFrame")
        out_frame.pack(fill="x")

        self.file_hash_out_var = tk.StringVar()
        out_entry = ttk.Entry(out_frame, textvariable=self.file_hash_out_var, font=("Consolas", 10), state="readonly")
        out_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(out_frame, text="📋 Copy", style="Action.TButton", command=lambda: self._copy_to_clipboard(self.file_hash_out_var.get())).pack(side="right")

        # Progress bar for file hash
        self.file_progress = ttk.Progressbar(algo_card, mode="indeterminate", style="TProgressbar")

        # Verification Card
        verify_card = ttk.Frame(tab, style="Card.TFrame", padding=15)
        verify_card.pack(fill="x", expand=False)

        ttk.Label(verify_card, text="Verify Integrity", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        v_input_frame = ttk.Frame(verify_card, style="Card.TFrame")
        v_input_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(v_input_frame, text="Expected Hash:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.expected_hash_var = tk.StringVar()
        self.expected_hash_var.trace_add("write", lambda *args: self._reset_verify_badge())
        exp_entry = ttk.Entry(v_input_frame, textvariable=self.expected_hash_var, font=("Consolas", 10))
        exp_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(v_input_frame, text="📂 Load .sha256 / .md5", style="Action.TButton", command=self._load_checksum_file).pack(side="right")

        v_btn_frame = ttk.Frame(verify_card, style="Card.TFrame")
        v_btn_frame.pack(fill="x")

        ttk.Button(v_btn_frame, text="🔍 Verify Hash Match", style="Accent.TButton", command=self._verify_file_hash).pack(side="left", padx=(0, 15))

        # Status badge frame
        self.verify_badge = tk.Label(
            v_btn_frame,
            text="STATUS: PENDING VERIFICATION",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["border"],
            fg=self.colors["subtext"],
            padx=12,
            pady=4,
        )
        self.verify_badge.pack(side="left")

    def _browse_file(self):
        filename = filedialog.askopenfilename(title="Select File to Hash")
        if filename:
            self.file_path_var.set(filename)
            self._set_status(f"Selected file: {os.path.basename(filename)}")

    def _start_compute_file_hash(self):
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("Input Required", "Please select a file first.")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", f"File not found: {file_path}")
            return

        algo = self.file_algo_var.get()
        self.file_progress.pack(fill="x", pady=(10, 0))
        self.file_progress.start(10)
        self._set_status(f"Computing {algo.upper()} for {os.path.basename(file_path)}...")

        def thread_target():
            start_time = time.time()
            try:
                digest = compute_hash(file_path, algo)
                elapsed = time.time() - start_time
                self.after(0, lambda: self._on_file_hash_success(digest, elapsed, algo))
            except Exception as e:
                self.after(0, lambda: self._on_file_hash_error(str(e)))

        threading.Thread(target=thread_target, daemon=True).start()

    def _on_file_hash_success(self, digest, elapsed, algo):
        self.file_progress.stop()
        self.file_progress.pack_forget()
        self.file_hash_out_var.set(digest)
        self._set_status(f"Computed {algo.upper()} in {elapsed:.3f}s")

        # Auto-trigger verify check if expected hash field has text
        if self.expected_hash_var.get().strip():
            self._verify_file_hash()

    def _on_file_hash_error(self, err_msg):
        self.file_progress.stop()
        self.file_progress.pack_forget()
        messagebox.showerror("Calculation Error", err_msg)
        self._set_status("Error during hash computation.")

    def _save_file_checksum(self):
        file_path = self.file_path_var.get().strip()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showwarning("Input Required", "Please select a valid file first.")
            return

        algo = self.file_algo_var.get()
        try:
            checksum_path = generate_hash_file(file_path, algo)
            messagebox.showinfo("Saved", f"Checksum file created:\n{checksum_path}")
            self._set_status(f"Saved checksum to {os.path.basename(checksum_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save checksum file: {e}")

    def _load_checksum_file(self):
        hash_file = filedialog.askopenfilename(
            title="Select Checksum File",
            filetypes=[("Checksum Files", "*.sha256 *.md5 *.sha512 *.sha1 *.txt"), ("All Files", "*.*")],
        )
        if not hash_file:
            return

        try:
            with open(hash_file, "r", encoding="utf-8") as f:
                content = f.readline().strip()
                if content:
                    expected = content.split()[0]
                    if not is_valid_hash(expected):
                        messagebox.showerror(
                            "Invalid Checksum File",
                            f"The selected file '{os.path.basename(hash_file)}' does not contain a valid cryptographic hash digest.",
                        )
                        return
                    self.expected_hash_var.set(expected)
                    self._set_status(f"Loaded expected hash from {os.path.basename(hash_file)}")
                else:
                    messagebox.showerror("Error", "Selected file is empty.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read checksum file: {e}")

    def _verify_file_hash(self):
        computed = self.file_hash_out_var.get().strip().lower()
        expected = self.expected_hash_var.get().strip().lower()
        algo = self.file_algo_var.get()

        if not expected:
            messagebox.showwarning("Input Required", "Please enter or load an expected hash string.")
            return

        if not is_valid_hash(expected, algo):
            messagebox.showerror("Invalid Hash Digest", f"'{expected}' is not a valid {algo.upper()} hex digest.")
            return

        if not computed:
            # If no computed hash yet, compute first
            self._start_compute_file_hash()
            return

        if computed == expected:
            self.verify_badge.config(
                text="✓ MATCH — INTEGRITY VERIFIED",
                bg=self.colors["success_bg"],
                fg=self.colors["success"],
            )
            self._set_status("File verification successful: Hashes match!")
        else:
            self.verify_badge.config(
                text="✗ MISMATCH — FILE CORRUPTED / TAMPERED",
                bg=self.colors["danger_bg"],
                fg=self.colors["danger"],
            )
            self._set_status("File verification failed: Hash mismatch detected.")

    # -------------------------------------------------------------------
    # TAB 2: TEXT STRING HASHER
    # -------------------------------------------------------------------
    def _build_text_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text=" Text Hasher ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=15)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Input Text String", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        # Text Widget with scrollbar
        txt_frame = ttk.Frame(card, style="Card.TFrame")
        txt_frame.pack(fill="both", expand=True, pady=(0, 12))

        self.text_input = tk.Text(
            txt_frame,
            wrap="word",
            font=("Consolas", 10),
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"],
            bd=1,
            relief="solid",
            height=8,
        )
        sb = ttk.Scrollbar(txt_frame, command=self.text_input.yview)
        self.text_input.configure(yscrollcommand=sb.set)

        self.text_input.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Controls & Algo
        ctrl = ttk.Frame(card, style="Card.TFrame")
        ctrl.pack(fill="x", pady=(0, 12))

        ttk.Label(ctrl, text="Algorithm:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.text_algo_var = tk.StringVar(value="sha256")
        ttk.Combobox(ctrl, textvariable=self.text_algo_var, values=SUPPORTED_ALGOS, state="readonly", width=12).pack(side="left", padx=(0, 15))

        ttk.Button(ctrl, text="⚡ Compute Text Hash", style="Accent.TButton", command=self._compute_text_hash_action).pack(side="left")

        # Result box
        ttk.Label(card, text="Computed Text Hash:", style="Card.TLabel").pack(anchor="w", pady=(5, 4))
        res_frame = ttk.Frame(card, style="Card.TFrame")
        res_frame.pack(fill="x")

        self.text_hash_out_var = tk.StringVar()
        t_entry = ttk.Entry(res_frame, textvariable=self.text_hash_out_var, font=("Consolas", 10), state="readonly")
        t_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(res_frame, text="📋 Copy", style="Action.TButton", command=lambda: self._copy_to_clipboard(self.text_hash_out_var.get())).pack(side="right")

    def _compute_text_hash_action(self):
        text_content = self.text_input.get("1.0", "end-1c")
        algo = self.text_algo_var.get()
        try:
            digest = compute_text_hash(text_content, algo)
            self.text_hash_out_var.set(digest)
            self._set_status(f"Computed {algo.upper()} text hash ({len(text_content)} chars)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute text hash: {e}")

    # -------------------------------------------------------------------
    # TAB 3: DIRECTORY HASHER
    # -------------------------------------------------------------------
    def _build_dir_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(tab, text=" Directory Hasher ")

        # Card
        card = ttk.Frame(tab, style="Card.TFrame", padding=15)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Select Directory", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 8))

        dir_input_frame = ttk.Frame(card, style="Card.TFrame")
        dir_input_frame.pack(fill="x", pady=(0, 12))

        self.dir_path_var = tk.StringVar()
        d_entry = ttk.Entry(dir_input_frame, textvariable=self.dir_path_var, font=("Segoe UI", 10))
        d_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Button(dir_input_frame, text="Browse Folder...", style="Action.TButton", command=self._browse_directory).pack(side="right")

        # Controls
        ctrl_frame = ttk.Frame(card, style="Card.TFrame")
        ctrl_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(ctrl_frame, text="Algorithm:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.dir_algo_var = tk.StringVar(value="sha256")
        ttk.Combobox(ctrl_frame, textvariable=self.dir_algo_var, values=SUPPORTED_ALGOS, state="readonly", width=12).pack(side="left", padx=(0, 15))

        ttk.Button(ctrl_frame, text="⚡ Hash Entire Directory", style="Accent.TButton", command=self._start_hash_directory).pack(side="left", padx=(0, 10))
        ttk.Button(ctrl_frame, text="💾 Export Results...", style="Action.TButton", command=self._export_dir_hashes).pack(side="left")

        # Progress bar
        self.dir_progress = ttk.Progressbar(card, mode="indeterminate", style="TProgressbar")

        # Treeview Table
        table_frame = ttk.Frame(card, style="Card.TFrame")
        self.table_frame = table_frame
        table_frame.pack(fill="both", expand=True, pady=(10, 0))

        columns = ("relative_path", "hash_digest")
        self.dir_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.dir_tree.heading("relative_path", text="Relative File Path")
        self.dir_tree.heading("hash_digest", text="Hash Digest")
        self.dir_tree.column("relative_path", width=300, anchor="w")
        self.dir_tree.column("hash_digest", width=380, anchor="w")

        tree_sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.dir_tree.yview)
        self.dir_tree.configure(yscrollcommand=tree_sb.set)

        self.dir_tree.pack(side="left", fill="both", expand=True)
        tree_sb.pack(side="right", fill="y")

        # Double click to copy hash digest
        self.dir_tree.bind("<Double-1>", self._on_tree_double_click)
        self.dir_results_cache = {}

    def _browse_directory(self):
        dir_path = filedialog.askdirectory(title="Select Folder to Hash")
        if dir_path:
            self.dir_path_var.set(dir_path)
            self._set_status(f"Selected folder: {dir_path}")

    def _start_hash_directory(self):
        dir_path = self.dir_path_var.get().strip()
        if not dir_path or not os.path.isdir(dir_path):
            messagebox.showwarning("Input Required", "Please select a valid directory first.")
            return

        algo = self.dir_algo_var.get()
        self.dir_progress.pack(before=self.table_frame, fill="x", pady=(0, 10))
        self.dir_progress.start(10)
        self._set_status(f"Scanning & hashing directory recursively ({algo.upper()})...")

        # Clear existing table rows
        for item in self.dir_tree.get_children():
            self.dir_tree.delete(item)

        def thread_target():
            start_time = time.time()
            try:
                results = hash_directory(dir_path, algo)
                elapsed = time.time() - start_time
                self.after(0, lambda: self._on_dir_hash_success(results, elapsed, algo))
            except Exception as e:
                self.after(0, lambda: self._on_dir_hash_error(str(e)))

        threading.Thread(target=thread_target, daemon=True).start()

    def _on_dir_hash_success(self, results, elapsed, algo):
        self.dir_progress.stop()
        self.dir_progress.pack_forget()
        self.dir_results_cache = results

        for rel_path, digest in results.items():
            self.dir_tree.insert("", "end", values=(rel_path, digest))

        total_files = len(results)
        self._set_status(f"Hashed {total_files} file(s) in {elapsed:.3f}s ({algo.upper()})")

    def _on_dir_hash_error(self, err_msg):
        self.dir_progress.stop()
        self.dir_progress.pack_forget()
        messagebox.showerror("Directory Hashing Error", err_msg)
        self._set_status("Error during directory hashing.")

    def _on_tree_double_click(self, event):
        selected_item = self.dir_tree.selection()
        if selected_item:
            item_values = self.dir_tree.item(selected_item[0], "values")
            if item_values and len(item_values) > 1:
                digest = item_values[1]
                self._copy_to_clipboard(digest)

    def _export_dir_hashes(self):
        if not self.dir_results_cache:
            messagebox.showwarning("No Data", "No directory hashes computed to export.")
            return

        export_file = filedialog.asksaveasfilename(
            title="Export Directory Hashes",
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt"), ("Checksum File", "*.sha256"), ("All Files", "*.*")],
        )
        if not export_file:
            return

        try:
            algo = self.dir_algo_var.get().upper()
            with open(export_file, "w", encoding="utf-8") as f:
                f.write(f"# Directory Hash Summary - {algo}\n")
                f.write(f"# Base Directory: {self.dir_path_var.get()}\n\n")
                for rel_path, digest in self.dir_results_cache.items():
                    f.write(f"{digest}  {rel_path}\n")

            messagebox.showinfo("Export Successful", f"Exported hashes to:\n{export_file}")
            self._set_status(f"Exported {len(self.dir_results_cache)} file hashes")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write file: {e}")

    # -------------------------------------------------------------------
    # TAB 4: VIRUSTOTAL ANALYZER
    # -------------------------------------------------------------------
    def _build_vt_tab(self):
        tab = ttk.Frame(self.notebook, padding=15)
        self.vt_tab_index = 3
        self.notebook.add(tab, text=" 🦠 VirusTotal Analyzer ")

        # API Key Card
        key_card = ttk.Frame(tab, style="Card.TFrame", padding=12)
        key_card.pack(fill="x", pady=(0, 10))

        ttk.Label(key_card, text="VirusTotal API v3 Configuration", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 6))

        k_frame = ttk.Frame(key_card, style="Card.TFrame")
        k_frame.pack(fill="x")

        ttk.Label(k_frame, text="API Key:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.vt_api_key_var = tk.StringVar(value=os.environ.get("VIRUSTOTAL_API_KEY", ""))
        self.vt_key_entry = ttk.Entry(k_frame, textvariable=self.vt_api_key_var, show="*", font=("Consolas", 10))
        self.vt_key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.vt_show_key_var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(
            k_frame,
            text="Show Key",
            variable=self.vt_show_key_var,
            command=self._toggle_vt_key_visibility,
        )
        cb.pack(side="right")

        env_status = "Found VIRUSTOTAL_API_KEY env var" if os.environ.get("VIRUSTOTAL_API_KEY") else "Optional: Set key above or via VIRUSTOTAL_API_KEY env var"
        ttk.Label(key_card, text=f"ℹ {env_status}", style="Muted.TLabel").pack(anchor="w", pady=(4, 0))

        # Target Selection Card
        input_card = ttk.Frame(tab, style="Card.TFrame", padding=12)
        input_card.pack(fill="x", pady=(0, 10))

        ttk.Label(input_card, text="Target File Path or Hash Digest", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 6))

        in_frame = ttk.Frame(input_card, style="Card.TFrame")
        in_frame.pack(fill="x", pady=(0, 8))

        self.vt_target_var = tk.StringVar()
        target_entry = ttk.Entry(in_frame, textvariable=self.vt_target_var, font=("Consolas", 10))
        target_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(in_frame, text="Browse File...", style="Action.TButton", command=self._browse_vt_target_file).pack(side="right")

        opts_frame = ttk.Frame(input_card, style="Card.TFrame")
        opts_frame.pack(fill="x")

        self.vt_upload_missing_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts_frame,
            text="Upload file to VirusTotal if not found in database",
            variable=self.vt_upload_missing_var,
        ).pack(side="left")

        ttk.Button(opts_frame, text="🔍 Analyze with VirusTotal", style="Accent.TButton", command=self._start_vt_analysis).pack(side="right")

        # Progress bar
        self.vt_progress = ttk.Progressbar(input_card, mode="indeterminate", style="TProgressbar")

        # Results Card
        res_card = ttk.Frame(tab, style="Card.TFrame", padding=12)
        self.vt_res_card = res_card
        res_card.pack(fill="both", expand=True)

        header_res_frame = ttk.Frame(res_card, style="Card.TFrame")
        header_res_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(header_res_frame, text="Analysis Results", style="SubHeader.TLabel").pack(side="left")

        self.vt_status_badge = tk.Label(
            header_res_frame,
            text="STATUS: READY",
            font=("Segoe UI", 9, "bold"),
            bg=self.colors["border"],
            fg=self.colors["subtext"],
            padx=10,
            pady=3,
        )
        self.vt_status_badge.pack(side="left", padx=15)

        self.vt_open_link_btn = ttk.Button(
            header_res_frame,
            text="🔗 Open VirusTotal Page",
            style="Action.TButton",
            command=self._open_vt_permalink,
            state="disabled",
        )
        self.vt_open_link_btn.pack(side="right")
        self.vt_current_permalink = ""

        # Metadata labels grid
        meta_frame = ttk.Frame(res_card, style="Card.TFrame")
        meta_frame.pack(fill="x", pady=(0, 8))

        self.vt_meta_name_var = tk.StringVar(value="File Name: -")
        self.vt_meta_size_var = tk.StringVar(value="Size: -")
        self.vt_meta_type_var = tk.StringVar(value="Type: -")
        self.vt_meta_date_var = tk.StringVar(value="Scan Date: -")
        self.vt_meta_threat_var = tk.StringVar(value="Threat Label: -")
        self.vt_meta_rep_var = tk.StringVar(value="Reputation: -")

        m1 = ttk.Frame(meta_frame, style="Card.TFrame")
        m1.pack(fill="x")
        ttk.Label(m1, textvariable=self.vt_meta_name_var, style="Card.TLabel").pack(side="left", padx=(0, 20))
        ttk.Label(m1, textvariable=self.vt_meta_size_var, style="Card.TLabel").pack(side="left", padx=(0, 20))
        ttk.Label(m1, textvariable=self.vt_meta_type_var, style="Card.TLabel").pack(side="left")

        m2 = ttk.Frame(meta_frame, style="Card.TFrame")
        m2.pack(fill="x", pady=(4, 0))
        ttk.Label(m2, textvariable=self.vt_meta_date_var, style="Card.TLabel").pack(side="left", padx=(0, 20))
        ttk.Label(m2, textvariable=self.vt_meta_threat_var, style="Card.TLabel").pack(side="left", padx=(0, 20))
        ttk.Label(m2, textvariable=self.vt_meta_rep_var, style="Card.TLabel").pack(side="left")

        # Table for Detections
        ttk.Label(res_card, text="Vendor Detections:", style="Card.TLabel").pack(anchor="w", pady=(8, 4))

        vt_table_frame = ttk.Frame(res_card, style="Card.TFrame")
        vt_table_frame.pack(fill="both", expand=True)

        columns = ("engine_name", "category", "result")
        self.vt_tree = ttk.Treeview(vt_table_frame, columns=columns, show="headings", selectmode="browse")
        self.vt_tree.heading("engine_name", text="Security Vendor / Engine")
        self.vt_tree.heading("category", text="Category")
        self.vt_tree.heading("result", text="Detection Result")
        self.vt_tree.column("engine_name", width=220, anchor="w")
        self.vt_tree.column("category", width=140, anchor="w")
        self.vt_tree.column("result", width=320, anchor="w")

        vt_sb = ttk.Scrollbar(vt_table_frame, orient="vertical", command=self.vt_tree.yview)
        self.vt_tree.configure(yscrollcommand=vt_sb.set)

        self.vt_tree.pack(side="left", fill="both", expand=True)
        vt_sb.pack(side="right", fill="y")

    def _toggle_vt_key_visibility(self):
        show_char = "" if self.vt_show_key_var.get() else "*"
        self.vt_key_entry.config(show=show_char)

    def _browse_vt_target_file(self):
        filename = filedialog.askopenfilename(title="Select File to Analyze with VirusTotal")
        if filename:
            self.vt_target_var.set(filename)
            self._set_status(f"Selected VirusTotal target file: {os.path.basename(filename)}")

    def _quick_scan_vt_from_file_tab(self):
        file_path = self.file_path_var.get().strip()
        computed_hash = self.file_hash_out_var.get().strip()

        if file_path:
            self.vt_target_var.set(file_path)
        elif computed_hash:
            self.vt_target_var.set(computed_hash)
        else:
            messagebox.showwarning("Input Required", "Please select a file or compute a hash first.")
            return

        self.notebook.select(self.vt_tab_index)
        self._start_vt_analysis()

    def _open_vt_permalink(self):
        if self.vt_current_permalink:
            webbrowser.open(self.vt_current_permalink)

    def _start_vt_analysis(self):
        target = self.vt_target_var.get().strip()
        api_key = self.vt_api_key_var.get().strip()
        upload_missing = self.vt_upload_missing_var.get()

        if not target:
            messagebox.showwarning("Input Required", "Please enter a hash string or select a file path.")
            return

        if not api_key:
            messagebox.showwarning(
                "API Key Required",
                "Please enter a VirusTotal API key or set the VIRUSTOTAL_API_KEY environment variable.",
            )
            return

        self.vt_progress.pack(fill="x", pady=(8, 0))
        self.vt_progress.start(10)
        self.vt_status_badge.config(
            text="STATUS: SCANNING...", bg=self.colors["border"], fg=self.colors["subtext"]
        )
        self.vt_open_link_btn.config(state="disabled")
        self._set_status("Querying VirusTotal API...")

        # Clear existing table rows
        for item in self.vt_tree.get_children():
            self.vt_tree.delete(item)

        def thread_target():
            start_time = time.time()
            try:
                report = vt_client.analyze_file_or_hash(
                    target, api_key=api_key, upload_if_missing=upload_missing
                )
                elapsed = time.time() - start_time
                self.after(0, lambda: self._on_vt_success(report, elapsed))
            except Exception as e:
                self.after(0, lambda: self._on_vt_error(str(e)))

        threading.Thread(target=thread_target, daemon=True).start()

    def _on_vt_success(self, report: dict, elapsed: float):
        self.vt_progress.stop()
        self.vt_progress.pack_forget()

        if not report.get("success"):
            err_msg = report.get("error", "Unknown VirusTotal error.")
            self.vt_status_badge.config(
                text="STATUS: ERROR", bg=self.colors["danger_bg"], fg=self.colors["danger"]
            )
            messagebox.showerror("VirusTotal API Error", err_msg)
            self._set_status(f"VirusTotal error: {err_msg}")
            return

        if not report.get("found"):
            self.vt_status_badge.config(
                text="STATUS: NOT FOUND IN DB", bg=self.colors["border"], fg=self.colors["subtext"]
            )
            self.vt_meta_name_var.set("File Name: N/A")
            self.vt_meta_size_var.set("Size: N/A")
            self.vt_meta_type_var.set("Type: N/A")
            self.vt_meta_date_var.set("Scan Date: N/A")
            self.vt_meta_threat_var.set("Threat Label: N/A")
            self.vt_meta_rep_var.set("Reputation: N/A")

            permalink = report.get("permalink", "")
            if permalink:
                self.vt_current_permalink = permalink
                self.vt_open_link_btn.config(state="normal")

            msg = "Hash not found in VirusTotal database."
            if report.get("upload_attempted"):
                up_res = report.get("upload_result", {})
                if up_res.get("success"):
                    msg += f"\nFile uploaded for analysis! Analysis ID: {up_res.get('analysis_id')}"
                else:
                    msg += f"\nUpload failed: {up_res.get('error')}"

            messagebox.showinfo("VirusTotal Result", msg)
            self._set_status(f"VirusTotal lookup completed in {elapsed:.3f}s (Not Found)")
            return

        stats = report.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            self.vt_status_badge.config(
                text=f" ⚠️ MALICIOUS ({malicious}/{total}) ",
                bg=self.colors["danger_bg"],
                fg=self.colors["danger"],
            )
        elif suspicious > 0:
            self.vt_status_badge.config(
                text=f" ⚡ SUSPICIOUS ({suspicious}/{total}) ",
                bg="#3a2f18",
                fg="#f9e2af",
            )
        else:
            self.vt_status_badge.config(
                text=f" ✓ CLEAN (0/{total}) ",
                bg=self.colors["success_bg"],
                fg=self.colors["success"],
            )

        self.vt_meta_name_var.set(f"File Name: {report.get('meaningful_name')}")
        self.vt_meta_size_var.set(f"Size: {report.get('size')} bytes")
        self.vt_meta_type_var.set(f"Type: {report.get('type_description')}")
        self.vt_meta_date_var.set(f"Scan Date: {report.get('scan_date')}")
        self.vt_meta_threat_var.set(f"Threat Label: {report.get('threat_label')}")
        self.vt_meta_rep_var.set(f"Reputation: {report.get('reputation')}")

        permalink = report.get("permalink", "")
        if permalink:
            self.vt_current_permalink = permalink
            self.vt_open_link_btn.config(state="normal")

        # Populate Detections Table
        detections = report.get("detections", {})
        all_results = report.get("all_results", {})

        display_results = detections if detections else all_results

        for eng, info in display_results.items():
            cat = info.get("category", "")
            res = info.get("result") or "Clean"
            self.vt_tree.insert("", "end", values=(eng, cat, res))

        self._set_status(f"VirusTotal report loaded in {elapsed:.3f}s ({malicious} malicious detections)")

    def _on_vt_error(self, err_msg: str):
        self.vt_progress.stop()
        self.vt_progress.pack_forget()
        self.vt_status_badge.config(
            text="STATUS: ERROR", bg=self.colors["danger_bg"], fg=self.colors["danger"]
        )
        messagebox.showerror("VirusTotal Error", f"An unexpected error occurred:\n{err_msg}")
        self._set_status("Error during VirusTotal analysis.")

    # -------------------------------------------------------------------
    # UTILITIES
    # -------------------------------------------------------------------
    def _copy_to_clipboard(self, text):
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Copied hash to clipboard!")

    def _set_status(self, msg):
        self.status_bar.config(text=f"  {msg}")


def main():
    app = HashToolGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
