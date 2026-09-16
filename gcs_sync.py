import os
import sys

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog
except ImportError:
    tk = None
    ttk = None
    filedialog = None
    messagebox = None
    simpledialog = None

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import pathlib
import datetime
import time
import base64
import hmac
import hashlib
from typing import Dict, Optional, Any

# --- DURATION AND SPEED FORMATTING HELPERS ---
def format_time_duration(seconds: float) -> str:
    """Format duration in seconds into MM:SS or HH:MM:SS."""
    if seconds is None or seconds < 0 or seconds == float('inf'):
        return "--:--"
    total_seconds = int(seconds)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"

def format_transfer_speed(bytes_per_sec: float) -> str:
    """Format bytes per second into B/s, KB/s, or MB/s."""
    if bytes_per_sec is None or bytes_per_sec <= 0:
        return "0.0 B/s"
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.1f} B/s"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    else:
        return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"

# --- DEPENDENCY IMPORTS ---
try:
    from google.cloud import storage
    from google.oauth2 import service_account
except ImportError:
    storage = None
    service_account = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    import secrets
except ImportError:
    Cipher = None
    algorithms = None
    modes = None
    default_backend = None
    padding = None
    import secrets

class SyncPausedException(Exception):
    """Raised when the user pauses sync, immediately aborting the active file transfer."""
    pass


class SyncCancelledException(Exception):
    """Raised when the user cancels the entire sync operation."""
    pass


class EncryptedStreamAdapter:
    """
    A file-like object that encrypts data on the fly.
    Fixes the 'Content-Range' size mismatch error by reporting correct tell() offset.
    Appends a 16-byte random IV/nonce at the beginning of the stream.
    Supports on_progress(bytes_count) callback for live upload speed tracking
    and check_interrupted() callback to immediately abort in-flight transfer when paused.
    """
    def __init__(self, source_file, key: bytes, on_progress=None, check_interrupted=None):
        if Cipher is None:
            raise RuntimeError("The 'cryptography' library is required for EncryptedStreamAdapter.")
        self.source_file = source_file
        self.key = key
        self.on_progress = on_progress
        self.check_interrupted = check_interrupted
        # Generate 16-byte IV (Nonce) for AES-CTR
        self.nonce = secrets.token_bytes(16)
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(self.nonce), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self._nonce_sent = False

    def read(self, size=-1):
        if self.check_interrupted:
            self.check_interrupted()

        # If this is the very first read, prepare to send the Nonce
        chunk = b""
        if not self._nonce_sent:
            self._nonce_sent = True
            chunk = self.nonce
            # If the caller requested a specific size, subtract the 16 bytes
            # we just "generated" so we don't return more than requested.
            if size != -1:
                size -= 16

        # If size became 0 (or negative) after subtracting nonce, just return the nonce for now
        if size == 0:
            if self.on_progress and chunk:
                self.on_progress(len(chunk))
            return chunk

        # Read from the actual file
        # We read 'size' bytes (or all if -1)
        data = self.source_file.read(size)

        # If file is empty (EOF), just return whatever chunk we have (nonce or empty)
        if not data:
            if self.on_progress and chunk:
                self.on_progress(len(chunk))
            return chunk

        # Encrypt and append to our chunk (nonce + encrypted_data)
        encrypted_data = self.encryptor.update(data)
        full_chunk = chunk + encrypted_data
        if self.on_progress and full_chunk:
            self.on_progress(len(full_chunk))
        return full_chunk

    def tell(self):
        # CRITICAL FIX: Report the position of the *encrypted* stream (File + 16)
        # The GCS library uses this to verify upload integrity.
        offset = 16 if self._nonce_sent else 0
        return self.source_file.tell() + offset


class ProgressStreamAdapter:
    """
    A file-like wrapper around a standard stream that triggers on_progress(bytes_count)
    callback on every read for real-time transfer speed monitoring, and check_interrupted()
    to immediately cancel in-flight transfer on pause.
    """
    def __init__(self, source_file, on_progress=None, check_interrupted=None):
        self.source_file = source_file
        self.on_progress = on_progress
        self.check_interrupted = check_interrupted

    def read(self, size=-1):
        if self.check_interrupted:
            self.check_interrupted()
        data = self.source_file.read(size)
        if data and self.on_progress:
            self.on_progress(len(data))
        return data

    def tell(self):
        return self.source_file.tell()


class CloudStorageSync:
    """
    Desktop synchronization tool between a local directory and Google Cloud Storage (GCS).
    Features:
    - On-the-fly streaming AES-256 CTR encryption
    - Persistent cloud file tree caching with instant scan loading
    - Manual cache refresh trigger
    - Security warning modal when uploading without encryption
    """
    def __init__(self, master):
        self.master = master
        master.title("Google Cloud Storage Sync (Streaming AES-256 Encryption)")
        master.geometry("1000x880")
        master.minsize(850, 650)

        # Application state
        self.local_dir = ""
        self.bucket_name = ""
        self.credentials_path = ""
        self.gcs_client = None
        self.bucket = None
        self.local_files = {}
        self.cloud_files = {}
        self.is_scanning = False
        self.excluded_patterns = []
        self.sync_mode = "two_way"

        # Encryption State
        self.encryption_key: Optional[bytes] = None  # Raw 32 bytes for AES-256

        # Sync Execution & Pause/Resume/Cancel Control State
        self.is_syncing = False
        self.is_paused = False
        self.is_cancelled = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.current_syncing_file: Optional[str] = None
        self.max_workers: int = 4
        self.active_workers_count: int = 0

        # Caching State
        self.cloud_cache_timestamp: Optional[str] = None
        self.config_file = "config.json"

        # History Lists for Previous Directories, Credentials, and Buckets
        self.history_local_dirs: list[str] = []
        self.history_credentials_paths: list[str] = []
        self.history_bucket_names: list[str] = []

        # Sorting and Filtering State across all columns
        self.sort_column = "#0"
        self.sort_descending = False
        self.filter_status_var = tk.StringVar(value="All Statuses")
        self.filter_encryption_var = tk.StringVar(value="All Encryption")
        self.filter_search_var = tk.StringVar(value="")
        self.view_mode_var = tk.StringVar(value="Tree View")
        self._item_to_path = {}
        self._item_to_raw_size = {}
        self.tree_headings = {
            "#0": "File Path",
            "status": "Status",
            "size": "Size",
            "last_modified": "Last Modified",
            "encrypted": "Encrypted?",
            "cloud_name": "Cloud Name (Encrypted Blob)"
        }

        self.create_ui()
        self.load_config()

    def get_cache_filename(self) -> str:
        """Generate a safe, bucket-specific cache filename."""
        clean_bucket = "".join(c for c in self.bucket_name if c.isalnum() or c in ("-", "_")).strip()
        if not clean_bucket:
            clean_bucket = "default"
        return f".gcs_cache_{clean_bucket}.json"

    def create_ui(self):
        # Apply modern ttk theme and colors
        style = ttk.Style()
        try:
            if "clam" in style.theme_names():
                style.theme_use("clam")
        except Exception:
            pass

        # Configure modern fonts, paddings, and styles
        style.configure("Treeview", font=("TkDefaultFont", 9), rowheight=24)
        style.configure("Treeview.Heading", font=("TkDefaultFont", 9, "bold"), padding=4)
        style.configure("TLabelframe.Label", font=("TkDefaultFont", 9, "bold"))

        main_frame = ttk.Frame(self.master, padding="12")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Configuration Container (Can be hidden/collapsed to enlarge files view) ---
        self.config_hidden = False
        self.config_container = ttk.Frame(main_frame)
        self.config_container.pack(fill=tk.X, pady=2)

        # Compact Summary Bar (Displayed when configuration is collapsed)
        self.compact_config_bar = ttk.Frame(main_frame, padding="4")
        self.compact_summary_var = tk.StringVar(value="")
        self.compact_summary_label = ttk.Label(
            self.compact_config_bar, 
            textvariable=self.compact_summary_var, 
            font=("TkDefaultFont", 9, "bold"), 
            foreground="#0284c7"
        )
        self.compact_summary_label.pack(side=tk.LEFT, padx=6)
        ttk.Button(
            self.compact_config_bar, 
            text="⚙️ Show Settings", 
            command=self.toggle_config_visibility
        ).pack(side=tk.RIGHT, padx=4)

        # --- Configuration ---
        config_frame = ttk.LabelFrame(self.config_container, text="Configuration & Path History", padding="10")
        config_frame.pack(fill=tk.X, pady=4)

        # Local Dir (Editable Combobox with Dropdown History)
        ttk.Label(config_frame, text="Local Directory:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=4)
        self.local_dir_var = tk.StringVar()
        self.local_dir_combo = ttk.Combobox(config_frame, textvariable=self.local_dir_var, width=52)
        self.local_dir_combo.grid(column=1, row=0, sticky=tk.W, padx=5, pady=4)
        self.local_dir_combo.bind("<<ComboboxSelected>>", self.on_local_dir_selected)
        ttk.Button(config_frame, text="Browse...", command=self.browse_directory).grid(column=2, row=0, padx=5, pady=4)

        # Credentials (Editable Combobox with Dropdown History)
        ttk.Label(config_frame, text="GCS Credentials:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=4)
        self.credentials_var = tk.StringVar()
        self.credentials_combo = ttk.Combobox(config_frame, textvariable=self.credentials_var, width=52)
        self.credentials_combo.grid(column=1, row=1, sticky=tk.W, padx=5, pady=4)
        self.credentials_combo.bind("<<ComboboxSelected>>", self.on_credentials_selected)
        ttk.Button(config_frame, text="Browse...", command=self.browse_credentials).grid(column=2, row=1, padx=5, pady=4)

        # Bucket (Editable Combobox with Dropdown History)
        ttk.Label(config_frame, text="Bucket Name:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=4)
        self.bucket_var = tk.StringVar()
        self.bucket_combo = ttk.Combobox(config_frame, textvariable=self.bucket_var, width=52)
        self.bucket_combo.grid(column=1, row=2, sticky=tk.W, padx=5, pady=4)
        self.bucket_combo.bind("<<ComboboxSelected>>", self.on_bucket_selected)
        ttk.Button(config_frame, text="Connect", command=self.connect_to_gcs).grid(column=2, row=2, padx=5, pady=4)

        # Sync Mode & Parallel Workers
        ttk.Label(config_frame, text="Sync Mode:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=4)
        sync_mode_frame = ttk.Frame(config_frame)
        sync_mode_frame.grid(column=1, row=3, columnspan=2, sticky=tk.W, padx=5, pady=4)
        self.sync_mode_var = tk.StringVar(value="two_way")
        ttk.Radiobutton(sync_mode_frame, text="Two-way Sync", variable=self.sync_mode_var, value="two_way").pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(sync_mode_frame, text="Local to Cloud Only", variable=self.sync_mode_var, value="local_to_cloud").pack(side=tk.LEFT, padx=(0, 20))

        ttk.Label(sync_mode_frame, text="⚡ Parallel Transfers:").pack(side=tk.LEFT, padx=(10, 4))
        self.workers_var = tk.IntVar(value=4)
        self.workers_spinbox = ttk.Spinbox(sync_mode_frame, from_=1, to=16, width=4, textvariable=self.workers_var, command=self.on_workers_changed)
        self.workers_spinbox.pack(side=tk.LEFT, padx=(0, 4))
        self.workers_spinbox.bind("<KeyRelease>", lambda e: self.on_workers_changed())
        ttk.Label(sync_mode_frame, text="threads (1-16)", foreground="#64748b").pack(side=tk.LEFT)

        # --- Encryption Section ---
        enc_frame = ttk.LabelFrame(self.config_container, text="Encryption Management (AES-256 CTR Streaming)", padding="10")
        enc_frame.pack(fill=tk.X, pady=4)

        ttk.Label(enc_frame, text="Current Key Status:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=4)
        self.key_status_var = tk.StringVar(value="⚠️ No Key Loaded - Files will be uploaded unencrypted!")
        self.key_status_label = ttk.Label(enc_frame, textvariable=self.key_status_var, foreground="#dc2626", font=("TkDefaultFont", 9, "bold"))
        self.key_status_label.grid(column=1, row=0, columnspan=2, sticky=tk.W, padx=5, pady=4)

        btn_frame = ttk.Frame(enc_frame)
        btn_frame.grid(column=1, row=1, sticky=tk.W, padx=5, pady=4)

        ttk.Button(btn_frame, text="Generate New Key", command=self.generate_key).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Load Key from File", command=self.load_key_from_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Save Current Key", command=self.save_key_to_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Unload Key", command=self.unload_key).pack(side=tk.LEFT, padx=4)

        # --- Cloud Cache Status & Control Bar ---
        cache_frame = ttk.LabelFrame(self.config_container, text="Cloud File Tree Cache", padding="8")
        cache_frame.pack(fill=tk.X, pady=4)

        self.cache_status_var = tk.StringVar(value="Cloud Cache: No local cache stored yet")
        self.cache_label = ttk.Label(cache_frame, textvariable=self.cache_status_var, font=("TkDefaultFont", 9))
        self.cache_label.pack(side=tk.LEFT, padx=6, pady=2)

        cache_btn_frame = ttk.Frame(cache_frame)
        cache_btn_frame.pack(side=tk.RIGHT, padx=6)

        self.check_leaks_btn = ttk.Button(cache_btn_frame, text="🛡️ Check for Leaks", command=self.check_cloud_leaks)
        self.check_leaks_btn.pack(side=tk.LEFT, padx=4)
        self.refresh_cache_btn = ttk.Button(cache_btn_frame, text="🔄 Refresh Cloud Cache", command=self.refresh_cloud_cache)
        self.refresh_cache_btn.pack(side=tk.LEFT, padx=4)
        self.clear_cache_btn = ttk.Button(cache_btn_frame, text="Clear Cache", command=self.clear_cloud_cache)
        self.clear_cache_btn.pack(side=tk.LEFT, padx=4)

        # --- Exclusions ---
        exclusion_frame = ttk.LabelFrame(self.config_container, text="Excluded Folders & Patterns", padding="8")
        exclusion_frame.pack(fill=tk.X, pady=4)

        self.exclusion_listbox = tk.Listbox(exclusion_frame, height=3)
        self.exclusion_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=3)

        exclusion_scrollbar = ttk.Scrollbar(exclusion_frame, orient="vertical", command=self.exclusion_listbox.yview)
        self.exclusion_listbox.configure(yscrollcommand=exclusion_scrollbar.set)
        exclusion_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=3)

        exclusion_buttons_frame = ttk.Frame(exclusion_frame)
        exclusion_buttons_frame.pack(fill=tk.X, pady=3)
        ttk.Button(exclusion_buttons_frame, text="Add Exclusion", command=self.add_exclusion).pack(side=tk.LEFT, padx=4)
        ttk.Button(exclusion_buttons_frame, text="Remove Selected", command=self.remove_exclusion).pack(side=tk.LEFT, padx=4)
        ttk.Button(exclusion_buttons_frame, text="Save Exclusions", command=self.save_exclusions).pack(side=tk.LEFT, padx=4)
        ttk.Button(exclusion_buttons_frame, text="Load Exclusions", command=self.load_exclusions).pack(side=tk.LEFT, padx=4)

        # --- File List Treeview with Sort & Filter Toolbar ---
        self.files_frame = ttk.LabelFrame(main_frame, text="Files & Search Filters", padding="8")
        self.files_frame.pack(fill=tk.BOTH, expand=True, pady=4)

        # Filter & Search Toolbar
        filter_toolbar = ttk.Frame(self.files_frame)
        filter_toolbar.pack(fill=tk.X, pady=(0, 6))

        # Search Query
        ttk.Label(filter_toolbar, text="Search:").pack(side=tk.LEFT, padx=(0, 3))
        self.search_entry = ttk.Entry(filter_toolbar, textvariable=self.filter_search_var, width=16)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self.update_file_list())

        # Status Filter Combobox (including "Files in Cloud" / "Cloud only")
        ttk.Label(filter_toolbar, text="Status:").pack(side=tk.LEFT, padx=(0, 3))
        self.status_filter_combo = ttk.Combobox(
            filter_toolbar,
            textvariable=self.filter_status_var,
            values=["All Statuses", "Files in Cloud", "Cloud only", "Local only", "Synced", "Modified"],
            state="readonly",
            width=13
        )
        self.status_filter_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.status_filter_combo.bind("<<ComboboxSelected>>", lambda e: self.update_file_list())

        # Encryption Filter Combobox
        ttk.Label(filter_toolbar, text="Encryption:").pack(side=tk.LEFT, padx=(0, 3))
        self.enc_filter_combo = ttk.Combobox(
            filter_toolbar,
            textvariable=self.filter_encryption_var,
            values=["All Encryption", "Encrypted only", "Unencrypted only"],
            state="readonly",
            width=15
        )
        self.enc_filter_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.enc_filter_combo.bind("<<ComboboxSelected>>", lambda e: self.update_file_list())

        # View Mode Combobox (Tree vs Flat vs 2 Sides)
        ttk.Label(filter_toolbar, text="View:").pack(side=tk.LEFT, padx=(0, 3))
        self.view_mode_combo = ttk.Combobox(
            filter_toolbar,
            textvariable=self.view_mode_var,
            values=["Tree View", "Flat View", "2 Sides View"],
            state="readonly",
            width=12
        )
        self.view_mode_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.view_mode_combo.bind("<<ComboboxSelected>>", lambda e: self.on_view_mode_changed())

        # Quick Filter Action Buttons
        ttk.Button(filter_toolbar, text="☁️ In Cloud", command=lambda: self.set_quick_status_filter("Files in Cloud")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_toolbar, text="💻 Local Only", command=lambda: self.set_quick_status_filter("Local only")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_toolbar, text="⚠️ Leaks", command=lambda: self.set_quick_encryption_filter("Unencrypted only")).pack(side=tk.LEFT, padx=2)
        ttk.Button(filter_toolbar, text="Reset", command=self.reset_filters).pack(side=tk.LEFT, padx=2)

        # 2 Sides View Toggle Button (Local folder on left, Cloud bucket on right)
        self.toggle_two_sided_btn = ttk.Button(
            filter_toolbar,
            text="👥 2 Sides View",
            command=self.toggle_two_sided_view
        )
        self.toggle_two_sided_btn.pack(side=tk.RIGHT, padx=4)

        # Enlarge Files View Toggle Button (Hides configuration sections above)
        self.toggle_config_btn = ttk.Button(
            filter_toolbar, 
            text="🔍 Enlarge View", 
            command=self.toggle_config_visibility
        )
        self.toggle_config_btn.pack(side=tk.RIGHT, padx=4)

        # File Count Badge
        self.filter_count_label = ttk.Label(filter_toolbar, text="", foreground="#475569")
        self.filter_count_label.pack(side=tk.RIGHT, padx=4)

        self.tree = ttk.Treeview(self.files_frame)
        self.tree["columns"] = ("status", "size", "last_modified", "encrypted", "cloud_name")
        self.tree.column("#0", width=300, minwidth=180)
        self.tree.column("status", width=110, minwidth=80)
        self.tree.column("size", width=85, minwidth=60)
        self.tree.column("last_modified", width=140, minwidth=110)
        self.tree.column("encrypted", width=80, minwidth=70)
        self.tree.column("cloud_name", width=280, minwidth=180)

        for col_id, title in self.tree_headings.items():
            self.tree.heading(col_id, text=title, command=lambda c=col_id: self.sort_by_column(c))

        scrollbar = ttk.Scrollbar(self.files_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Color tags for clear visual status in treeview
        self.tree.tag_configure("synced", foreground="#16a34a")        # Emerald Green
        self.tree.tag_configure("local_only", foreground="#0284c7")     # Sky Blue
        self.tree.tag_configure("cloud_only", foreground="#7c3aed")     # Violet / Purple
        self.tree.tag_configure("modified", foreground="#d97706")       # Amber
        self.tree.tag_configure("unencrypted", foreground="#dc2626")    # Red Warning
        self.tree.tag_configure("empty_local", foreground="#94a3b8")    # Muted Slate Gray for empty local row
        self.tree.tag_configure("empty_cloud", foreground="#94a3b8")    # Muted Slate Gray for empty cloud row

        self.tree.bind("<Control-c>", self.copy_cloud_name)

        # --- Actions Row ---
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=6)

        self.scan_button = ttk.Button(actions_frame, text="Scan Files", command=self.scan_files)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.check_leaks_action_btn = ttk.Button(actions_frame, text="🛡️ Audit Cloud Leaks (Cache)", command=self.check_cloud_leaks)
        self.check_leaks_action_btn.pack(side=tk.LEFT, padx=5)

        self.sync_button = ttk.Button(actions_frame, text="Sync Selected Files", command=self.sync_selected_files)
        self.sync_button.pack(side=tk.LEFT, padx=5)
        self.sync_button.config(state=tk.DISABLED)

        self.sync_all_button = ttk.Button(actions_frame, text="Sync All Missing Files", command=self.sync_all_missing_files)
        self.sync_all_button.pack(side=tk.LEFT, padx=5)
        self.sync_all_button.config(state=tk.DISABLED)

        self.pause_button = ttk.Button(actions_frame, text="⏸️ Pause Sync", command=self.toggle_pause_sync)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        self.pause_button.config(state=tk.DISABLED)

        self.cancel_button = ttk.Button(actions_frame, text="⏹️ Cancel Sync", command=self.cancel_sync)
        self.cancel_button.pack(side=tk.LEFT, padx=5)
        self.cancel_button.config(state=tk.DISABLED)

        # Status & Progress
        self.status_var = tk.StringVar(value="Ready. Connect to bucket or scan files to begin.")
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding="4")
        self.status_bar.pack(fill=tk.X, pady=(4, 2))

        # Transfer & Sync Telemetry (Speeds, Elapsed Time, ETA, Volume)
        self.metrics_frame = ttk.Frame(main_frame)
        self.metrics_frame.pack(fill=tk.X, pady=(1, 3))

        self.speed_var = tk.StringVar(value="Speed: ↑ 0.0 KB/s  |  ↓ 0.0 KB/s")
        self.speed_label = ttk.Label(self.metrics_frame, textvariable=self.speed_var, font=("TkDefaultFont", 9, "bold"), foreground="#0284c7")
        self.speed_label.pack(side=tk.LEFT, padx=(4, 12))

        self.time_var = tk.StringVar(value="Time: Elapsed: 00:00  |  ETA: --:--")
        self.time_label = ttk.Label(self.metrics_frame, textvariable=self.time_var, font=("TkDefaultFont", 9), foreground="#334155")
        self.time_label.pack(side=tk.LEFT, padx=(4, 12))

        self.volume_var = tk.StringVar(value="Volume: 0 B / 0 B (0%)")
        self.volume_label = ttk.Label(self.metrics_frame, textvariable=self.volume_var, font=("TkDefaultFont", 9), foreground="#475569")
        self.volume_label.pack(side=tk.RIGHT, padx=4)

        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=2)

    def toggle_config_visibility(self):
        """Toggle visibility of the configuration sections above the files list to enlarge treeview."""
        self.config_hidden = not self.config_hidden
        if self.config_hidden:
            self.config_container.pack_forget()
            key_str = "AES-256 CTR Key Active" if self.encryption_key else "No Key (Plaintext)"
            b_str = f"gs://{self.bucket_name}" if self.bucket_name else "No bucket connected"
            d_str = self.local_dir if self.local_dir else "No directory set"
            self.compact_summary_var.set(f"📁 {d_str}   |   ☁️ {b_str}   |   🛡️ {key_str}")
            self.compact_config_bar.pack(fill=tk.X, pady=2, before=self.files_frame)
            if hasattr(self, 'toggle_config_btn'):
                self.toggle_config_btn.config(text="⚙️ Show Settings")
        else:
            self.compact_config_bar.pack_forget()
            self.config_container.pack(fill=tk.X, pady=2, before=self.files_frame)
            if hasattr(self, 'toggle_config_btn'):
                self.toggle_config_btn.config(text="🔍 Enlarge View")

    def toggle_two_sided_view(self):
        """Toggle between 2 Sides View (Left: Local, Right: Cloud) and standard Tree/Flat View."""
        if self.view_mode_var.get() == "2 Sides View":
            self.view_mode_var.set("Tree View")
            if hasattr(self, 'toggle_two_sided_btn'):
                self.toggle_two_sided_btn.config(text="👥 2 Sides View")
        else:
            self.view_mode_var.set("2 Sides View")
            if hasattr(self, 'toggle_two_sided_btn'):
                self.toggle_two_sided_btn.config(text="📋 Standard View")
        self.update_heading_arrows()
        self.update_file_list()

    def on_view_mode_changed(self):
        """Handle combobox view mode selection changes."""
        if hasattr(self, 'toggle_two_sided_btn'):
            if self.view_mode_var.get() == "2 Sides View":
                self.toggle_two_sided_btn.config(text="📋 Standard View")
            else:
                self.toggle_two_sided_btn.config(text="👥 2 Sides View")
        self.update_heading_arrows()
        self.update_file_list()

    # --- CRYPTO HELPERS ---

    def generate_key(self):
        """Generate a cryptographically secure 32-byte key for AES-256."""
        try:
            key = secrets.token_bytes(32)
            self.set_encryption_key(key)
            messagebox.showinfo(
                "Key Generated",
                "New 256-bit AES key generated!\n\n"
                "⚠️ IMPORTANT: Please click 'Save Current Key' and keep a secure backup.\n"
                "If this key is lost, your encrypted files in Google Cloud Storage cannot be recovered."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")

    def load_key_from_file(self):
        filename = filedialog.askopenfilename(
            title="Load Encryption Key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "rb") as key_file:
                    encoded_key = key_file.read().strip()

                try:
                    key = base64.urlsafe_b64decode(encoded_key)
                except Exception:
                    key = encoded_key

                if len(key) != 32:
                    messagebox.showerror(
                        "Invalid Key",
                        f"Invalid key length ({len(key)} bytes). AES-256 requires exactly 32 bytes."
                    )
                    return

                self.set_encryption_key(key)
                messagebox.showinfo("Success", "AES-256 encryption key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")

    def save_key_to_file(self):
        if not self.encryption_key:
            messagebox.showwarning("Warning", "No key is currently loaded to save.")
            return
        filename = filedialog.asksaveasfilename(
            title="Save Encryption Key",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key")]
        )
        if filename:
            try:
                with open(filename, "wb") as key_file:
                    key_file.write(base64.urlsafe_b64encode(self.encryption_key))
                messagebox.showinfo("Success", f"Key safely saved to: {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")

    def unload_key(self):
        self.encryption_key = None
        self.key_status_var.set("⚠️ No Key Loaded - Files will be uploaded unencrypted!")
        self.key_status_label.config(foreground="#dc2626")
        self.status_var.set("Encryption key unloaded. Any subsequent uploads will trigger an unencrypted warning.")

    def set_encryption_key(self, key: bytes):
        self.encryption_key = key
        b64_preview = base64.urlsafe_b64encode(key).decode()
        preview = b64_preview[:6] + "..." + b64_preview[-6:]
        self.key_status_var.set(f"🔒 Active Key: {preview} (Streaming AES-256 CTR)")
        self.key_status_label.config(foreground="#16a34a")

    def encrypt_filename(self, path: str) -> str:
        """Derive a deterministic, opaque blob name from the original path using HMAC-SHA256."""
        h = hmac.new(self.encryption_key, path.encode('utf-8'), hashlib.sha256).hexdigest()
        return f"enc_{h}"

    def encrypt_metadata_path(self, path: str) -> str:
        """Encrypt the original file path (AES-256-CBC) for storage in blob metadata."""
        if Cipher is None:
            raise RuntimeError("The 'cryptography' library is required.")
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(path.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_metadata_path(self, encrypted_b64: str) -> str:
        """Decrypt the original file path from blob metadata."""
        if Cipher is None:
            raise RuntimeError("The 'cryptography' library is required.")
        data = base64.urlsafe_b64decode(encrypted_b64)
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')

    # --- CLOUD CACHE MANAGEMENT ---

    def load_cloud_cache(self) -> bool:
        """
        Load cloud file tree from local disk cache if available.
        Returns True if cache was loaded, False otherwise.
        """
        cache_file = self.get_cache_filename()
        if not os.path.exists(cache_file):
            self.cloud_cache_timestamp = None
            self.cache_status_var.set("Cloud Cache: No cache found on disk (will fetch from GCS)")
            return False

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if data.get("bucket") != self.bucket_name:
                return False

            raw_files = data.get("files", {})
            self.cloud_files = {}
            for path, meta in raw_files.items():
                mod_str = meta.get("modified")
                mod_dt = datetime.datetime.fromisoformat(mod_str) if mod_str else None
                self.cloud_files[path] = {
                    'size': meta.get('size', 0),
                    'modified': mod_dt,
                    'is_encrypted': meta.get('is_encrypted', False),
                    'blob_name': meta.get('blob_name', path)
                }

            self.cloud_cache_timestamp = data.get("timestamp")
            formatted_ts = self.cloud_cache_timestamp.replace("T", " ")[:16] if self.cloud_cache_timestamp else "unknown"
            self.cache_status_var.set(
                f"Cloud Cache: {len(self.cloud_files)} items (Cached: {formatted_ts})"
            )
            return True
        except Exception as e:
            print(f"Error loading cloud cache: {e}")
            return False

    def save_cloud_cache(self):
        """Persist current cloud file tree to disk."""
        if not self.bucket_name:
            return

        cache_file = self.get_cache_filename()
        try:
            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
            serialized_files = {}
            for path, meta in self.cloud_files.items():
                mod = meta.get('modified')
                mod_str = mod.isoformat() if isinstance(mod, (datetime.datetime, datetime.date)) else str(mod) if mod else None
                serialized_files[path] = {
                    'size': meta.get('size', 0),
                    'modified': mod_str,
                    'is_encrypted': meta.get('is_encrypted', False),
                    'blob_name': meta.get('blob_name', path)
                }

            data = {
                "bucket": self.bucket_name,
                "timestamp": now_str,
                "count": len(serialized_files),
                "files": serialized_files
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            self.cloud_cache_timestamp = now_str
            formatted_ts = now_str.replace("T", " ")[:16]
            self.cache_status_var.set(
                f"Cloud Cache: {len(serialized_files)} items (Cached: {formatted_ts})"
            )
        except Exception as e:
            print(f"Error saving cloud cache: {e}")

    def clear_cloud_cache(self):
        """Manually clear the cached cloud file tree."""
        cache_file = self.get_cache_filename()
        if os.path.exists(cache_file):
            try:
                os.remove(cache_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete cache file: {e}")
                return

        self.cloud_files = {}
        self.cloud_cache_timestamp = None
        self.cache_status_var.set("Cloud Cache: Cleared. Next scan will query GCS directly.")
        if messagebox:
            messagebox.showinfo("Cache Cleared", f"Cache cleared for bucket '{self.bucket_name}'.")
        else:
            print(f"Cache cleared for bucket '{self.bucket_name}'.")

    def refresh_cloud_cache(self):
        """Trigger an explicit fresh scan of the cloud bucket, bypassing the cache."""
        if not self.bucket:
            if messagebox:
                messagebox.showwarning("Not Connected", "Please connect to a GCS bucket before refreshing the cache.")
            else:
                print("Please connect to a GCS bucket before refreshing the cache.")
            return
        self.scan_files(force_refresh_cloud=True)

    # --- CLOUD LEAK AUDIT (USES CACHED DATA - NO NETWORK RESCAN REQUIRED) ---

    def check_cloud_leaks(self) -> list:
        """
        Check for leaks: inspects the cloud file tree for any unencrypted files.
        Uses cached cloud data without querying or rescanning the GCS network.
        Returns a list of leaked file information dictionaries.
        """
        # Ensure cloud files are loaded from cache if not already in memory
        if not self.cloud_files:
            loaded = self.load_cloud_cache()
            if not loaded or not self.cloud_files:
                if messagebox:
                    messagebox.showwarning(
                        "No Cloud Cache Available",
                        "No cached cloud file tree was found to audit for leaks.\n\n"
                        "Please connect to your Google Cloud Storage bucket or perform an initial scan first."
                    )
                else:
                    print("No cached cloud file tree available to audit for leaks.")
                return []

        leaks = []
        total_unenc_bytes = 0
        total_cloud_files = len(self.cloud_files)

        for path, meta in self.cloud_files.items():
            if not meta.get('is_encrypted', False):
                sz = meta.get('size', 0)
                total_unenc_bytes += sz
                leaks.append({
                    'path': path,
                    'size': sz,
                    'modified': meta.get('modified'),
                    'blob_name': meta.get('blob_name', path)
                })

        if leaks:
            self.status_var.set(
                f"⚠️ Security Audit: {len(leaks)} unencrypted leak(s) detected in cloud ({self.format_size(total_unenc_bytes)})"
            )
            self.show_leak_report_dialog(leaks, total_cloud_files, total_unenc_bytes)
        else:
            self.status_var.set(
                f"✅ Security Audit: 0 leaks detected! All {total_cloud_files} file(s) in cloud cache are encrypted."
            )
            if messagebox:
                messagebox.showinfo(
                    "Cloud Security Audit: Zero Leaks",
                    f"✅ ZERO LEAKS DETECTED!\n\n"
                    f"Audited {total_cloud_files} file(s) in cloud cache.\n"
                    f"All files in the cloud bucket are verified to be encrypted with AES-256 CTR."
                )
            else:
                print(f"Zero leaks detected among {total_cloud_files} cloud files.")

        return leaks

    def show_leak_report_dialog(self, leaks: list, total_files: int, total_unenc_bytes: int):
        """Display an interactive leak audit report window with selection & export options."""
        if tk is None or not hasattr(self, 'master') or self.master is None:
            print("=" * 60)
            print(f"SECURITY LEAK AUDIT REPORT: {len(leaks)} unencrypted file(s) found!")
            for lk in leaks:
                print(f" - {lk['path']} ({self.format_size(lk['size'])}) -> Blob: {lk['blob_name']}")
            print("=" * 60)
            return

        try:
            dialog = tk.Toplevel(self.master)
            dialog.title("⚠️ Cloud Security Leak Audit Report")
            dialog.geometry("720x460")
            dialog.minsize(600, 350)
            dialog.transient(self.master)
            dialog.grab_set()

            # Header warning banner
            header_frame = tk.Frame(dialog, bg="#450a0a", padx=12, pady=10)
            header_frame.pack(fill=tk.X)

            title_lbl = tk.Label(
                header_frame,
                text=f"⚠️ CLOUD LEAK DETECTED: {len(leaks)} UNENCRYPTED FILE(S)",
                font=("TkDefaultFont", 11, "bold"),
                bg="#450a0a",
                fg="#fecaca"
            )
            title_lbl.pack(anchor=tk.W)

            summary_lbl = tk.Label(
                header_frame,
                text=f"Audited {total_files} file(s) from local cloud cache • {self.format_size(total_unenc_bytes)} stored in PLAINTEXT on GCS\n"
                     f"These files can be read by anyone with bucket access or cloud administrators without your AES key.",
                font=("TkDefaultFont", 9),
                bg="#450a0a",
                fg="#fca5a5",
                justify=tk.LEFT
            )
            summary_lbl.pack(anchor=tk.W, pady=2)

            # Leaks Table Frame
            table_frame = ttk.Frame(dialog, padding="8")
            table_frame.pack(fill=tk.BOTH, expand=True)

            leak_tree = ttk.Treeview(table_frame)
            leak_tree["columns"] = ("size", "modified", "blob_name")
            leak_tree.column("#0", width=260, minwidth=180)
            leak_tree.column("size", width=85, minwidth=60)
            leak_tree.column("modified", width=140, minwidth=110)
            leak_tree.column("blob_name", width=220, minwidth=150)

            leak_tree.heading("#0", text="Leaked File Path (Unencrypted)")
            leak_tree.heading("size", text="Size")
            leak_tree.heading("modified", text="Last Modified")
            leak_tree.heading("blob_name", text="Cloud Blob Name")

            scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=leak_tree.yview)
            leak_tree.configure(yscrollcommand=scrollbar.set)
            leak_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            for lk in leaks:
                cmod = lk.get('modified')
                mod_str = cmod.strftime("%Y-%m-%d %H:%M") if isinstance(cmod, (datetime.datetime, datetime.date)) else str(cmod) if cmod else "?"
                leak_tree.insert(
                    "",
                    "end",
                    text=lk['path'],
                    values=(self.format_size(lk['size']), mod_str, lk['blob_name'])
                )

            # Action Buttons Bar
            btn_bar = ttk.Frame(dialog, padding="8")
            btn_bar.pack(fill=tk.X)

            def on_select_leaks():
                paths = [l['path'] for l in leaks]
                self.select_leaked_items_in_tree(paths)
                dialog.destroy()

            def on_export():
                self.export_leak_report(leaks, total_files, total_unenc_bytes)

            select_btn = ttk.Button(btn_bar, text="🎯 Select Leaked Files in Main Window", command=on_select_leaks)
            select_btn.pack(side=tk.LEFT, padx=4)

            export_btn = ttk.Button(btn_bar, text="💾 Export Audit Report (JSON)", command=on_export)
            export_btn.pack(side=tk.LEFT, padx=4)

            close_btn = ttk.Button(btn_bar, text="Close", command=dialog.destroy)
            close_btn.pack(side=tk.RIGHT, padx=4)

        except Exception as e:
            print(f"Error opening leak report dialog: {e}")

    def select_leaked_items_in_tree(self, leaked_paths: list):
        """Highlight and select leaked items in the main Tkinter treeview."""
        if not leaked_paths or not hasattr(self, 'tree'):
            return
        target_set = set(leaked_paths)
        to_select = []
        for item in self.tree.get_children():
            self._find_matching_tree_items(item, target_set, to_select)
        if to_select:
            self.tree.selection_set(to_select)
            self.tree.see(to_select[0])
            self.status_var.set(f"Selected {len(to_select)} unencrypted file(s) in treeview for review/re-sync.")

    def _find_matching_tree_items(self, item, target_paths, matches):
        children = self.tree.get_children(item)
        if children:
            for ch in children:
                self._find_matching_tree_items(ch, target_paths, matches)
        else:
            path = self.get_path(item)
            if path in target_paths:
                matches.append(item)
                # Expand parent directories
                parent = self.tree.parent(item)
                while parent:
                    self.tree.item(parent, open=True)
                    parent = self.tree.parent(parent)

    def export_leak_report(self, leaks: list, total_files: int, total_bytes: int):
        """Export leak audit findings to a JSON file."""
        if filedialog is None:
            return
        clean_bucket = self.bucket_name or "bucket"
        f = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt")],
            initialfile=f"leak_audit_{clean_bucket}.json"
        )
        if f:
            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
            report = {
                "audit_timestamp": now_str,
                "bucket": self.bucket_name,
                "source": "local_cloud_cache",
                "total_cloud_files_audited": total_files,
                "unencrypted_leaks_count": len(leaks),
                "unencrypted_total_bytes": total_bytes,
                "unencrypted_files": [
                    {
                        "path": l['path'],
                        "size": l['size'],
                        "modified": str(l['modified']),
                        "blob_name": l['blob_name']
                    }
                    for l in leaks
                ]
            }
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            if messagebox:
                messagebox.showinfo("Report Exported", f"Leak audit report exported successfully to:\n{f}")

    # --- CONFIG PERSISTENCE & PATH HISTORY ---

    def update_history(self, history_list: list, new_val: str, max_items: int = 15) -> list:
        """Helper to append a newly used directory, credential, or bucket to history without duplicates."""
        if not new_val or not str(new_val).strip():
            return history_list
        val = str(new_val).strip()
        updated = [item for item in history_list if item != val]
        updated.insert(0, val)
        return updated[:max_items]

    def on_local_dir_selected(self, event=None):
        """Triggered when user selects a previously used local directory from combobox dropdown."""
        val = self.local_dir_var.get().strip()
        if val:
            self.local_dir = val
            self.save_config()

    def on_credentials_selected(self, event=None):
        """Triggered when user selects a previously used credentials file from combobox dropdown."""
        val = self.credentials_var.get().strip()
        if val:
            self.credentials_path = val
            self.save_config()

    def on_bucket_selected(self, event=None):
        """Triggered when user selects a previously used bucket name from combobox dropdown."""
        val = self.bucket_var.get().strip()
        if val:
            self.bucket_name = val
            self.load_cloud_cache()
            self.save_config()

    def on_workers_changed(self):
        """Handle user changing worker thread count."""
        try:
            val = int(self.workers_var.get())
            self.max_workers = max(1, min(16, val))
            self.workers_var.set(self.max_workers)
            self.save_config()
        except Exception:
            pass

    def load_config(self):
        """Load configuration and previous path history from file."""
        try:
            with open(self.config_file, 'r', encoding="utf-8") as f:
                config = json.load(f)
                self.local_dir = config.get('local_dir', '')
                self.local_dir_var.set(self.local_dir)
                self.credentials_path = config.get('credentials_path', '')
                self.credentials_var.set(self.credentials_path)
                self.bucket_name = config.get('bucket_name', '')
                self.bucket_var.set(self.bucket_name)

                # Parallel worker threads count
                saved_workers = config.get('max_workers', 4)
                try:
                    self.max_workers = max(1, min(16, int(saved_workers)))
                    if hasattr(self, 'workers_var'):
                        self.workers_var.set(self.max_workers)
                except Exception:
                    self.max_workers = 4

                # Load previous history lists
                self.history_local_dirs = config.get('history_local_dirs', [])
                self.history_credentials_paths = config.get('history_credentials_paths', [])
                self.history_bucket_names = config.get('history_bucket_names', [])

                # Ensure active values are present at the front of history
                if self.local_dir and self.local_dir not in self.history_local_dirs:
                    self.history_local_dirs.insert(0, self.local_dir)
                if self.credentials_path and self.credentials_path not in self.history_credentials_paths:
                    self.history_credentials_paths.insert(0, self.credentials_path)
                if self.bucket_name and self.bucket_name not in self.history_bucket_names:
                    self.history_bucket_names.insert(0, self.bucket_name)

                # Populate combobox dropdown values
                if hasattr(self, 'local_dir_combo'):
                    self.local_dir_combo['values'] = self.history_local_dirs
                if hasattr(self, 'credentials_combo'):
                    self.credentials_combo['values'] = self.history_credentials_paths
                if hasattr(self, 'bucket_combo'):
                    self.bucket_combo['values'] = self.history_bucket_names

                # Load excluded patterns
                loaded_exclusions = config.get('excluded_patterns', None)
                if loaded_exclusions is not None and isinstance(loaded_exclusions, list):
                    self.excluded_patterns = loaded_exclusions

                if hasattr(self, 'exclusion_listbox'):
                    self.exclusion_listbox.delete(0, tk.END)
                    for p in self.excluded_patterns:
                        self.exclusion_listbox.insert(tk.END, p)

                # Check for existing cache
                if self.bucket_name:
                    self.load_cloud_cache()
        except FileNotFoundError:
            # If no previous config, populate listbox with defaults
            if hasattr(self, 'exclusion_listbox'):
                self.exclusion_listbox.delete(0, tk.END)
                for p in self.excluded_patterns:
                    self.exclusion_listbox.insert(tk.END, p)

    def save_config(self):
        """Save current configuration and history lists to file."""
        if hasattr(self, 'local_dir_var'):
            ld = self.local_dir_var.get().strip()
            if ld:
                self.local_dir = ld
        if self.local_dir:
            self.history_local_dirs = self.update_history(self.history_local_dirs, self.local_dir)

        if hasattr(self, 'credentials_var'):
            cp = self.credentials_var.get().strip()
            if cp:
                self.credentials_path = cp
        if self.credentials_path:
            self.history_credentials_paths = self.update_history(self.history_credentials_paths, self.credentials_path)

        if hasattr(self, 'bucket_var'):
            bn = self.bucket_var.get().strip()
            if bn:
                self.bucket_name = bn
        if self.bucket_name:
            self.history_bucket_names = self.update_history(self.history_bucket_names, self.bucket_name)

        # Keep comboboxes in sync with latest history
        if hasattr(self, 'local_dir_combo'):
            self.local_dir_combo['values'] = self.history_local_dirs
        if hasattr(self, 'credentials_combo'):
            self.credentials_combo['values'] = self.history_credentials_paths
        if hasattr(self, 'bucket_combo'):
            self.bucket_combo['values'] = self.history_bucket_names

        config = {
            'local_dir': self.local_dir,
            'credentials_path': self.credentials_path,
            'bucket_name': self.bucket_name,
            'max_workers': self.max_workers,
            'history_local_dirs': self.history_local_dirs,
            'history_credentials_paths': self.history_credentials_paths,
            'history_bucket_names': self.history_bucket_names,
            'excluded_patterns': self.excluded_patterns
        }
        with open(self.config_file, 'w', encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    # --- UI EVENT HANDLERS ---

    def copy_cloud_name(self, event=None):
        """Copy the encrypted cloud name to clipboard."""
        sel = self.tree.selection()
        if sel:
            item = sel[0]
            values = self.tree.item(item, "values")
            if values and len(values) > 4:
                cloud_name = values[4]
                if cloud_name:
                    self.master.clipboard_clear()
                    self.master.clipboard_append(cloud_name)
                    self.master.update()
                    self.status_var.set(f"Copied cloud blob name: {cloud_name}")

    def browse_directory(self):
        d = filedialog.askdirectory()
        if d:
            self.local_dir_var.set(d)
            self.local_dir = d
            self.history_local_dirs = self.update_history(self.history_local_dirs, d)
            if hasattr(self, 'local_dir_combo'):
                self.local_dir_combo['values'] = self.history_local_dirs
            self.save_config()

    def browse_credentials(self):
        f = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if f:
            self.credentials_var.set(f)
            self.credentials_path = f
            self.history_credentials_paths = self.update_history(self.history_credentials_paths, f)
            if hasattr(self, 'credentials_combo'):
                self.credentials_combo['values'] = self.history_credentials_paths
            self.save_config()

    def add_exclusion(self):
        p = simpledialog.askstring("Add Exclusion", "Pattern to ignore (e.g. '.git', '__pycache__', 'temp'):")
        if p and p.strip():
            p = p.strip()
            if p not in self.excluded_patterns:
                self.excluded_patterns.append(p)
                self.exclusion_listbox.insert(tk.END, p)
                self.save_config()
                self.status_var.set(f"Added exclusion '{p}' and saved to configuration.")

    def remove_exclusion(self):
        sel = self.exclusion_listbox.curselection()
        if sel:
            idx = sel[0]
            removed = self.excluded_patterns.pop(idx)
            self.exclusion_listbox.delete(idx)
            self.save_config()
            self.status_var.set(f"Removed exclusion '{removed}' and updated configuration.")

    def save_exclusions(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if f:
            with open(f, 'w', encoding="utf-8") as fh:
                json.dump(self.excluded_patterns, fh, indent=2)
            messagebox.showinfo("Saved", "Exclusion patterns saved to export file.")

    def load_exclusions(self):
        f = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if f:
            try:
                with open(f, 'r', encoding="utf-8") as fh:
                    loaded = json.load(fh)
                    if isinstance(loaded, list):
                        self.excluded_patterns = loaded
                        self.exclusion_listbox.delete(0, tk.END)
                        for p in self.excluded_patterns:
                            self.exclusion_listbox.insert(tk.END, p)
                        self.save_config()
                        self.status_var.set("Loaded exclusions from file and saved to configuration.")
                        messagebox.showinfo("Loaded", f"Loaded {len(loaded)} exclusion patterns.")
                    else:
                        messagebox.showerror("Error", "Invalid exclusion file format (expected JSON list).")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load exclusions: {str(e)}")

    def is_excluded(self, path: str) -> bool:
        for p in self.excluded_patterns:
            if path.startswith(p + '/') or ('/' + p + '/') in path or path.endswith('/' + p) or path == p:
                return True
        return False

    def connect_to_gcs(self):
        self.bucket_name = self.bucket_var.get().strip()
        self.credentials_path = self.credentials_var.get().strip()
        if not self.credentials_path or not self.bucket_name:
            messagebox.showerror("Configuration Error", "Please provide both the Credentials JSON path and Bucket Name.")
            return

        if storage is None or service_account is None:
            messagebox.showerror(
                "Missing Library",
                "Google Cloud Storage client library is not installed.\n\nPlease install it via:\npip install google-cloud-storage"
            )
            return

        try:
            self.status_var.set("Connecting to Google Cloud Storage...")
            self.master.update_idletasks()
            creds = service_account.Credentials.from_service_account_file(self.credentials_path)
            self.gcs_client = storage.Client(credentials=creds)
            try:
                self.bucket = self.gcs_client.get_bucket(self.bucket_name)
                self.status_var.set(f"Connected successfully: gs://{self.bucket_name}")
                self.load_cloud_cache()
                messagebox.showinfo("Connected", f"Connected to bucket: {self.bucket_name}")
                self.sync_button.config(state=tk.NORMAL)
                self.sync_all_button.config(state=tk.NORMAL)
                self.save_config()
            except Exception as e:
                messagebox.showerror("Bucket Connection Error", f"Failed to access bucket '{self.bucket_name}':\n{e}")
        except Exception as e:
            messagebox.showerror("Authentication Error", f"Client authentication error:\n{e}")

    # --- SCANNING WITH CACHE ---

    def scan_files(self, force_refresh_cloud: bool = False):
        if not self.local_dir:
            messagebox.showwarning("Missing Directory", "Please specify and select a local directory first.")
            return
        if not self.bucket:
            messagebox.showwarning("Not Connected", "Please connect to your Google Cloud Storage bucket first.")
            return

        self.sync_mode = self.sync_mode_var.get()
        self.tree.delete(*self.tree.get_children())
        self.is_scanning = True
        t = threading.Thread(target=self.perform_scan, args=(force_refresh_cloud,))
        t.daemon = True
        t.start()

    def perform_scan(self, force_refresh_cloud: bool = False):
        try:
            scan_start_time = time.time()
            total_items_scanned = 0

            # 1. Scan Local Directory
            self.status_var.set("Scanning Local Directory...")
            if hasattr(self, 'speed_var'):
                self.speed_var.set("Speed: Structure Scan: Initializing...")
            if hasattr(self, 'time_var'):
                self.time_var.set("Time: Elapsed: 00:00  |  ETA: --:--")
            if hasattr(self, 'volume_var'):
                self.volume_var.set("Volume: 0 items discovered")
            self.master.update_idletasks()

            self.local_files = {}
            lp = pathlib.Path(self.local_dir)
            if lp.exists() and lp.is_dir():
                for p in lp.rglob('*'):
                    if p.is_file():
                        rp = str(p.relative_to(lp)).replace('\\', '/')
                        if self.is_excluded(rp):
                            continue
                        self.local_files[rp] = {
                            'path': str(p),
                            'size': p.stat().st_size,
                            'modified': datetime.datetime.fromtimestamp(p.stat().st_mtime)
                        }
                        total_items_scanned += 1
                        if total_items_scanned % 15 == 0:
                            elapsed = max(0.001, time.time() - scan_start_time)
                            rate = total_items_scanned / elapsed
                            if hasattr(self, 'speed_var'):
                                self.speed_var.set(f"Speed: Structure Discovery: {rate:.1f} items/s")
                            if hasattr(self, 'time_var'):
                                self.time_var.set(f"Time: Elapsed: {format_time_duration(elapsed)}  |  ETA: --:--")
                            if hasattr(self, 'volume_var'):
                                self.volume_var.set(f"Volume: {len(self.local_files)} local files")
                            self.master.update_idletasks()

            # 2. Scan Cloud (Check cache first unless force_refresh_cloud is True)
            has_cache = False
            if not force_refresh_cloud:
                has_cache = self.load_cloud_cache()

            if has_cache and not force_refresh_cloud:
                elapsed = max(0.001, time.time() - scan_start_time)
                total_items = len(self.local_files) + len(self.cloud_files)
                rate = total_items / elapsed
                if hasattr(self, 'speed_var'):
                    self.speed_var.set(f"Speed: Structure Cache: {rate:.1f} items/s (cached)")
                if hasattr(self, 'time_var'):
                    self.time_var.set(f"Time: Elapsed: {format_time_duration(elapsed)}  |  ETA: 00:00")
                if hasattr(self, 'volume_var'):
                    self.volume_var.set(f"Volume: {total_items} items")
                self.status_var.set(f"Loaded cloud files from cache ({len(self.cloud_files)} items in {elapsed:.2f}s)")
            else:
                self.status_var.set("Scanning Cloud Bucket (live query)...")
                self.master.update_idletasks()
                self.cloud_files = {}

                cloud_count = 0
                for b in self.bucket.list_blobs():
                    is_enc = b.metadata and b.metadata.get('encryption') == 'aes-stream'
                    # Resolve original path: encrypted blobs store the encrypted path in metadata
                    if is_enc and self.encryption_key and b.metadata.get('encrypted_path'):
                        try:
                            original_path = self.decrypt_metadata_path(b.metadata['encrypted_path'])
                        except Exception:
                            original_path = b.name
                    else:
                        original_path = b.name

                    if self.is_excluded(original_path):
                        continue

                    self.cloud_files[original_path] = {
                        'size': b.size,
                        'modified': b.updated,
                        'is_encrypted': is_enc,
                        'blob_name': b.name
                    }
                    cloud_count += 1
                    total_items_scanned += 1
                    if cloud_count % 10 == 0:
                        elapsed = max(0.001, time.time() - scan_start_time)
                        rate = total_items_scanned / elapsed
                        if hasattr(self, 'speed_var'):
                            self.speed_var.set(f"Speed: Structure Discovery: {rate:.1f} items/s")
                        if hasattr(self, 'time_var'):
                            self.time_var.set(f"Time: Elapsed: {format_time_duration(elapsed)}  |  ETA: --:--")
                        if hasattr(self, 'volume_var'):
                            self.volume_var.set(f"Volume: {cloud_count} cloud blobs")
                        self.master.update_idletasks()

                # Save new cloud file tree to disk cache
                self.save_cloud_cache()

            total_elapsed = max(0.001, time.time() - scan_start_time)
            total_items = len(self.local_files) + len(self.cloud_files)
            overall_rate = total_items / total_elapsed
            if hasattr(self, 'speed_var'):
                self.speed_var.set(f"Speed: Structure: {overall_rate:.1f} items/s")
            if hasattr(self, 'time_var'):
                self.time_var.set(f"Time: Elapsed: {format_time_duration(total_elapsed)}  |  ETA: 00:00")
            if hasattr(self, 'volume_var'):
                self.volume_var.set(f"Volume: {total_items} items total")

            self.master.after(0, self.update_file_list)
        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Scan Error", f"Failed during file scan:\n{err}"))
        finally:
            self.is_scanning = False

    # --- SORTING AND FILTERING METHODS ---

    def sort_by_column(self, col_id: str):
        """Toggle sort order or switch sort column across all table columns."""
        if self.sort_column == col_id:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_column = col_id
            self.sort_descending = False
        self.update_heading_arrows()
        self.update_file_list()

    def update_heading_arrows(self):
        """Update treeview column headers with sort direction indicators."""
        is_two_sided = self.view_mode_var.get() == "2 Sides View"
        for col_id, base_title in self.tree_headings.items():
            if is_two_sided:
                if col_id == "#0":
                    display_title = "Local File (Left Side)"
                elif col_id == "status":
                    display_title = "Sync State"
                elif col_id == "size":
                    display_title = "Local Size"
                elif col_id == "last_modified":
                    display_title = "Local Modified"
                elif col_id == "encrypted":
                    display_title = "Encrypted?"
                elif col_id == "cloud_name":
                    display_title = "Cloud Blob (Right Side)"
                else:
                    display_title = base_title
            else:
                display_title = base_title

            if col_id == self.sort_column:
                arrow = " ▼" if self.sort_descending else " ▲"
                self.tree.heading(col_id, text=f"{display_title}{arrow}")
            else:
                self.tree.heading(col_id, text=display_title)

    def set_quick_status_filter(self, status: str):
        """Set a quick status filter like 'Files in Cloud' or 'Local only'."""
        self.filter_status_var.set(status)
        self.update_file_list()

    def set_quick_encryption_filter(self, enc: str):
        """Set a quick encryption filter like 'Unencrypted only'."""
        self.filter_encryption_var.set(enc)
        self.update_file_list()

    def reset_filters(self):
        """Reset all search filters to default."""
        self.filter_status_var.set("All Statuses")
        self.filter_encryption_var.set("All Encryption")
        self.filter_search_var.set("")
        self.update_file_list()

    def collect_file_records(self) -> list:
        """Collect normalized metadata for all files from local and cloud inventories."""
        if self.sync_mode == "local_to_cloud":
            paths = sorted(self.local_files.keys())
        else:
            paths = sorted(set(list(self.local_files.keys()) + list(self.cloud_files.keys())))

        records = []
        for p in paths:
            enc_str = "No"
            is_enc = False
            cloud_name = ""
            status = "Local only"

            if p in self.local_files and p in self.cloud_files:
                status = "Synced"
                if self.cloud_files[p].get('is_encrypted'):
                    enc_str = "Yes"
                    is_enc = True
                cloud_name = self.cloud_files[p].get('blob_name', p)

                ls, cs = self.local_files[p]['size'], self.cloud_files[p]['size']
                if self.cloud_files[p].get('is_encrypted'):
                    if cs != ls + 16:
                        status = "Modified"
                else:
                    if cs != ls:
                        status = "Modified"
            elif p in self.local_files:
                status = "Local only"
            else:
                status = "Cloud only"
                if self.cloud_files[p].get('is_encrypted'):
                    enc_str = "Yes"
                    is_enc = True
                cloud_name = self.cloud_files[p].get('blob_name', p)
                if self.sync_mode == "local_to_cloud":
                    continue

            if p in self.local_files:
                raw_size = self.local_files[p]['size']
                raw_mod = self.local_files[p]['modified']
                mod_str = raw_mod.strftime("%Y-%m-%d %H:%M") if hasattr(raw_mod, 'strftime') else str(raw_mod)
            else:
                raw_size = self.cloud_files[p]['size']
                raw_mod = self.cloud_files[p]['modified']
                mod_str = raw_mod.strftime("%Y-%m-%d %H:%M") if hasattr(raw_mod, 'strftime') else str(raw_mod) if raw_mod else "?"

            records.append({
                'path': p,
                'status': status,
                'raw_size': raw_size if raw_size is not None else 0,
                'size_str': self.format_size(raw_size),
                'raw_modified': raw_mod,
                'mod_str': mod_str,
                'encrypted': enc_str,
                'is_encrypted': is_enc,
                'cloud_name': cloud_name,
                'in_cloud': p in self.cloud_files,
                'in_local': p in self.local_files
            })
        return records

    def filter_records(self, records: list) -> list:
        """Filter records by status (e.g. only files on cloud), encryption, and text query."""
        status_filter = self.filter_status_var.get()
        enc_filter = self.filter_encryption_var.get()
        search_query = self.filter_search_var.get().strip().lower()

        filtered = []
        for r in records:
            # Status Filter
            if status_filter == "Files in Cloud":
                if not r['in_cloud']:
                    continue
            elif status_filter in ("Cloud only", "Local only", "Synced", "Modified"):
                if r['status'] != status_filter:
                    continue

            # Encryption Filter
            if enc_filter == "Encrypted only" and r['encrypted'] != "Yes":
                continue
            elif enc_filter == "Unencrypted only" and r['encrypted'] != "No":
                continue

            # Text Search Filter
            if search_query:
                fname = r['path'].split('/')[-1].lower()
                full_path = r['path'].lower()
                cname = r['cloud_name'].lower()
                status_str = r['status'].lower()
                if (search_query not in full_path and 
                    search_query not in fname and 
                    search_query not in cname and 
                    search_query not in status_str):
                    continue

            filtered.append(r)
        return filtered

    def sort_records(self, records: list) -> list:
        """Sort records by any column with support for numeric sizes and timestamps."""
        col = self.sort_column
        reverse = self.sort_descending

        def sort_key(r):
            if col == "#0":
                return (r['path'].lower(),)
            elif col == "status":
                return (r['status'].lower(), r['path'].lower())
            elif col == "size":
                return (r['raw_size'], r['path'].lower())
            elif col == "last_modified":
                dt_str = str(r['raw_modified'] or "")
                return (dt_str, r['path'].lower())
            elif col == "encrypted":
                return (r['encrypted'], r['path'].lower())
            elif col == "cloud_name":
                return (r['cloud_name'].lower(), r['path'].lower())
            return (r['path'].lower(),)

        return sorted(records, key=sort_key, reverse=reverse)

    def update_file_list(self):
        """Populate treeview with filtered and sorted file records."""
        self.tree.delete(*self.tree.get_children())
        self._item_to_path.clear()
        self._item_to_raw_size.clear()

        all_records = self.collect_file_records()
        filtered_records = self.filter_records(all_records)
        sorted_records = self.sort_records(filtered_records)

        view_mode = self.view_mode_var.get()

        if view_mode == "2 Sides View":
            for r in sorted_records:
                status = r['status']
                # Left side (local file): empty placeholder if not on local disk
                if not r['in_local']:
                    local_text = "— (Empty on Local Disk) —"
                    local_size = "—"
                    local_mod = "—"
                else:
                    local_text = r['path']
                    local_size = r['size_str']
                    local_mod = r['mod_str']

                # Right side (cloud file): empty placeholder if not in cloud bucket
                if not r['in_cloud']:
                    cloud_blob = "— (Empty in Cloud Storage) —"
                    enc_display = "—"
                else:
                    cloud_blob = r['cloud_name'] or r['path']
                    enc_display = "🔒 Yes (AES-256)" if r['encrypted'] == "Yes" else "⚠️ Plaintext"

                if status == "Local only":
                    status_display = "Local only →"
                elif status == "Cloud only":
                    status_display = "← Cloud only"
                elif status == "Synced":
                    status_display = "🟢 Synced"
                elif status == "Modified":
                    status_display = "🟡 Modified"
                else:
                    status_display = status

                vals = (status_display, local_size, local_mod, enc_display, cloud_blob)
                tags = [status.lower().replace(" ", "_")]
                if r['encrypted'] == "No" and r['in_cloud']:
                    tags.append("unencrypted")
                if not r['in_local']:
                    tags.append("empty_local")
                if not r['in_cloud']:
                    tags.append("empty_cloud")

                item_id = self.tree.insert("", "end", text=local_text, values=vals, tags=tuple(tags))
                self._item_to_path[item_id] = r['path']
                self._item_to_raw_size[item_id] = r.get('raw_size', 0)
        elif view_mode == "Flat View":
            for r in sorted_records:
                vals = (r['status'], r['size_str'], r['mod_str'], r['encrypted'], r['cloud_name'])
                tags = [r['status'].lower().replace(" ", "_")]
                if r['encrypted'] == "No":
                    tags.append("unencrypted")
                item_id = self.tree.insert("", "end", text=r['path'], values=vals, tags=tuple(tags))
                self._item_to_path[item_id] = r['path']
                self._item_to_raw_size[item_id] = r.get('raw_size', 0)
        else:
            dirs = {}
            for r in sorted_records:
                p = r['path']
                parts = p.split('/')
                fname = parts[-1]
                curr, parent = "", ""
                for i, part in enumerate(parts[:-1]):
                    if i == 0:
                        curr = part
                        if curr not in dirs:
                            dirs[curr] = self.tree.insert("", "end", text=part, values=("", "", "", "", ""))
                        parent = dirs[curr]
                    else:
                        parent = dirs[curr]
                        curr = f"{curr}/{part}"
                        if curr not in dirs:
                            dirs[curr] = self.tree.insert(parent, "end", text=part, values=("", "", "", "", ""))
                        parent = dirs[curr]

                vals = (r['status'], r['size_str'], r['mod_str'], r['encrypted'], r['cloud_name'])
                tags = [r['status'].lower().replace(" ", "_")]
                if r['encrypted'] == "No":
                    tags.append("unencrypted")

                if parts[:-1]:
                    item_id = self.tree.insert(parent, "end", text=fname, values=vals, tags=tuple(tags))
                else:
                    item_id = self.tree.insert("", "end", text=fname, values=vals, tags=tuple(tags))
                self._item_to_path[item_id] = p
                self._item_to_raw_size[item_id] = r.get('raw_size', 0)

            # Compute cumulative folder sizes for files in them and all subfolders
            dir_sizes = {}
            for r in sorted_records:
                p = r['path']
                raw_sz = r.get('raw_size', 0)
                parts = p.split('/')
                curr = ""
                for part in parts[:-1]:
                    curr = f"{curr}/{part}" if curr else part
                    dir_sizes[curr] = dir_sizes.get(curr, 0) + raw_sz

            # Update directory cumulative size and aggregated statuses
            for curr, dir_item in dirs.items():
                self._item_to_path[dir_item] = curr
                cum_size = dir_sizes.get(curr, 0)
                self.tree.set(dir_item, "size", self.format_size(cum_size))
                status = self.get_directory_status(dir_item)
                if status:
                    self.tree.set(dir_item, "status", status)

        # Update filter count label and status bar
        filter_status = self.filter_status_var.get()
        if hasattr(self, 'filter_count_label'):
            if len(sorted_records) != len(all_records):
                self.filter_count_label.config(text=f"Showing {len(sorted_records)} of {len(all_records)} files (filtered)")
            else:
                self.filter_count_label.config(text=f"Total: {len(all_records)} files")

        cache_note = " (cached)" if self.cloud_cache_timestamp else ""
        self.status_var.set(
            f"Local: {len(self.local_files)} | Cloud: {len(self.cloud_files)}{cache_note} | Showing: {len(sorted_records)} files"
        )

    def format_size(self, b):
        if b is None:
            return "0 B"
        for u in ['B', 'KB', 'MB', 'GB']:
            if b < 1024:
                return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    def get_directory_status(self, item):
        """Get the common status of all files in this directory, or empty if mixed."""
        statuses = set()
        for child in self.tree.get_children(item):
            if self.tree.get_children(child):
                sub_status = self.get_directory_status(child)
                if sub_status:
                    statuses.add(sub_status)
                else:
                    return ""
            else:
                status = self.tree.item(child, "values")[0]
                if status:
                    statuses.add(status)
        if len(statuses) == 1:
            return next(iter(statuses))
        return ""

    def get_directory_size(self, item) -> int:
        """Get the cumulative size in bytes of all files in this directory and all subfolders."""
        total = 0
        for child in self.tree.get_children(item):
            if self.tree.get_children(child):
                total += self.get_directory_size(child)
            else:
                total += self._item_to_raw_size.get(child, 0)
        return total

    def get_all_descendants(self, item):
        res = []
        for child in self.tree.get_children(item):
            if not self.tree.get_children(child):
                if self.tree.item(child, "values")[0]:
                    res.append(child)
            else:
                res.extend(self.get_all_descendants(child))
        return res

    def get_path(self, item):
        """Retrieve the canonical file path for a selected tree item."""
        if hasattr(self, '_item_to_path') and item in self._item_to_path:
            return self._item_to_path[item]
        parts = []
        cur = item
        while cur:
            parts.insert(0, self.tree.item(cur, "text"))
            cur = self.tree.parent(cur)
        return '/'.join(parts)

    def should_sync(self, path, status):
        if self.sync_mode == "local_to_cloud":
            return status in ["Local only", "Modified"] and path in self.local_files
        else:
            if status == "Local only" and path in self.local_files:
                return True
            if status == "Cloud only" and path in self.cloud_files:
                return True
            if status == "Modified" and path in self.local_files:
                return True
        return False

    def is_modified(self, p):
        if p not in self.cloud_files:
            return True
        ls = self.local_files[p]['size']
        cs = self.cloud_files[p]['size']
        if self.cloud_files[p].get('is_encrypted'):
            return cs != ls + 16
        return cs != ls

    # --- UNENCRYPTED UPLOAD CONFIRMATION WARNING ---

    def confirm_unencrypted_upload_if_needed(self, files_to_sync: list) -> bool:
        """
        SECURITY CHECK:
        If no encryption key is loaded, and any file in the sync list is a local upload,
        show a prominent warning box. Return True if user accepts, False to cancel.
        """
        if self.encryption_key is not None:
            return True  # Safe! AES-256 encryption is active

        # Check if any of the items are uploads (files present locally)
        uploads = [p for p in files_to_sync if p in self.local_files]
        if not uploads:
            return True  # Only downloads, no unencrypted upload occurring

        # Trigger security warning dialog
        warning_msg = (
            f"SECURITY ALERT: UNENCRYPTED UPLOAD\n\n"
            f"You are about to upload {len(uploads)} file(s) to Google Cloud Storage WITHOUT an encryption key!\n\n"
            f"⚠️ Your files will be transmitted and stored in PLAINTEXT.\n"
            f"⚠️ Anyone with bucket access or cloud administrators can inspect your data.\n\n"
            f"To secure your files, click 'No', then click 'Generate New Key' or 'Load Key from File'.\n\n"
            f"Do you really want to proceed with an UNENCRYPTED upload?"
        )

        if messagebox:
            proceed = messagebox.askyesno(
                "⚠️ Warning: Unencrypted Upload",
                warning_msg,
                icon="warning"
            )
        else:
            print(f"[SECURITY WARNING] {warning_msg}")
            proceed = True

        if not proceed:
            self.status_var.set("Sync cancelled: Upload aborted to prevent unencrypted transmission.")
            return False

        return True

    # --- SYNC ACTIONS & PAUSE / RESUME / CANCEL CONTROLS ---

    def toggle_pause_sync(self):
        """Pause or resume the active synchronization."""
        if not self.is_syncing:
            return

        if not self.is_paused:
            # User wants to PAUSE
            self.is_paused = True
            self.pause_event.clear()
            self.pause_button.config(text="▶️ Resume Sync")
            workers_str = f" ({self.active_workers_count} active workers)" if self.active_workers_count > 0 else ""
            self.status_var.set(f"⏸️ Pausing sync... cancelling in-flight file transfers{workers_str}. Press Resume to re-sync.")
            if hasattr(self, 'speed_var'):
                self.speed_var.set("Speed: ⏸️ PAUSED (0.0 KB/s)")
        else:
            # User wants to RESUME
            self.is_paused = False
            self.pause_event.set()
            self.pause_button.config(text="⏸️ Pause Sync")
            self.status_var.set(f"▶️ Resuming sync... continuing with {self.max_workers} worker threads.")

    def cancel_sync(self):
        """Cancel the ongoing sync entirely."""
        if not self.is_syncing:
            return
        self.is_cancelled = True
        self.is_paused = False
        self.pause_event.set()  # Unblock if paused
        self.status_var.set("⏹️ Cancelling sync operation...")
        if hasattr(self, 'pause_button'):
            self.pause_button.config(state=tk.DISABLED, text="⏸️ Pause Sync")
        if hasattr(self, 'cancel_button'):
            self.cancel_button.config(state=tk.DISABLED)

    def sync_selected_files(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Selection Required", "Please select at least one file or folder from the list to sync.")
            return

        files = []
        for item in sel:
            if self.tree.get_children(item):
                for fitem in self.get_all_descendants(item):
                    p = self.get_path(fitem)
                    st = self.tree.item(fitem, "values")[0]
                    if self.should_sync(p, st):
                        files.append(p)
            else:
                p = self.get_path(item)
                st = self.tree.item(item, "values")[0]
                if st and self.should_sync(p, st):
                    files.append(p)

        # De-duplicate
        files = list(dict.fromkeys(files))

        if not files:
            messagebox.showinfo("Nothing to Sync", "All selected items are already in sync.")
            return

        # Security check: prompt user if attempting unencrypted upload
        if not self.confirm_unencrypted_upload_if_needed(files):
            return

        t = threading.Thread(target=self.perform_sync, args=(files,))
        t.daemon = True
        t.start()

    def sync_all_missing_files(self):
        files = []
        if self.sync_mode == "local_to_cloud":
            for p in self.local_files:
                if p not in self.cloud_files or self.is_modified(p):
                    files.append(p)
        else:
            for p in self.local_files:
                if p not in self.cloud_files or self.is_modified(p):
                    files.append(p)
            for p in self.cloud_files:
                if p not in self.local_files:
                    files.append(p)

        # De-duplicate
        files = list(dict.fromkeys(files))

        if not files:
            messagebox.showinfo("Synced", "All files are currently synchronized.")
            return

        # Security check: prompt user if attempting unencrypted upload
        if not self.confirm_unencrypted_upload_if_needed(files):
            return

        t = threading.Thread(target=self.perform_sync, args=(files,))
        t.daemon = True
        t.start()

    def perform_sync(self, file_list):
        self.is_syncing = True
        self.is_paused = False
        self.is_cancelled = False
        self.pause_event.set()
        self.active_workers_count = 0

        # Update GUI controls on main thread
        self.master.after(0, lambda: [
            self.pause_button.config(state=tk.NORMAL, text="⏸️ Pause Sync"),
            self.cancel_button.config(state=tk.NORMAL),
            self.sync_button.config(state=tk.DISABLED),
            self.sync_all_button.config(state=tk.DISABLED),
            self.scan_button.config(state=tk.DISABLED)
        ])

        def check_interrupted():
            if self.is_cancelled:
                raise SyncCancelledException("Sync operation was cancelled by user.")
            if self.is_paused:
                raise SyncPausedException("Sync operation was paused by user.")

        try:
            total = len(file_list)
            # Calculate total sync bytes across all targets
            total_bytes = 0
            for fpath in file_list:
                if fpath in self.local_files:
                    fsize = self.local_files[fpath].get('size', 0)
                    total_bytes += fsize + (16 if self.encryption_key else 0)
                elif fpath in self.cloud_files:
                    total_bytes += self.cloud_files[fpath].get('size', 0)

            sync_start_time = time.time()
            transferred_bytes = 0
            upload_bytes = 0
            download_bytes = 0

            # Locks for concurrency safety
            progress_lock = threading.Lock()
            state_lock = threading.Lock()

            # Set of currently in-flight file paths across workers
            active_inflight_files = set()

            # Rolling window for responsive instantaneous upload/download speeds: (timestamp, bytes, is_upload)
            transfer_history = []

            self.progress['maximum'] = 100
            self.progress['value'] = 0
            cache_updated = False
            completed_count = 0

            def on_chunk_transferred(chunk_size: int, is_upload: bool):
                nonlocal transferred_bytes, upload_bytes, download_bytes, transfer_history
                now = time.time()
                with progress_lock:
                    transferred_bytes += chunk_size
                    if is_upload:
                        upload_bytes += chunk_size
                    else:
                        download_bytes += chunk_size

                    transfer_history.append((now, chunk_size, is_upload))
                    cutoff = now - 2.0
                    transfer_history = [item for item in transfer_history if item[0] >= cutoff]

                    up_window = sum(item[1] for item in transfer_history if item[2])
                    down_window = sum(item[1] for item in transfer_history if not item[2])
                    window_duration = max(0.2, now - transfer_history[0][0]) if transfer_history else 1.0

                    inst_up_speed = up_window / window_duration
                    inst_down_speed = down_window / window_duration

                    elapsed = max(0.1, now - sync_start_time)
                    overall_avg_speed = transferred_bytes / elapsed
                    remaining_bytes = max(0, total_bytes - transferred_bytes)

                    active_speed = (inst_up_speed + inst_down_speed) if (inst_up_speed + inst_down_speed) > 0 else overall_avg_speed
                    eta_seconds = (remaining_bytes / active_speed) if active_speed > 0 else 0

                    pct = min(100, int((transferred_bytes / total_bytes) * 100)) if total_bytes > 0 else 100
                    self.progress['value'] = pct

                    if hasattr(self, 'speed_var'):
                        self.speed_var.set(f"Speed: ↑ {format_transfer_speed(inst_up_speed)}  |  ↓ {format_transfer_speed(inst_down_speed)}")
                    if hasattr(self, 'time_var'):
                        self.time_var.set(f"Time: Elapsed: {format_time_duration(elapsed)}  |  ETA: {format_time_duration(eta_seconds)}")
                    if hasattr(self, 'volume_var'):
                        self.volume_var.set(f"Volume: {self.format_size(transferred_bytes)} / {self.format_size(total_bytes)} ({pct}%)")
                    self.master.update_idletasks()

            def transfer_single_file(fpath: str):
                """Worker function executed inside ThreadPoolExecutor to transfer one file."""
                nonlocal cache_updated, transferred_bytes, transfer_history
                temp_download_path = None
                file_start_bytes = 0

                with state_lock:
                    active_inflight_files.add(fpath)
                    self.active_workers_count = len(active_inflight_files)
                    self.current_syncing_file = next(iter(active_inflight_files), fpath)
                    cur_active_list = list(active_inflight_files)

                # Update live status bar with active workers summary
                workers_summary = f"{len(cur_active_list)} active in parallel" if len(cur_active_list) > 1 else cur_active_list[0]
                self.master.after(0, lambda: self.status_var.set(
                    f"Syncing [{completed_count + 1}/{total}] ({workers_summary}): {fpath}"
                ))

                try:
                    check_interrupted()

                    # --- UPLOAD ---
                    if fpath in self.local_files:
                        local_full = os.path.join(self.local_dir, fpath)
                        blob_name = self.encrypt_filename(fpath) if self.encryption_key else fpath
                        blob = self.bucket.blob(blob_name)

                        if self.encryption_key:
                            file_size = os.path.getsize(local_full)
                            with open(local_full, 'rb') as f:
                                enc_stream = EncryptedStreamAdapter(
                                    f, 
                                    self.encryption_key, 
                                    on_progress=lambda n: on_chunk_transferred(n, is_upload=True),
                                    check_interrupted=check_interrupted
                                )
                                blob.metadata = {
                                    'encryption': 'aes-stream',
                                    'encrypted_path': self.encrypt_metadata_path(fpath)
                                }
                                blob.upload_from_file(enc_stream, size=file_size + 16)
                        else:
                            file_size = os.path.getsize(local_full)
                            with open(local_full, 'rb') as f:
                                prog_stream = ProgressStreamAdapter(
                                    f, 
                                    on_progress=lambda n: on_chunk_transferred(n, is_upload=True),
                                    check_interrupted=check_interrupted
                                )
                                blob.upload_from_file(prog_stream, size=file_size)

                        blob.reload()
                        is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'
                        with state_lock:
                            self.cloud_files[fpath] = {
                                'size': blob.size,
                                'modified': blob.updated,
                                'is_encrypted': is_enc,
                                'blob_name': blob.name
                            }
                            cache_updated = True

                    # --- DOWNLOAD ---
                    elif fpath in self.cloud_files and self.sync_mode != "local_to_cloud":
                        local_full = os.path.join(self.local_dir, fpath)
                        os.makedirs(os.path.dirname(local_full), exist_ok=True)
                        temp_download_path = local_full + f".part.{os.getpid()}_{threading.get_ident()}"

                        with state_lock:
                            blob_name = self.cloud_files[fpath].get('blob_name', fpath)
                        blob = self.bucket.get_blob(blob_name)
                        if not blob:
                            print(f"Cloud blob not found: {blob_name}")
                            return False

                        is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'

                        if is_enc:
                            if not self.encryption_key:
                                print(f"Skipping {fpath}: Blob is encrypted but no key loaded.")
                                return False

                            with blob.open("rb") as gcs_stream:
                                check_interrupted()
                                nonce = gcs_stream.read(16)
                                on_chunk_transferred(len(nonce), is_upload=False)
                                if len(nonce) < 16:
                                    print(f"Corrupted file header for: {fpath}")
                                    return False

                                cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(nonce), backend=default_backend())
                                decryptor = cipher.decryptor()

                                with open(temp_download_path, 'wb') as dest_file:
                                    while True:
                                        check_interrupted()
                                        chunk = gcs_stream.read(64 * 1024)
                                        if not chunk:
                                            break
                                        dest_file.write(decryptor.update(chunk))
                                        on_chunk_transferred(len(chunk), is_upload=False)
                                    dest_file.write(decryptor.finalize())
                        else:
                            with blob.open("rb") as gcs_stream:
                                with open(temp_download_path, 'wb') as dest_file:
                                    while True:
                                        check_interrupted()
                                        chunk = gcs_stream.read(64 * 1024)
                                        if not chunk:
                                            break
                                        dest_file.write(chunk)
                                        on_chunk_transferred(len(chunk), is_upload=False)

                        if os.path.exists(temp_download_path):
                            if os.path.exists(local_full):
                                os.remove(local_full)
                            os.rename(temp_download_path, local_full)
                        temp_download_path = None

                        st = os.stat(local_full)
                        with state_lock:
                            self.local_files[fpath] = {
                                'path': local_full,
                                'size': st.st_size,
                                'modified': datetime.datetime.fromtimestamp(st.st_mtime)
                            }

                    return True

                except (SyncPausedException, SyncCancelledException):
                    if temp_download_path and os.path.exists(temp_download_path):
                        try:
                            os.remove(temp_download_path)
                        except Exception:
                            pass
                    raise

                except Exception as e:
                    print(f"Transfer error {fpath}: {e}")
                    if temp_download_path and os.path.exists(temp_download_path):
                        try:
                            os.remove(temp_download_path)
                        except Exception:
                            pass
                    return False

                finally:
                    with state_lock:
                        active_inflight_files.discard(fpath)
                        self.active_workers_count = len(active_inflight_files)
                        self.current_syncing_file = next(iter(active_inflight_files), None)

            # Concurrent transfer loop across ThreadPoolExecutor
            num_workers = max(1, min(16, getattr(self, 'max_workers', 4)))
            pending_queue = list(file_list)

            while pending_queue and not self.is_cancelled:
                # Wait if paused before dispatching next batch of workers
                if self.is_paused:
                    self.master.after(0, lambda: self.status_var.set("⏸️ Sync Paused. Click 'Resume Sync' to continue."))
                    if hasattr(self, 'speed_var'):
                        self.speed_var.set("Speed: ⏸️ PAUSED (0.0 KB/s)")
                    self.pause_event.wait()
                    if self.is_cancelled:
                        break

                current_batch = []
                # Pop next batch of tasks up to worker pool capacity
                batch_size = min(len(pending_queue), num_workers)
                for _ in range(batch_size):
                    if pending_queue:
                        current_batch.append(pending_queue.pop(0))

                with ThreadPoolExecutor(max_workers=len(current_batch), thread_name_prefix="GcsSyncWorker") as executor:
                    future_to_file = {executor.submit(transfer_single_file, f): f for f in current_batch}

                    for future in as_completed(future_to_file):
                        f = future_to_file[future]
                        try:
                            res = future.result()
                            if res:
                                completed_count += 1
                        except SyncPausedException:
                            # Re-queue interrupted file to re-sync from byte 0 when resumed
                            pending_queue.insert(0, f)
                            with progress_lock:
                                transfer_history = []
                            self.pause_event.wait()
                            if self.is_cancelled:
                                break
                        except SyncCancelledException:
                            break
                        except Exception as exc:
                            print(f"Worker exception for {f}: {exc}")

            # Update cache file if any changes were made
            if cache_updated:
                self.save_cloud_cache()

            total_elapsed = max(0.1, time.time() - sync_start_time)
            avg_speed = transferred_bytes / total_elapsed

            if self.is_cancelled:
                self.progress['value'] = 0
                if hasattr(self, 'speed_var'):
                    self.speed_var.set("Speed: 0.0 KB/s (Cancelled)")
                self.status_var.set(f"⏹️ Sync Cancelled by user. {completed_count} of {total} files completed.")
                self.master.after(0, lambda: [
                    self.update_file_list(),
                    messagebox.showinfo("Sync Cancelled", f"Sync was cancelled. {completed_count} of {total} files completed.")
                ])
            else:
                self.progress['value'] = 100
                if hasattr(self, 'speed_var'):
                    self.speed_var.set(f"Speed: Avg {format_transfer_speed(avg_speed)} (↑ {self.format_size(upload_bytes)} / ↓ {self.format_size(download_bytes)})")
                if hasattr(self, 'time_var'):
                    self.time_var.set(f"Time: Elapsed: {format_time_duration(total_elapsed)}  |  ETA: 00:00")
                if hasattr(self, 'volume_var'):
                    self.volume_var.set(f"Volume: {self.format_size(transferred_bytes)} processed")

                self.status_var.set(f"Sync Finished ({completed_count}/{total} files, {self.format_size(transferred_bytes)} in {format_time_duration(total_elapsed)} at {format_transfer_speed(avg_speed)} using {num_workers} parallel workers). Cloud cache updated.")
                self.master.after(0, lambda: [
                    self.update_file_list(),
                    messagebox.showinfo("Sync Finished", f"Processed {completed_count} items successfully ({self.format_size(transferred_bytes)} in {format_time_duration(total_elapsed)} with {num_workers} parallel workers).")
                ])

        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Sync Error", f"Sync failed:\n{err}"))
        finally:
            self.is_syncing = False
            self.is_paused = False
            self.is_cancelled = False
            self.current_syncing_file = None
            self.active_workers_count = 0
            self.progress['value'] = 0
            self.master.after(0, lambda: [
                self.pause_button.config(state=tk.DISABLED, text="⏸️ Pause Sync"),
                self.cancel_button.config(state=tk.DISABLED),
                self.sync_button.config(state=tk.NORMAL),
                self.sync_all_button.config(state=tk.NORMAL),
                self.scan_button.config(state=tk.NORMAL)
            ])


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("=" * 65)
        print("Encrypted Google Cloud Storage (GCS) Sync")
        print("=" * 65)
        print("Features:")
        print("  • AES-256 CTR Streaming Encryption on the fly")
        print("  • Cloud File Tree Disk Caching with instant startup")
        print("  • Manual Cloud Refresh Button (bypasses cache)")
        print("  • Prominent Warning Confirmation if uploading without encryption key")
        print("  • Two-way and Local-to-Cloud sync modes")
        print("\nUsage:")
        print("  python gcs_sync.py          # Launches desktop GUI")
        print("  python gcs_sync.py --help   # Displays this help message")
        print("=" * 65)
        return

    if tk is None:
        print("=" * 65)
        print("Encrypted Google Cloud Storage Sync")
        print("=" * 65)
        print("Notice: Tkinter graphical package is not installed in this environment.")
        print("On Debian/Ubuntu Linux, install it via:")
        print("  sudo apt-get install python3-tk")
        print("On macOS and Windows, Tkinter is included by default with python.org Python.")
        print("=" * 65)
        return

    try:
        root = tk.Tk()
        app = CloudStorageSync(root)
        root.mainloop()
    except Exception as e:
        print("=" * 65)
        print("Encrypted Google Cloud Storage Sync")
        print("=" * 65)
        print(f"Notice: Could not start GUI ({e}).")
        print("This application is a Tkinter desktop GUI app.")
        print("To run the GUI, launch it on your local desktop machine with Python 3.8+:")
        print("  pip install -r requirements.txt")
        print("  python gcs_sync.py")
        print("=" * 65)


if __name__ == "__main__":
    main()
