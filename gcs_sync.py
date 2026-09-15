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
import json
import pathlib
import datetime
import base64
import hmac
import hashlib
from typing import Dict, Optional, Any

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

class EncryptedStreamAdapter:
    """
    A file-like object that encrypts data on the fly.
    Fixes the 'Content-Range' size mismatch error by reporting correct tell() offset.
    Appends a 16-byte random IV/nonce at the beginning of the stream.
    """
    def __init__(self, source_file, key: bytes):
        if Cipher is None:
            raise RuntimeError("The 'cryptography' library is required for EncryptedStreamAdapter.")
        self.source_file = source_file
        self.key = key
        # Generate 16-byte IV (Nonce) for AES-CTR
        self.nonce = secrets.token_bytes(16)
        self.cipher = Cipher(algorithms.AES(key), modes.CTR(self.nonce), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self._nonce_sent = False

    def read(self, size=-1):
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
            return chunk

        # Read from the actual file
        # We read 'size' bytes (or all if -1)
        data = self.source_file.read(size)

        # If file is empty (EOF), just return whatever chunk we have (nonce or empty)
        if not data:
            return chunk

        # Encrypt and append to our chunk (nonce + encrypted_data)
        return chunk + self.encryptor.update(data)

    def tell(self):
        # CRITICAL FIX: Report the position of the *encrypted* stream (File + 16)
        # The GCS library uses this to verify upload integrity.
        offset = 16 if self._nonce_sent else 0
        return self.source_file.tell() + offset


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

        # Caching State
        self.cloud_cache_timestamp: Optional[str] = None
        self.config_file = "config.json"

        # History Lists for Previous Directories, Credentials, and Buckets
        self.history_local_dirs: list[str] = []
        self.history_credentials_paths: list[str] = []
        self.history_bucket_names: list[str] = []

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

        # --- Configuration ---
        config_frame = ttk.LabelFrame(main_frame, text="Configuration & Path History", padding="10")
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

        # Sync Mode
        ttk.Label(config_frame, text="Sync Mode:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=4)
        self.sync_mode_var = tk.StringVar(value="two_way")
        sync_mode_frame = ttk.Frame(config_frame)
        sync_mode_frame.grid(column=1, row=3, sticky=tk.W, padx=5, pady=4)
        ttk.Radiobutton(sync_mode_frame, text="Two-way Sync", variable=self.sync_mode_var, value="two_way").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(sync_mode_frame, text="Local to Cloud Only", variable=self.sync_mode_var, value="local_to_cloud").pack(side=tk.LEFT, padx=10)

        # --- Encryption Section ---
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption Management (AES-256 CTR Streaming)", padding="10")
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
        cache_frame = ttk.LabelFrame(main_frame, text="Cloud File Tree Cache", padding="8")
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
        exclusion_frame = ttk.LabelFrame(main_frame, text="Excluded Folders & Patterns", padding="8")
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

        # --- File List Treeview ---
        files_frame = ttk.LabelFrame(main_frame, text="Files", padding="8")
        files_frame.pack(fill=tk.BOTH, expand=True, pady=4)

        self.tree = ttk.Treeview(files_frame)
        self.tree["columns"] = ("status", "size", "last_modified", "encrypted", "cloud_name")
        self.tree.column("#0", width=300, minwidth=180)
        self.tree.column("status", width=110, minwidth=80)
        self.tree.column("size", width=85, minwidth=60)
        self.tree.column("last_modified", width=140, minwidth=110)
        self.tree.column("encrypted", width=80, minwidth=70)
        self.tree.column("cloud_name", width=280, minwidth=180)

        self.tree.heading("#0", text="File Path")
        self.tree.heading("status", text="Status")
        self.tree.heading("size", text="Size")
        self.tree.heading("last_modified", text="Last Modified")
        self.tree.heading("encrypted", text="Encrypted?")
        self.tree.heading("cloud_name", text="Cloud Name (Encrypted Blob)")

        scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Color tags for clear visual status in treeview
        self.tree.tag_configure("synced", foreground="#16a34a")        # Emerald Green
        self.tree.tag_configure("local_only", foreground="#0284c7")     # Sky Blue
        self.tree.tag_configure("cloud_only", foreground="#7c3aed")     # Violet / Purple
        self.tree.tag_configure("modified", foreground="#d97706")       # Amber
        self.tree.tag_configure("unencrypted", foreground="#dc2626")    # Red Warning

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

        # Status & Progress
        self.status_var = tk.StringVar(value="Ready. Connect to bucket or scan files to begin.")
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding="4")
        self.status_bar.pack(fill=tk.X, pady=4)

        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=2)

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

                # Check for existing cache
                if self.bucket_name:
                    self.load_cloud_cache()
        except FileNotFoundError:
            pass

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
            'history_local_dirs': self.history_local_dirs,
            'history_credentials_paths': self.history_credentials_paths,
            'history_bucket_names': self.history_bucket_names
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
            self.excluded_patterns.append(p)
            self.exclusion_listbox.insert(tk.END, p)

    def remove_exclusion(self):
        sel = self.exclusion_listbox.curselection()
        if sel:
            idx = sel[0]
            self.excluded_patterns.pop(idx)
            self.exclusion_listbox.delete(idx)

    def save_exclusions(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if f:
            with open(f, 'w', encoding="utf-8") as fh:
                json.dump(self.excluded_patterns, fh)
            messagebox.showinfo("Saved", "Exclusion patterns saved.")

    def load_exclusions(self):
        f = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if f:
            with open(f, 'r', encoding="utf-8") as fh:
                self.excluded_patterns = json.load(fh)
                self.exclusion_listbox.delete(0, tk.END)
                for p in self.excluded_patterns:
                    self.exclusion_listbox.insert(tk.END, p)

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
            # 1. Scan Local Directory
            self.status_var.set("Scanning Local Directory...")
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

            # 2. Scan Cloud (Check cache first unless force_refresh_cloud is True)
            has_cache = False
            if not force_refresh_cloud:
                has_cache = self.load_cloud_cache()

            if has_cache and not force_refresh_cloud:
                self.status_var.set(f"Loaded cloud files from cache ({len(self.cloud_files)} items)")
            else:
                self.status_var.set("Scanning Cloud Bucket (live query)...")
                self.master.update_idletasks()
                self.cloud_files = {}

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

                # Save new cloud file tree to disk cache
                self.save_cloud_cache()

            self.master.after(0, self.update_file_list)
        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Scan Error", f"Failed during file scan:\n{err}"))
        finally:
            self.is_scanning = False

    def update_file_list(self):
        self.tree.delete(*self.tree.get_children())
        if self.sync_mode == "local_to_cloud":
            paths = sorted(self.local_files.keys())
        else:
            paths = sorted(set(list(self.local_files.keys()) + list(self.cloud_files.keys())))

        dirs = {}
        for p in paths:
            enc_str = "No"
            cloud_name = ""
            if p in self.local_files and p in self.cloud_files:
                status = "Synced"
                if self.cloud_files[p].get('is_encrypted'):
                    enc_str = "Yes"
                cloud_name = self.cloud_files[p].get('blob_name', p)

                ls, cs = self.local_files[p]['size'], self.cloud_files[p]['size']
                if self.cloud_files[p].get('is_encrypted'):
                    # Encrypted file size has 16-byte nonce prepended
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
                cloud_name = self.cloud_files[p].get('blob_name', p)
                if self.sync_mode == "local_to_cloud":
                    continue

            if p in self.local_files:
                sz = self.format_size(self.local_files[p]['size'])
                mod = self.local_files[p]['modified'].strftime("%Y-%m-%d %H:%M")
            else:
                sz = self.format_size(self.cloud_files[p]['size'])
                cmod = self.cloud_files[p]['modified']
                mod = cmod.strftime("%Y-%m-%d %H:%M") if isinstance(cmod, (datetime.datetime, datetime.date)) else str(cmod) if cmod else "?"

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

            vals = (status, sz, mod, enc_str, cloud_name)
            tags = [status.lower().replace(" ", "_")]
            if enc_str == "No":
                tags.append("unencrypted")

            if parts[:-1]:
                self.tree.insert(parent, "end", text=fname, values=vals, tags=tuple(tags))
            else:
                self.tree.insert("", "end", text=fname, values=vals, tags=tuple(tags))

        # Update directory aggregated statuses
        for dir_item in dirs.values():
            status = self.get_directory_status(dir_item)
            if status:
                self.tree.set(dir_item, "status", status)

        cache_note = " (cached)" if self.cloud_cache_timestamp else ""
        self.status_var.set(f"Local: {len(self.local_files)} files | Cloud: {len(self.cloud_files)} files{cache_note}")

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

    # --- SYNC ACTIONS ---

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
        try:
            total = len(file_list)
            self.progress['maximum'] = total
            self.progress['value'] = 0
            cache_updated = False

            for i, fpath in enumerate(file_list):
                self.progress['value'] = i
                self.master.update_idletasks()

                # --- UPLOAD ---
                if fpath in self.local_files:
                    local_full = os.path.join(self.local_dir, fpath)
                    # Derive deterministic blob name when key is loaded
                    blob_name = self.encrypt_filename(fpath) if self.encryption_key else fpath
                    blob = self.bucket.blob(blob_name)

                    if self.encryption_key:
                        self.status_var.set(f"Encrypting & Uploading ({i+1}/{total}): {fpath}")
                        try:
                            file_size = os.path.getsize(local_full)
                            with open(local_full, 'rb') as f:
                                enc_stream = EncryptedStreamAdapter(f, self.encryption_key)
                                blob.metadata = {
                                    'encryption': 'aes-stream',
                                    'encrypted_path': self.encrypt_metadata_path(fpath)
                                }
                                # Size is original + 16 bytes for CTR nonce
                                blob.upload_from_file(enc_stream, size=file_size + 16)
                        except Exception as e:
                            print(f"Upload error {fpath}: {e}")
                            continue
                    else:
                        self.status_var.set(f"Uploading Unencrypted ({i+1}/{total}): {fpath}")
                        blob.upload_from_filename(local_full)

                    blob.reload()
                    is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'
                    self.cloud_files[fpath] = {
                        'size': blob.size,
                        'modified': blob.updated,
                        'is_encrypted': is_enc,
                        'blob_name': blob.name
                    }
                    cache_updated = True

                # --- DOWNLOAD ---
                elif fpath in self.cloud_files and self.sync_mode != "local_to_cloud":
                    self.status_var.set(f"Downloading ({i+1}/{total}): {fpath}")
                    local_full = os.path.join(self.local_dir, fpath)
                    os.makedirs(os.path.dirname(local_full), exist_ok=True)

                    blob_name = self.cloud_files[fpath].get('blob_name', fpath)
                    blob = self.bucket.get_blob(blob_name)
                    if not blob:
                        print(f"Cloud blob not found: {blob_name}")
                        continue

                    is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'

                    if is_enc:
                        if not self.encryption_key:
                            print(f"Skipping {fpath}: Blob is encrypted but no key loaded.")
                            continue

                        self.status_var.set(f"Decrypting & Streaming ({i+1}/{total}): {fpath}")

                        try:
                            with blob.open("rb") as gcs_stream:
                                nonce = gcs_stream.read(16)
                                if len(nonce) < 16:
                                    print(f"Corrupted file header for: {fpath}")
                                    continue

                                cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(nonce), backend=default_backend())
                                decryptor = cipher.decryptor()

                                with open(local_full, 'wb') as dest_file:
                                    while True:
                                        chunk = gcs_stream.read(64 * 1024)
                                        if not chunk:
                                            break
                                        dest_file.write(decryptor.update(chunk))
                                    dest_file.write(decryptor.finalize())
                        except Exception as e:
                            print(f"Decryption error {fpath}: {e}")
                            continue
                    else:
                        blob.download_to_filename(local_full)

                    st = os.stat(local_full)
                    self.local_files[fpath] = {
                        'path': local_full,
                        'size': st.st_size,
                        'modified': datetime.datetime.fromtimestamp(st.st_mtime)
                    }

            # Update cache file if any changes were made
            if cache_updated:
                self.save_cloud_cache()

            self.progress['value'] = total
            self.status_var.set(f"Sync Finished ({total} files processed). Cloud cache updated.")
            self.master.after(0, lambda: [
                self.update_file_list(),
                messagebox.showinfo("Sync Finished", f"Processed {total} items successfully.")
            ])

        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("Sync Error", f"Sync failed:\n{err}"))
        finally:
            self.progress['value'] = 0


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
