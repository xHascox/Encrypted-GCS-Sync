import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
from google.cloud import storage
from google.oauth2 import service_account
import json
import pathlib
import datetime
import base64
from typing import Dict, Optional

# --- CRYPTOGRAPHY IMPORTS ---
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    import secrets
except ImportError:
    tk.messagebox.showerror("Dependency Error", "Please install the cryptography library:\npip install cryptography")
    exit()

class EncryptedStreamAdapter:
    """
    A file-like object that encrypts data on the fly.
    Fixes the 'Content-Range' size mismatch error by reporting correct tell() offset.
    """
    def __init__(self, source_file, key):
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
    def __init__(self, master):
        self.master = master
        master.title("Google Cloud Storage Sync (Streaming Encryption)")
        master.geometry("950x850")
        
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
        self.encryption_key = None  # Raw bytes (32 bytes for AES-256)
        
        self.create_ui()
    
    def create_ui(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- Configuration ---
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        
        # Local Dir
        ttk.Label(config_frame, text="Local Directory:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.local_dir_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.local_dir_var, width=50).grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Button(config_frame, text="Browse...", command=self.browse_directory).grid(column=2, row=0, padx=5, pady=5)
        
        # Credentials
        ttk.Label(config_frame, text="GCS Credentials:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        self.credentials_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.credentials_var, width=50).grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(config_frame, text="Browse...", command=self.browse_credentials).grid(column=2, row=1, padx=5, pady=5)
        
        # Bucket
        ttk.Label(config_frame, text="Bucket Name:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        self.bucket_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.bucket_var, width=50).grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        ttk.Button(config_frame, text="Connect", command=self.connect_to_gcs).grid(column=2, row=2, padx=5, pady=5)
        
        # Sync Mode
        ttk.Label(config_frame, text="Sync Mode:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)
        self.sync_mode_var = tk.StringVar(value="two_way")
        sync_mode_frame = ttk.Frame(config_frame)
        sync_mode_frame.grid(column=1, row=3, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(sync_mode_frame, text="Two-way Sync", variable=self.sync_mode_var, value="two_way").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(sync_mode_frame, text="Local to Cloud Only", variable=self.sync_mode_var, value="local_to_cloud").pack(side=tk.LEFT, padx=10)

        # --- Encryption Section ---
        enc_frame = ttk.LabelFrame(main_frame, text="Encryption Management (AES-256 Streaming)", padding="10")
        enc_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(enc_frame, text="Current Key Status:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.key_status_var = tk.StringVar(value="No Key Loaded - Files will be uploaded unencrypted")
        self.key_status_label = ttk.Label(enc_frame, textvariable=self.key_status_var, foreground="red", font=("TkDefaultFont", 9, "bold"))
        self.key_status_label.grid(column=1, row=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        btn_frame = ttk.Frame(enc_frame)
        btn_frame.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="Generate New Key", command=self.generate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load Key from File", command=self.load_key_from_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Current Key", command=self.save_key_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Unload Key", command=self.unload_key).pack(side=tk.LEFT, padx=5)

        # --- Exclusions ---
        exclusion_frame = ttk.LabelFrame(main_frame, text="Excluded Folders", padding="10")
        exclusion_frame.pack(fill=tk.X, pady=5)
        
        self.exclusion_listbox = tk.Listbox(exclusion_frame, height=3)
        self.exclusion_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        exclusion_scrollbar = ttk.Scrollbar(exclusion_frame, orient="vertical", command=self.exclusion_listbox.yview)
        self.exclusion_listbox.configure(yscrollcommand=exclusion_scrollbar.set)
        exclusion_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        exclusion_buttons_frame = ttk.Frame(exclusion_frame)
        exclusion_buttons_frame.pack(fill=tk.X, pady=5)
        ttk.Button(exclusion_buttons_frame, text="Add Exclusion", command=self.add_exclusion).pack(side=tk.LEFT, padx=5)
        ttk.Button(exclusion_buttons_frame, text="Remove Selected", command=self.remove_exclusion).pack(side=tk.LEFT, padx=5)
        ttk.Button(exclusion_buttons_frame, text="Save Exclusions", command=self.save_exclusions).pack(side=tk.LEFT, padx=5)
        ttk.Button(exclusion_buttons_frame, text="Load Exclusions", command=self.load_exclusions).pack(side=tk.LEFT, padx=5)
        
        # --- File List ---
        files_frame = ttk.LabelFrame(main_frame, text="Files", padding="10")
        files_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.tree = ttk.Treeview(files_frame)
        self.tree["columns"] = ("status", "size", "last_modified", "encrypted")
        self.tree.column("#0", width=300, minwidth=200)
        self.tree.column("status", width=100)
        self.tree.column("size", width=80)
        self.tree.column("last_modified", width=150)
        self.tree.column("encrypted", width=80)
        
        self.tree.heading("#0", text="File Path")
        self.tree.heading("status", text="Status")
        self.tree.heading("size", text="Size")
        self.tree.heading("last_modified", text="Last Modified")
        self.tree.heading("encrypted", text="Encrypted?")
        
        scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # --- Actions ---
        actions_frame = ttk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, pady=5)
        
        self.scan_button = ttk.Button(actions_frame, text="Scan Files", command=self.scan_files)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        self.sync_button = ttk.Button(actions_frame, text="Sync Selected Files", command=self.sync_selected_files)
        self.sync_button.pack(side=tk.LEFT, padx=5)
        self.sync_button.config(state=tk.DISABLED)
        self.sync_all_button = ttk.Button(actions_frame, text="Sync All Missing Files", command=self.sync_all_missing_files)
        self.sync_all_button.pack(side=tk.LEFT, padx=5)
        self.sync_all_button.config(state=tk.DISABLED)
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, pady=5)
        
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

    # --- CRYPTO HELPERS ---

    def generate_key(self):
        """Generate a secure 32-byte key for AES-256."""
        try:
            # Generate 32 bytes
            key = secrets.token_bytes(32)
            self.set_encryption_key(key)
            
            # Show the Base64 representation to user just for info, but we store raw bytes
            b64_key = base64.urlsafe_b64encode(key).decode()
            messagebox.showinfo("Success", f"New key generated!\n\nSave this key. If lost, data is unrecoverable.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")

    def load_key_from_file(self):
        filename = filedialog.askopenfilename(title="Load Encryption Key", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "rb") as key_file:
                    encoded_key = key_file.read().strip()
                
                # We expect the file to contain base64 encoded key (standard practice for user handling)
                try:
                    key = base64.urlsafe_b64decode(encoded_key)
                except:
                    # Fallback if user saved raw bytes
                    key = encoded_key
                    
                if len(key) != 32:
                    messagebox.showerror("Error", f"Invalid key length: {len(key)} bytes. AES-256 requires 32 bytes.")
                    return

                self.set_encryption_key(key)
                messagebox.showinfo("Success", "Encryption key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")

    def save_key_to_file(self):
        if not self.encryption_key:
            messagebox.showwarning("Warning", "No key loaded.")
            return
        filename = filedialog.asksaveasfilename(title="Save Encryption Key", defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if filename:
            try:
                with open(filename, "wb") as key_file:
                    # Save as base64 for better portability
                    key_file.write(base64.urlsafe_b64encode(self.encryption_key))
                messagebox.showinfo("Success", f"Key saved to {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")

    def unload_key(self):
        self.encryption_key = None
        self.key_status_var.set("No Key Loaded - Files will be uploaded unencrypted")
        self.key_status_label.config(foreground="red")

    def set_encryption_key(self, key):
        self.encryption_key = key
        b64_preview = base64.urlsafe_b64encode(key).decode()
        preview = b64_preview[:5] + "..." + b64_preview[-5:]
        self.key_status_var.set(f"Active Key: {preview} (Streaming AES-256)")
        self.key_status_label.config(foreground="green")

    # --- MAIN LOGIC ---

    def browse_directory(self):
        d = filedialog.askdirectory()
        if d: self.local_dir_var.set(d); self.local_dir = d
    
    def browse_credentials(self):
        f = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if f: self.credentials_var.set(f); self.credentials_path = f

    def add_exclusion(self):
        p = simpledialog.askstring("Add Exclusion", "Pattern (e.g. 'temp', '.git')")
        if p: self.excluded_patterns.append(p); self.exclusion_listbox.insert(tk.END, p)
    
    def remove_exclusion(self):
        sel = self.exclusion_listbox.curselection()
        if sel: self.excluded_patterns.pop(sel[0]); self.exclusion_listbox.delete(sel[0])

    def save_exclusions(self):
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if f: 
            with open(f, 'w') as fh: json.dump(self.excluded_patterns, fh)

    def load_exclusions(self):
        f = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if f:
            with open(f, 'r') as fh:
                self.excluded_patterns = json.load(fh)
                self.exclusion_listbox.delete(0, tk.END)
                for p in self.excluded_patterns: self.exclusion_listbox.insert(tk.END, p)

    def is_excluded(self, path):
        for p in self.excluded_patterns:
            if path.startswith(p + '/') or ('/' + p + '/') in path or path == p: return True
        return False
    
    def connect_to_gcs(self):
        self.bucket_name = self.bucket_var.get().strip()
        if not self.credentials_path or not self.bucket_name:
            messagebox.showerror("Error", "Missing credentials or bucket name.")
            return
        
        try:
            self.status_var.set("Connecting...")
            self.master.update_idletasks()
            creds = service_account.Credentials.from_service_account_file(self.credentials_path)
            self.gcs_client = storage.Client(credentials=creds)
            try:
                self.bucket = self.gcs_client.get_bucket(self.bucket_name)
                self.status_var.set(f"Connected: {self.bucket_name}")
                messagebox.showinfo("Success", f"Connected to {self.bucket_name}")
                self.sync_button.config(state=tk.NORMAL)
                self.sync_all_button.config(state=tk.NORMAL)
            except Exception as e:
                messagebox.showerror("Error", f"Bucket error: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Client error: {e}")

    def scan_files(self):
        if not self.local_dir or not self.bucket: return
        self.sync_mode = self.sync_mode_var.get()
        self.tree.delete(*self.tree.get_children())
        self.is_scanning = True
        t = threading.Thread(target=self.perform_scan)
        t.daemon = True; t.start()

    def perform_scan(self):
        try:
            self.status_var.set("Scanning Local...")
            self.master.update_idletasks()
            self.local_files = {}
            lp = pathlib.Path(self.local_dir)
            for p in lp.rglob('*'):
                if p.is_file():
                    rp = str(p.relative_to(lp)).replace('\\', '/')
                    if self.is_excluded(rp): continue
                    self.local_files[rp] = {
                        'path': str(p), 'size': p.stat().st_size,
                        'modified': datetime.datetime.fromtimestamp(p.stat().st_mtime)
                    }
            
            self.status_var.set("Scanning Cloud...")
            self.master.update_idletasks()
            self.cloud_files = {}
            for b in self.bucket.list_blobs():
                if self.is_excluded(b.name): continue
                is_enc = b.metadata and b.metadata.get('encryption') == 'aes-stream'
                self.cloud_files[b.name] = {'size': b.size, 'modified': b.updated, 'is_encrypted': is_enc}
            
            self.master.after(0, self.update_file_list)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
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
            if p in self.local_files and p in self.cloud_files:
                status = "Synced"
                if self.cloud_files[p].get('is_encrypted'): enc_str = "Yes"
                # Size check is tricky with encryption (overhead is just 16 bytes for IV)
                ls, cs = self.local_files[p]['size'], self.cloud_files[p]['size']
                if self.cloud_files[p].get('is_encrypted'):
                    # Encrypted size = Original + 16 bytes IV
                    if cs != ls + 16: status = "Modified"
                else:
                    if cs != ls: status = "Modified"
            elif p in self.local_files:
                status = "Local only"
            else:
                status = "Cloud only"
                if self.cloud_files[p].get('is_encrypted'): enc_str = "Yes"
                if self.sync_mode == "local_to_cloud": continue
            
            if p in self.local_files:
                sz = self.format_size(self.local_files[p]['size'])
                mod = self.local_files[p]['modified'].strftime("%Y-%m-%d %H:%M")
            else:
                sz = self.format_size(self.cloud_files[p]['size'])
                mod = self.cloud_files[p]['modified'].strftime("%Y-%m-%d %H:%M") if self.cloud_files[p]['modified'] else "?"
            
            parts = p.split('/')
            fname = parts[-1]
            curr, parent = "", ""
            for i, part in enumerate(parts[:-1]):
                if i==0:
                    curr = part
                    if curr not in dirs: dirs[curr] = self.tree.insert("", "end", text=part, values=("","","",""))
                    parent = dirs[curr]
                else:
                    parent_path = curr
                    curr = f"{curr}/{part}"
                    if curr not in dirs: dirs[curr] = self.tree.insert(parent, "end", text=part, values=("","","",""))
                    parent = dirs[curr]
            
            vals = (status, sz, mod, enc_str)
            if parts[:-1]: self.tree.insert(parent, "end", text=fname, values=vals)
            else: self.tree.insert("", "end", text=fname, values=vals)
            
        self.status_var.set(f"Local: {len(self.local_files)} | Cloud: {len(self.cloud_files)}")

    def format_size(self, b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"

    def get_all_descendants(self, item):
        res = []
        for child in self.tree.get_children(item):
            if not self.tree.get_children(child):
                if self.tree.item(child, "values")[0]: res.append(child)
            else: res.extend(self.get_all_descendants(child))
        return res
    
    def get_path(self, item):
        parts = []
        cur = item
        while cur:
            parts.insert(0, self.tree.item(cur, "text"))
            cur = self.tree.parent(cur)
        return '/'.join(parts)

    def sync_selected_files(self):
        sel = self.tree.selection()
        if not sel: return
        files = []
        for item in sel:
            if self.tree.get_children(item):
                for fitem in self.get_all_descendants(item):
                    p = self.get_path(fitem)
                    st = self.tree.item(fitem, "values")[0]
                    if self.should_sync(p, st): files.append(p)
            else:
                p = self.get_path(item)
                st = self.tree.item(item, "values")[0]
                if st and self.should_sync(p, st): files.append(p)
        
        if not files:
            messagebox.showinfo("Info", "Nothing to sync.")
            return
        t = threading.Thread(target=self.perform_sync, args=(files,))
        t.daemon = True; t.start()

    def should_sync(self, path, status):
        if self.sync_mode == "local_to_cloud":
            return status in ["Local only", "Modified"] and path in self.local_files
        else:
            if status == "Local only" and path in self.local_files: return True
            if status == "Cloud only" and path in self.cloud_files: return True
            if status == "Modified" and path in self.local_files: return True
        return False
    
    def sync_all_missing_files(self):
        files = []
        # Logic simplified for brevity, essentially checking lists
        if self.sync_mode == "local_to_cloud":
            for p in self.local_files:
                if p not in self.cloud_files or self.is_modified(p): files.append(p)
        else:
            for p in self.local_files:
                if p not in self.cloud_files or self.is_modified(p): files.append(p)
            for p in self.cloud_files:
                if p not in self.local_files: files.append(p)
        
        if not files: messagebox.showinfo("Done", "Already synced."); return
        t = threading.Thread(target=self.perform_sync, args=(files,))
        t.daemon = True; t.start()

    def is_modified(self, p):
        # Helper to check modification considering encryption overhead
        if p not in self.cloud_files: return True
        ls = self.local_files[p]['size']
        cs = self.cloud_files[p]['size']
        if self.cloud_files[p].get('is_encrypted'):
            return cs != ls + 16
        return cs != ls

    def perform_sync(self, file_list):
        try:
            total = len(file_list)
            self.progress['maximum'] = total
            self.progress['value'] = 0
            
            for i, fpath in enumerate(file_list):
                self.progress['value'] = i
                self.master.update_idletasks()
                
                # --- UPLOAD ---
                if fpath in self.local_files:
                    local_full = os.path.join(self.local_dir, fpath)
                    blob = self.bucket.blob(fpath)
                    
                    if self.encryption_key:
                        self.status_var.set(f"Encrypting/Uploading {i+1}/{total}: {fpath}")
                        try:
                            file_size = os.path.getsize(local_full)
                            with open(local_full, 'rb') as f:
                                # Wrap file in encryption stream
                                enc_stream = EncryptedStreamAdapter(f, self.encryption_key)
                                # Set metadata
                                blob.metadata = {'encryption': 'aes-stream'}
                                # Upload via stream
                                blob.upload_from_file(enc_stream, size=file_size + 16)
                        except Exception as e:
                            print(f"Upload error {fpath}: {e}")
                            continue
                    else:
                        self.status_var.set(f"Uploading {i+1}/{total}: {fpath}")
                        blob.upload_from_filename(local_full)
                    
                    blob.reload()
                    is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'
                    self.cloud_files[fpath] = {'size': blob.size, 'modified': blob.updated, 'is_encrypted': is_enc}

                # --- DOWNLOAD ---
                elif fpath in self.cloud_files and self.sync_mode != "local_to_cloud":
                    self.status_var.set(f"Downloading {i+1}/{total}: {fpath}")
                    local_full = os.path.join(self.local_dir, fpath)
                    os.makedirs(os.path.dirname(local_full), exist_ok=True)
                    
                    blob = self.bucket.get_blob(fpath)
                    is_enc = blob.metadata and blob.metadata.get('encryption') == 'aes-stream'
                    
                    if is_enc:
                        if not self.encryption_key:
                            print(f"Skipping {fpath}: Encrypted but no key loaded.")
                            continue
                        
                        self.status_var.set(f"Decrypting {i+1}/{total}: {fpath}")
                        
                        # Streaming Download & Decrypt
                        try:
                            # Open stream from GCS
                            with blob.open("rb") as gcs_stream:
                                # Read IV (first 16 bytes)
                                nonce = gcs_stream.read(16)
                                if len(nonce) < 16:
                                    print(f"File too short: {fpath}")
                                    continue
                                
                                # Init Cipher
                                cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(nonce), backend=default_backend())
                                decryptor = cipher.decryptor()
                                
                                # Stream remaining data
                                with open(local_full, 'wb') as dest_file:
                                    while True:
                                        chunk = gcs_stream.read(64 * 1024) # 64KB chunks
                                        if not chunk: break
                                        dest_file.write(decryptor.update(chunk))
                                    dest_file.write(decryptor.finalize())
                        except Exception as e:
                            print(f"Decryption error {fpath}: {e}")
                            continue
                    else:
                        # Standard download
                        blob.download_to_filename(local_full)
                    
                    st = os.stat(local_full)
                    self.local_files[fpath] = {
                        'path': local_full, 'size': st.st_size,
                        'modified': datetime.datetime.fromtimestamp(st.st_mtime)
                    }

            self.progress['value'] = total
            self.status_var.set("Sync Complete")
            self.master.after(0, lambda: [self.update_file_list(), messagebox.showinfo("Success", "Sync Finished")])
            
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Sync failed: {str(e)}"))
        finally:
            self.progress['value'] = 0

def main():
    root = tk.Tk()
    app = CloudStorageSync(root)
    root.mainloop()

if __name__ == "__main__":
    main()
