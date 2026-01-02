# Secure Cloud Storage Sync

![Status](https://img.shields.io/badge/Status-Vibe%20Coded-8A2BE2)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Security](https://img.shields.io/badge/Encryption-AES--256-green)

Want to use Google Cloud Storage (GCS) because it is awesome, but don't want Google to be able to sniff in your files? This is the solution.

A lightweight, secure, and GUI-based tool to synchronize local files with GCS. Designed to handle large files efficiently through streaming encryption and robust sync logic.

Files are unencrypted on your local drive and are encrypted before they are uploaded to GCS.

---

## 🚀 Features

* **Two-Way Sync:** Automatically detects missing or modified files in both your local folder and the cloud.
* **Local-to-Cloud Mode:** Optional backup mode that only pushes changes to the cloud (prevents local deletions).
* **Military-Grade Encryption:**
    * Uses **AES-256** in **CTR (Counter) Mode**.
    * **Streaming Support:** Encrypts and uploads gigabyte-sized files on the fly without eating up RAM.
    * **Unique IVs:** Generates a random Initialization Vector (Nonce) for every file to prevent pattern analysis.
* **Smart Selection:**
    * Select specific files or entire folders to force-sync.
    * Recursive folder scanning.
    * File exclusion system (ignore `.git`, `__pycache__`, etc.).
* **Visual Interface:** Built with `tkinter` for a clean, no-nonsense desktop experience.

---

## 🛠️ Prerequisites

1.  **Python 3.8+** installed on your system.
2.  **Google Cloud Platform (GCP) Account**:
    * A created Storage Bucket.
    * A Service Account with `Storage Object Admin` permissions.
    * A JSON credentials file for that Service Account.

---

## 📦 Installation

1.  **Clone or Download** this repository.
2.  **Install Dependencies**:
    The app requires the Google Cloud Storage client and the Cryptography library.

    ```bash
    pip install google-cloud-storage cryptography
    ```

---

## 🎮 Usage Guide

### 1. Configuration
* **Local Directory:** Browse to the folder you want to sync.
* **GCS Credentials:** Select your `.json` Service Account key.
* **Bucket Name:** Type the exact name of your GCS bucket.
* Click **Connect**.

### 2. Encryption (Important!)
Before scanning or syncing, decide on your security strategy:
* **Generate New Key:** Creates a fresh 32-byte AES key. **Save this file immediately!**
* **Load Key:** Load a previously saved `.key` file.
* *Note: If you upload files with a key, you MUST have that same key loaded to download/decrypt them later. If you lose the key, the data is unrecoverable.*
* **If no key is used, the data is uploaded unencrypted**

### 3. Scanning & Syncing
* **Scan Files:** Compares your local folder against the cloud bucket.
* **The List:**
    * **Status:** Shows if a file is `Synced`, `Modified`, `Local only`, or `Cloud only`.
    * **Encrypted:** Shows `Yes` if the cloud version is encrypted.
* **Sync:**
    * **Sync All Missing:** Automatically processes all differences.
    * **Sync Selected:** Highlight specific files/folders to force a sync (useful for fixing errors).

---

## 🔐 Technical Security Details

This application implements a **Stream Adapter** pattern to handle cryptography:

* **Algorithm:** AES-256 (Advanced Encryption Standard).
* **Mode:** CTR (Counter Mode). This turns the block cipher into a stream cipher, allowing us to encrypt byte-by-byte as we upload.
* **Integrity:** The `tell()` method in the stream adapter is offset-adjusted to ensure Google Cloud's resumable upload validation succeeds (preventing `400 Bad Request` errors on large files).
* **Metadata:** Encrypted files are tagged with `metadata={'encryption': 'aes-stream'}` in the cloud, so the app knows to verify and decrypt them upon download.

---

## ⚠️ Disclaimer

This software was **vibe coded**. While it uses standard cryptographic libraries (`cryptography.io`) and robust logic, it is provided "as is". Always backup your encryption keys and don't use this tool with state secrets lol.
