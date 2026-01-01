
```markdown
# Mass YARA Scanner v50 (Multiprocessing Edition)

**Mass YARA Scanner** is a high-performance, multi-threaded, cross-platform forensic triage tool designed for Incident Response. It performs Disk and Process Memory scanning using a pure YARA engine approach, robust logging, and smart noise reduction features.
It solves the common limitation of the standard `yara` CLI by allowing you to **compile and run an entire directory of rules** simultaneously against **Disk or Memory**, without needing to manually merge rule files.

Unlike standard YARA wrappers, this tool is architected for **speed and stability** on live systems. It utilizes a **Producer/Consumer multiprocessing model** to saturate available CPU cores, smart "Drop Zone" prioritization to find malware faster, and robust safety mechanisms (Inode tracking, Memory limits) to prevent system instability during scans.


> ✨ **Proudly developed by Vibe Coding.**
> (Optimized for vibes, speed, and catch rates.)

## ⚡ Key Features

* **Multiprocessing Engine:** Automatically spawns worker processes (defaults to `CPU Count - 1`) to scan files in parallel. Includes a "Handshake" mechanism to prevent deadlocks.
  * **Pure YARA Engine:** Focused solely on deterministic content matching.
* **"Drop Zone" Priority:** Scans high-risk paths first (e.g., `Downloads`, `Temp`, `AppData`, `/tmp`, `/dev/shm`) before crawling the rest of the disk.
* **Memory Safety:** Explicit garbage collection and file size limits (`--max-size`) to prevent Out-Of-Memory (OOM) crashes on large datasets.
* **Dual Reporting:**
    * **JSONL:** Machine-readable logs for SIEM ingestion (Splunk/ELK).
    * **HTML Dashboard:** A standalone, dark-mode report with JavaScript-powered statistics and noise filtering.
* **Live System Safety:** `--low-priority` mode pins the tool to a single CPU core and drops process priority to `IDLE` to safely scan production servers.

---

##  🔧 Technical Deep Dive: Priority Drop Zones
The "Drop Zone" logic is not just a hardcoded list of paths; it is a dynamic, scope-aware pre-fetch mechanism designed to maximize the probability of early detection.

Wildcard Expansion: The scanner maintains a platform-specific map of high-risk patterns containing wildcards (e.g., C:\Users\*\Downloads on Windows or /home/*/.ssh on Linux). At runtime, these are expanded using glob to identify actual existing directories on the system.

Strict Scope Enforcement (The "Containment" Check): To prevent "scope leakage," the scanner strictly enforces that a Drop Zone must be a child of the user-provided target path (-p).

Scenario A: You scan -p C:\. The pattern C:\Users\*\Downloads expands to all user download folders. Since these are children of C:\, they are added to the Phase 1 priority queue.

Scenario B: You scan -p C:\Users\Alice. The pattern C:\Users\*\Downloads might find C:\Users\Bob\Downloads. The scanner detects that Bob is outside the scope of Alice and silently discards that path.

Result: You never scan files outside the directory tree you explicitly targeted, even if they are in the global priority list.

Phase 2 Deduplication: Directories scanned in Phase 1 are added to a processed_dirs set (normalized absolute paths). When Phase 2 begins the general os.walk() of the target root, it checks every directory against this set. If a directory was already handled in Phase 1, the walker prunes that branch of the tree immediately, ensuring zero redundant I/O operations.

---

## 🛠️ Installation

### Prerequisites

You need Python 3.8+ installed.

```bash
# Windows
pip install yara-python psutil colorama

# Linux (Ensure libyara is installed first)
sudo apt install libyara-dev
pip install yara-python psutil colorama

```

### Compilation (Building the Binary)

To deploy this on a target machine without installing Python, compile it into a standalone executable.

**Windows:**
*(Requires [Visual C++ Build Tools](https://www.google.com/search?q=https://visualstudio.microsoft.com/visual-cpp-build-tools/))*

```bash
pyinstaller --onefile --clean --name "MassYara_Win" mass_yara_multi_process.py

```

**Linux:**

```bash
pyinstaller --onefile --clean --name "MassYara_Linux" mass_yara_multi_process.py

```

**macOS:**

```bash
pyinstaller --onefile --clean --name "MassYara_Mac" mass_yara.py
```

---

## 🚀 Usage

**Note:** Requires `Administrator` (Windows) or `Root` (Linux/macOS) privileges.

### 1. The "Quick Triage" (Fast Mode)

Scans high-risk directories first, then checks *only* executable/script extensions (`.exe`, `.dll`, `.ps1`, `.php`) on the rest of the disk. Stops on the first match **per file.**

```bash
python mass_yara.py -r ./rules -p C:\ --fast --workers 16

```

### 2. The "Deep Forensic" Scan

Scans Process Memory and **ALL** files on disk (except redundant media files like `.iso`/`.mp4`).

```bash
python mass_yara.py -r /opt/yara-rules -m -p /

```

### 3. Production Server Safety Mode

Use this for Database or Exchange servers. It pins the scanner to **CPU 0**, sets process priority to **IDLE**, and limits memory usage.

```bash
python mass_yara.py -r ./rules -m -p C:\ --low-priority --max-mem 4096

```

### 4. False Positive Reduction (Hash List)

Provide a list of known-good SHA256 hashes (CSV or Space-separated). The tool calculates the hash of a file *before* scanning; if it matches the list, the YARA scan is skipped.

```bash
python mass_yara.py -r ./rules -p C:\Windows --known-good known_good.txt

```

---

## ⚙️ Command Line Arguments

| Argument | Description |
| --- | --- |
| `-r`, `--rules` | **Required.** Directory containing `.yar` rule files (compiled automatically). |
| `-p`, `--path` | Target directory or file to scan on disk. |
| `-m`, `--memory` | Enable Process Memory scanning (Windows/Linux only). |
| `--workers` | Number of parallel worker processes (Default: `CPU - 1`). |
| `--fast` | **Optimization.** Only scans specific extensions and stops on 1st match per file. |
| `--low-priority` | **Safety.** Overrides workers to **1**, pins to CPU 0, and sets IDLE priority. |
| `--known-good` | Path to a file containing SHA256 hashes to IGNORE. |
| `--max-size` | Max file size in MB to scan (Default: 100MB). |
| `--max-mem` | Max Process RAM in MB to scan (Default: 2048MB). |
| `-o`, `--out-dir` | Output directory for logs (Default: Current Dir). |

---

## 📄 Output Format

The tool generates a timestamped `.jsonl` file and an `.html` report in the output directory.

### 1. `scan_HOSTNAME_TIMESTAMP.jsonl`

Ideal for timeline analysis or SIEM ingestion.

```json
{
  "timestamp": "2026-01-01 12:01:22",
  "level": "HIT",
  "scan_type": "DISK",
  "rule": "Webshell_PHP_Obfuscated",
  "target": "C:\\inetpub\\wwwroot\\images\\logo.php",
  "meta": {
    "size": 4096,
    "sha256": "e3b0c442... (hash)",
    "iocs": { "ips": ["192.168.1.50"] }
  },
  "strings": [
    { "id": "$cmd", "offset": 102, "data_preview": "eval(base64_decode..." }
  ]
}

```

**Example Memory Hit:**

```json
{
  "timestamp": "2025-12-15 12:05:45",
  "level": "HIT",
  "scan_type": "MEMORY",
  "rule": "Mimikatz_Credential_Dump",
  "target": "lsass.exe [PID:744]",
  "meta": {
    "ppid": 620,
    "username": "NT AUTHORITY\\SYSTEM",
    "cmdline": "C:\\Windows\\system32\\lsass.exe",
    "parent_chain": [
      { "pid": 620, "name": "wininit.exe" }
    ],
    "started": "2025-12-15 09:00:00"
  },
  "strings": [
    {
      "id": "$sekurlsa",
      "offset": 1048576,
      "data_preview": "sekurlsa::logonpasswords"
    }
  ]
}
```

### 2. `scan_HOSTNAME_TIMESTAMP.html`

A visual dashboard containing:

* **Scan Statistics:** Duration, Files Scanned per second, Top hitting extensions.
* **Performance Warnings:** Alerts if specific rules are "noisy" (generating too many hits) and slowing down the scan.
* **Detail View:** Color-coded table of hits.

## 🛡️ Log Levels

  * `[!] HIT` (Critical): A confirmed YARA match.
  * `[?] SUS` (High): A security event, such as a blocked path traversal attempt.
  * `[-] WARN` (Medium): An operational issue (File locked, Permission denied, Timeout).
  * `[*] INFO` (Low): General status updates.

---

## ⚠️ Known Limitations

1. **macOS Memory:** Memory scanning is disabled on macOS due to SIP (System Integrity Protection) restrictions.
2. **Linux Ptrace:** On hardened Linux kernels (e.g., Ubuntu/Debian), you may need to temporarily allow `ptrace` for memory scanning:
`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
3. **Symlinks:** The tool tracks Inodes to prevent infinite loops, but will alert (`[?] SUS`) if a symlink points to a sensitive target like `/etc/shadow` or `C:\Windows\System32`.

## License

**MIT License** - Free for use in commercial, private, and educational settings.

```

```