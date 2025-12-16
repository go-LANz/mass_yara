# Mass YARA Triage

**Mass YARA Triage** is a robust, cross-platformYARA scanner designed for Digital Forensics and Incident Response (DFIR).

A high-performance, cross-platform forensic triage tool designed for Incident Response. It performs Disk and Process Memory scanning using a pure YARA engine approach, robust logging, and smart noise reduction features.
It solves the common limitation of the standard `yara` CLI by allowing you to **compile and run an entire directory of rules** simultaneously against **Disk or Memory**, without needing to manually merge rule files.

> ✨ **Proudly developed by Vibe Coding.**
> (We don't know why it works, but the vibes are immaculate.)

## ⚡ Key Features


  * **Directory Compilation:** Automatically compiles hundreds of `.yar` / `.yara` files from a folder into a single scanning engine.
  * **Pure YARA Engine:** Focused solely on deterministic content matching.
  * **Memory Scanning (Win/Linux):** Iterates through running processes and scans their memory (bypassing the need for manual PID injection).
  * **Dual Output:**
      * **Operator UI:** Colorized, real-time terminal alerts (Red for Hits, Yellow for Suspicious).
      * **Forensic Reports:** Generates a structured `.jsonl` pipeline file AND a dark-mode `.html` report.
  * **Forensic Triage:** Automatically calculates **SHA256 hash** and file size for any disk hit. Supports **"Known Good"** hash lists to skip scanning safe files.
  * **Fast Mode:** Optional Allowlist mode to scan *only* executables, scripts, and config files for rapid triage.
  * **Cross-Platform:** Universal support for Windows, Linux, and macOS (Disk Only).
  * **Resource Control:** `--low-priority` mode pins scanning to CPU 0 and drops process priority to IDLE to prevent server lag.

-----

## 🛠️ Installation

### Prerequisites

You need Python 3.8+ installed.

```bash
# Windows / Linux
pip install yara-python psutil colorama pyinstaller

# macOS (No psutil memory features used, but required for the script to load)
pip install yara-python psutil colorama pyinstaller
```

### Compilation (Building the Binary)

To deploy this on a target machine without installing Python, compile it into a standalone executable.

> **Note:** The script `mass_yara.py` is universal. You compile the same script on each OS to get the native binary for that OS.

**Windows:**
*(Requires [Visual C++ Build Tools](https://www.google.com/search?q=https://visualstudio.microsoft.com/visual-cpp-build-tools/))*

```bash
pyinstaller --onefile --clean --name "MassYara_Win" mass_yara.py
```

**Linux:**

```bash
pyinstaller --onefile --clean --name "MassYara_Linux" mass_yara.py
```

**macOS:**

```bash
pyinstaller --onefile --clean --name "MassYara_Mac" mass_yara.py
```

-----

## 🚀 Usage

**Note:** Requires `Administrator` / `Root` privileges for Memory scanning. On macOS, "Full Disk Access" is recommended.

### 1\. The "Quick Triage" (Fast Mode)

Scans running processes and critical file extensions (`.exe`, `.dll`, `.ps1`, `.php`) on the disk.

```bash
# Windows
MassYara_Win.exe -r ./rules -m -p C:\ --fast

# Linux
sudo ./MassYara_Linux -r ./rules -m -p / --fast
```

### 2\. The "Deep Forensic" Scan

Scans Memory and **ALL** files on disk (except huge media files like `.iso`/`.mp4`).

```bash
MassYara_Win.exe -r C:\YARA\rules -m -p C:\
```

### 3\. Server Safety Mode (Database/Exchange Servers)

Scans memory but skips any process using more than 4GB of RAM to avoid performance impact.

```bash
MassYara_Win.exe -r ./rules -m --max-mem 4096
```

### 4\. False Positive Reduction (Hash List)

Provide a list of known-good SHA256 hashes. The tool will calculate hashes *before* YARA scanning and skip matches.

```bash
MassYara_Win.exe -r ./rules -p C:\Windows --known-good known_good.txt
```

## ⚙️ Command Line Arguments

| Argument | Description |
| :--- | :--- |
| `-r`, `--rules` | **Required.** Directory containing `.yar` rule files. |
| `-p`, `--path` | Path to scan on disk (File or Directory). |
| `-m`, `--memory` | Enable Process Memory scanning. |
| `--fast` | **Optimization.** Only scans specific extensions and stops on 1st match per file. |
| `--low-priority` | **Safety.** Limits tool to CPU 0 and sets IDLE priority. |
| `--known-good` | Path to a file containing SHA256 hashes to IGNORE. |
| `--max-size` | Max file size in MB to scan (Default: 100MB). |
| `--max-mem` | Max Process RAM in MB to scan (Default: 2048MB). |
| `-o`, `--out-dir` | Output directory for logs (Default: Current Dir). |

-----

## 📄 Output Format

The tool generates a `scan.jsonl` file suitable for ingestion into SIEMs (Splunk, ELK) or timeline analysis tools, plus a analyst friendy `scan_report.html`

### 1\. `scan.jsonl` (JSON Lines)

**Example Disk Hit:**

```json
{
  "timestamp": "2025-12-15 12:01:22",
  "level": "HIT",
  "scan_type": "DISK",
  "rule": "Webshell_PHP_Obfuscated",
  "target": "C:\\inetpub\\wwwroot\\images\\logo.php",
  "meta": {
    "size": 4096,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "strings": [
    {
      "data": "eval(base64_decode($_POST['cmd']));"
    }
  ]
}
```

**Example Memory Hit:**

```json
{
  "timestamp": "2025-12-15 12:02:10",
  "level": "HIT",
  "scan_type": "MEMORY",
  "rule": "Mimikatz_Memory_Pattern",
  "target": "lsass.exe (744)",
  "meta": {}
}
```

### 2\. `scan_report.html` (Dashboard)

A standalone HTML file containing:

  * **Execution Metadata:** Hostname, Start/End time, Command used.
  * **Metrics:** Rules loaded, Items scanned, Detection count, Duration.
  * **Interactive Log Table:** Color-coded rows for Hits (Red), Suspicious Events (Orange), and Warnings (Yellow).
  * **Noisy Rules Summary:** A list of rules that were squelched due to excessive hits.

## 🛡️ Log Levels

  * `[!] HIT` (Critical): A confirmed YARA match.
  * `[?] SUS` (High): A security event, such as a blocked path traversal attempt.
  * `[-] WARN` (Medium): An operational issue (File locked, Permission denied, Timeout).
  * `[*] INFO` (Low): General status updates.

-----

## ⚠️ Known Limitations

1.  **macOS Memory:** The macOS version does not support memory scanning due to SIP (System Integrity Protection) and `task_for_pid` restrictions. The `-m` flag is automatically ignored on macOS to prevent errors.
2.  **Linux Ptrace:** On hardened Linux kernels, you may need to allow `ptrace` for memory scanning:
    `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
3.  **Cross-Platform Rules:** While you can run Windows rules on Linux (and vice versa), module-specific rules (like `pe` or `elf`) will simply return `undefined` on the wrong OS. This is safe but may slightly impact performance.
4.  **AV Detection:** As with any tool that iterates process memory, EDRs may flag the compiled binary as suspicious. Whitelisting the hash is recommended for deployment.

-----

## Disclaimer

This tool is intended for legal security analysis, digital forensics, and incident response. The author (and the Vibe Coding team) is not responsible for misuse or damage caused by this software. Use responsibly.