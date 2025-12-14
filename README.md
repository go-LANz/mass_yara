
# Mass YARA Scanner

A robust, cross-platform wrapper for YARA designed for Digital Forensics and Incident Response (DFIR).

This tool solves the common limitation of the standard `yara` CLI by allowing you to **compile and run an entire directory of rules** simultaneously against **Disk or Memory**, without needing to manually merge rule files. It outputs rich, newline-delimited JSON (`.jsonl`) logs suitable for ingestion into SIEMs (Splunk, ELK) or timeline analysis tools.

## Key Features

  * **Directory Compilation:** Automatically compiles hundreds of `.yar` / `.yara` files from a folder into a single scanning engine.
  * **Memory Scanning (Win/Linux):** Iterates through running processes and scans their memory (bypassing the need for manual PID injection).
  * **Rich Logging (JSONL):** Outputs detailed hits including:
      * Rule Metadata & Tags.
      * Specific String Matches (Identifier, Offset, and Data preview).
      * **Context Aware:** Process Name/PID (Memory) or File Path (Disk).
  * **Forensic Triage:** Automatically calculates **SHA256 hash** and file size for any disk file that triggers a hit.
  * **Cross-Platform:** specialized support for Windows, Linux, and macOS.

## Installation

### Prerequisites

You need Python 3.x installed.

```bash
# Windows / Linux
pip install yara-python psutil pyinstaller

# macOS (No psutil needed for the macOS variant)
pip install yara-python pyinstaller
```

## Compilation (Building the Binary)

To deploy this on a target machine without installing Python, compile it into a standalone executable.

**Windows:**

```bash
pyinstaller --onefile --name "MassYara_Win" mass_yara_win_linux.py
```

**Linux:**

```bash
pyinstaller --onefile --name "MassYara_Linux" mass_yara_win_linux.py
```

**macOS:**

```bash
pyinstaller --onefile --name "MassYara_Mac" mass_yara_macos.py
```

> **Note:** Compiling on Windows requires the [Visual C++ Build Tools](https://www.google.com/search?q=https://visualstudio.microsoft.com/visual-cpp-build-tools/) if they aren't already present.

## Usage

### Windows & Linux (Disk + Memory)

*Requires Administrator / Root privileges for Memory scanning.*

```bash
# Scan a directory recursively
mass_yara_win.exe --rules ./my_rules_folder --path C:\Users\Admin\Downloads

# Scan all running processes in Memory
mass_yara_win.exe --rules ./my_rules_folder --memory

# Custom output file
mass_yara_win.exe --rules ./rules --memory --output analysis_log.jsonl
```

### macOS (Disk Only)

*Requires "Full Disk Access" (TCC) for the terminal or binary running the scan.*

```bash
./mass_yara_mac --rules ./my_rules_folder --path /Users/golan/Documents
```

## Output Format (JSONL)

The tool generates a `yara_scan_results.jsonl` file. Every line is a valid JSON object, making it crash-safe and easy to stream.

**Example Disk Hit:**

```json
{
  "timestamp": "2025-12-14 18:01:22",
  "scan_type": "DISK",
  "rule_name": "Webshell_PHP_Obfuscated",
  "target": "C:\\inetpub\\wwwroot\\images\\logo.php",
  "tags": ["webshell", "critical"],
  "rule_meta": { "author": "Golan", "severity": "High" },
  "strings": [
    {
      "offset": 105,
      "identifier": "$eval",
      "data": "eval(base64_decode($_POST['cmd']));"
    }
  ],
  "file_meta": {
    "size_bytes": 4096,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

**Example Memory Hit:**

```json
{
  "timestamp": "2025-12-14 18:02:10",
  "scan_type": "MEMORY",
  "rule_name": "Mimikatz_Memory_Pattern",
  "target": "lsass.exe (PID: 744)",
  "file_meta": {
    "process_path": "C:\\Windows\\System32\\lsass.exe",
    "process_user": "NT AUTHORITY\\SYSTEM"
  }
}
```

## Known Limitations

1.  **macOS Memory:** The macOS version does not currently support memory scanning due to SIP (System Integrity Protection) and `task_for_pid` restrictions on modern macOS versions.
2.  **Cross-Platform Rules:** While you can run Windows rules on Linux (and vice versa), module-specific rules (like `pe` or `elf`) will simply return `undefined` on the wrong OS. This is safe but may slightly impact performance.
3.  **AV Detection:** As with any tool that iterates process memory, EDRs may flag the compiled binary as suspicious. Whitelisting the hash is recommended for deployment.

## Disclaimer

This tool is intended for legal security analysis, digital forensics, and incident response. The author is not responsible for misuse or damage caused by this software.