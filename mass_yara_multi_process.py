"""
Mass YARA Scanner v49 (Optimized & Hardened)
============================================

A high-performance, multi-threaded, OS-agnostic YARA scanner designed for 
Digital Forensics and Incident Response (DFIR) engagements.

Features:
    - **Wildcard Priority Logic:** Scans "Drop Zones" (Downloads, Temp, AppData) first.
    - **Multi-Processing:** Uses all available CPU cores with a Producer/Consumer model.
    - **Memory Safety:** Explicit garbage collection and size limits to prevent OOM.
    - **Resilience:** Handles locked files, permission errors, and symlink loops gracefully.
    - **Dual Logging:** Produces both JSONL (for ingestion) and HTML (for reporting).
    - **Worker Handshake:** Prevents deadlocks by verifying worker initialization.

Usage:
    python mass_yara.py -r /path/to/rules -p /path/to/scan
    python mass_yara.py -r rules/ -p C:\\ -m --fast --workers 16

Arguments:
    -r, --rules    : Directory containing .yara files (compiled automatically).
    -p, --path     : Target directory or file to scan on disk.
    -m, --memory   : Enable RAM scanning (Windows/Linux only).
    --fast         : Fast Mode (Scan specific extensions, stop on first match).
    --max-size     : Skip files larger than X MB (Default: 100).
    --low-priority : Run on 1 core with idle priority (for live servers).

Dependencies:
    pip install yara-python psutil colorama
    *Note: On Linux, ensure libyara is installed (e.g., sudo apt install libyara-dev) before installing yara-python.*

Log Format (JSONL):
    {
        "timestamp": "YYYY-MM-DD HH:MM:SS",
        "level": "HIT|WARN|SUS",
        "scan_type": "DISK|MEMORY",
        "rule": "Rule Name",
        "target": "File Path or Process Name",
        "meta": { "sha256": "...", "size": 1234, "iocs": {...} },
        "strings": [ { "id": "$a", "offset": 10, "data_preview": "..." } ]
    }

Exit Codes:
    0 : Scan completed successfully (regardless of detections).
    1 : Fatal error (Permissions, Missing Args, Compilation Failed).

License:
    MIT License - Free for use in commercial, private, and educational settings.

Author: Golan (DFIR Lead) & Gemini
Version: 49.0
"""

import os
import sys
import argparse
import time
import json
import hashlib
import yara
import psutil
import platform
import ctypes
import html
import warnings
import multiprocessing
import tempfile
import re
import errno
import glob
import gc
from collections import defaultdict
from functools import partial
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

# --- Configuration & Constants ---

DEFAULT_MAX_SIZE_MB = 100
DEFAULT_MAX_MEM_MB = 2048
DEFAULT_TIMEOUT = 60
NOISY_RULE_THRESHOLD = 50
DEFAULT_WORKERS = max(1, multiprocessing.cpu_count() - 1)
PROGRESS_INTERVAL = 10000 

# Suppress YARA warnings about "too many matches" to keep console clean.
# This often happens with poorly written rules on large files.
warnings.filterwarnings("ignore", category=RuntimeWarning, message="too many matches")

# --- Performance: Pre-compiled Regex ---
# These are compiled once at the module level to avoid re-compilation in tight loops.
# Used to extract IOCs (IPs, URLs, Emails) from YARA string matches.
IOC_IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
IOC_URL_REGEX = re.compile(r'https?://[^\s<>"\']+')
IOC_EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Extensions scanned when --fast mode is enabled.
# Includes scripts, executables, documents, and config files commonly targeted by malware.
FAST_SCAN_EXTS = {
    '.vbs', '.ps', '.ps1', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl',
    '.crt', '.dll', '.exe', '.hta', '.js', '.lnk', '.msc', '.ocx', '.pcd', '.pif',
    '.reg', '.scr', '.sct', '.sys', '.url', '.vb', '.vbe', '.wsc', '.wsf', '.wsh',
    '.ct', '.t', '.input', '.war', '.jar', '.psd1', '.psm1', '.ps1xml', '.clixml', 
    '.psc1', '.pssc', '.jsp', '.jspx', '.php', '.asp', '.aspx', '.pl', '.www',
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.pot', '.txt', '.conf', '.cfg', '.config', '.ini', '.pwd', '.w',
    '.log', '.dump', '.tmp', '.rar', '.rdp', '.elf', '.py'
}

# Extensions ALWAYS skipped unless --fast is OFF.
# These are high-volume, low-risk files (media, large databases) to save time.
DEFAULT_SKIP_EXTS = {
    '.iso', '.vhd', '.vhdx', '.mp4', '.mp3', '.avi', '.mkv', '.db', '.lock', 
    '.wim', '.bmp', '.ttf', '.class', '.jpg', '.png', '.gif'
}

# Directories to exclude to prevent recursion or hardware locking.
# Crucial for stability on Linux (avoiding /proc and /sys infinite loops).
PLATFORM_EXCLUDES = {
    "Linux":  ["/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker"],
    "Darwin": ["/dev", "/Volumes", "/Network", "/private/var/vm", "/cores"],
    "Windows": [] 
}

# If a symlink points to these, trigger a SUSPICIOUS warning.
# Helps identify attackers trying to hide files or link to sensitive system areas.
SENSITIVE_LINK_TARGETS = [
    '/etc/shadow', '/etc/passwd', '/root', 'c:\\windows\\system32', 
    'config', 'credential', 'password', '.ssh', 'id_rsa', 'authorized_keys'
]

# --- Priority Map "The Drop Zones" ---
# These paths are scanned in Phase 1. Wildcards (*) are expanded dynamically.
# Strategy: Scan where malware usually lands (Downloads, Temp) before scanning the whole disk.
PRIORITY_MAP = {
    "Windows": [
        "C:\\Users\\*\\Downloads",
        "C:\\Users\\*\\Desktop",
        "C:\\Users\\*\\Documents",
        "C:\\Users\\*\\AppData\\Local\\Temp",
        "C:\\Users\\*\\AppData\\Roaming",
        "C:\\Users\\*\\AppData\\Local\\Programs",
        "C:\\ProgramData",
        "C:\\Users\\Public",
        "C:\\Windows\\Temp"
    ],
    "Linux": [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home/*/Downloads",
        "/home/*/Desktop",
        "/home/*/.local/share",
        "/home/*/.config/autostart",
        "/root/Downloads"
    ],
    "Darwin": [ 
        "/Users/*/Downloads",
        "/Users/*/Desktop",
        "/Users/*/Library/Application Support",
        "/Users/*/Library/Caches",
        "/Users/*/Library/LaunchAgents",
        "/Users/Shared",
        "/tmp",
        "/var/tmp"
    ]
}

# --- GLOBAL WORKER STATE ---
# These variables are initialized inside every worker process.
# They allow sharing the compiled rules and hash list without serializing them 
# back and forth between processes (significant performance gain).
WORKER_RULES = None 
WORKER_HASHES = None

# --- HTML Template (Report Structure) ---
# Embedded HTML/CSS for the reporting engine.
HTML_HEADER = """
<!DOCTYPE html>
<html>
<head>
<title>YARA Scan Report</title>
<style>
    body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; padding: 20px; }
    h2 { border-bottom: 1px solid #555; padding-bottom: 10px; margin-top: 30px; color: #569cd6; }
    .meta-box { background-color: #252526; padding: 15px; border-radius: 6px; border: 1px solid #333; margin-bottom: 20px; font-size: 0.9em; }
    .meta-row { margin-bottom: 5px; }
    .meta-label { color: #888; display: inline-block; width: 120px; }
    .meta-val { color: #fff; font-weight: bold; }
    .dashboard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
    .card { background-color: #2d2d2d; padding: 15px; border-radius: 6px; border: 1px solid #333; text-align: center; }
    .card .label { display: block; font-size: 0.9em; color: #888; margin-bottom: 5px; }
    .card .value { font-size: 1.8em; font-weight: bold; color: #fff; }
    .card .value.red { color: #f44336; }
    .logs { border-top: 1px solid #333; padding-top: 10px; }
    .hit { color: #f44336; font-weight: bold; }   
    .sus { color: #ff9800; font-weight: bold; }   
    .warn { color: #ffeb3b; font-weight: bold; }  
    .info { color: #4caf50; }                     
    .meta { color: #569cd6; } 
    .source { color: #9cdcfe; font-size: 0.9em; margin-right: 10px; }
    .row { border-bottom: 1px solid #333; padding: 8px 0; display: block; font-size: 0.95em; }
    .row:hover { background-color: #252526; }
    .noisy-box { margin-top: 20px; padding: 10px; background-color: #332b00; border: 1px solid #ffeb3b; border-radius: 4px; display: none; }
    .stat-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .stat-table td { padding: 5px; border-bottom: 1px solid #333; }
</style>
</head>
<body>
<div class="meta-box">
    <div class="meta-row"><span class="meta-label">Hostname:</span> <span id="m_host" class="meta-val">--</span></div>
    <div class="meta-row"><span class="meta-label">Started:</span> <span id="m_start" class="meta-val">--</span></div>
    <div class="meta-row"><span class="meta-label">Finished:</span> <span id="m_end" class="meta-val">--</span></div>
    <div class="meta-row"><span class="meta-label">Command:</span> <span id="m_cmd" class="cmd-text">--</span></div>
</div>
<div class="dashboard">
    <div class="card"><span class="label">Rules Loaded</span><span id="d_rules" class="value">--</span></div>
    <div class="card"><span class="label">Items Scanned</span><span id="d_scanned" class="value">--</span></div>
    <div class="card"><span class="label">Detections</span><span id="d_hits" class="value red">--</span></div>
    <div class="card"><span class="label">Duration</span><span id="d_time" class="value">--</span></div>
</div>
<div id="noisy_container" class="noisy-box">
    <span class="noisy-title">⚠️ Performance Warning: Noisy Rules Detected</span>
    <div id="noisy_list"></div>
</div>
<h2>Detailed Scan Logs</h2>
<div class="logs">
"""

# --- Helpers ---

def is_admin():
    """
    Checks for Administrator (Windows) or Root (Linux/Mac) privileges.
    Required because YARA often needs to read files owned by other users.
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except: return False

def set_low_priority():
    """ 
    Lowers the process priority to avoid impacting system performance.
    Useful for live production servers. Pins process to CPU 0 on Linux.
    """
    try:
        p = psutil.Process(os.getpid())
        if platform.system() == "Windows":
            p.nice(psutil.IDLE_PRIORITY_CLASS)
        else:
            os.nice(19)
        if hasattr(p, "cpu_affinity"):
            p.cpu_affinity([0]) # Pin to CPU 0
        print(f"{Fore.YELLOW}[!] Low Priority Mode Enabled{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to set low priority: {e}{Style.RESET_ALL}")

def is_safe_path(filepath, base_path):
    """
    Validates that 'filepath' is strictly inside 'base_path'.
    Prevents path traversal attacks and symlink escapes (e.g. scanning / via a link).
    """
    try:
        real_path = os.path.realpath(filepath)
        real_base = os.path.realpath(base_path)
        real_path = os.path.normcase(real_path)
        real_base = os.path.normcase(real_base)
        
        # Ensure base path ends with a separator for correct prefix matching
        if not real_base.endswith(os.sep):
            real_base += os.sep
            
        return real_path.startswith(real_base) or real_path == real_base.rstrip(os.sep)
    except: return False

def get_buffer_hash(data):
    """ Returns SHA256 hex digest of a byte buffer. Used for known-good comparisons. """
    try:
        return hashlib.sha256(data).hexdigest()
    except: return None

def validate_positive_int(value):
    """ Argparse validator for positive integers. """
    try:
        ivalue = int(value)
        if ivalue <= 0: raise ValueError
        return ivalue
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a valid positive integer")

def should_exclude_path(root_path, current_os):
    """ 
    Checks if path is in the platform-specific exclusion list (e.g. /proc). 
    Prevents scanning virtual filesystems that can cause hangs.
    """
    excludes = PLATFORM_EXCLUDES.get(current_os, [])
    try:
        norm_root = os.path.realpath(root_path)
        for ex in excludes:
            if norm_root == ex or norm_root.startswith(ex + os.sep):
                return True
    except OSError: pass
    return False

def get_priority_paths(target_root):
    """
    Calculates the 'Drop Zone' paths for Phase 1 scanning.
    1. Expands wildcards (e.g., C:\\Users\\*\\Downloads) using glob.
    2. Enforces STRICT scope: Expanded path must be inside target_root.
    """
    sys_plat = platform.system()
    raw_patterns = PRIORITY_MAP.get(sys_plat, [])
    
    target_abs = os.path.normcase(os.path.abspath(target_root))
    # Ensure target ends with separator for strict prefix matching
    target_abs_strict = target_abs if target_abs.endswith(os.sep) else target_abs + os.sep
        
    valid_paths = []
    
    for pattern in raw_patterns:
        try:
            # Handle glob expansion; may fail on strict permissions
            expanded = glob.glob(pattern)
            for p in expanded:
                try:
                    p_abs = os.path.normcase(os.path.abspath(p))
                    # Enforce strict scope: Do not allow leakage outside the target (e.g., matching UserBackup when targeting Users)
                    if p_abs.startswith(target_abs_strict) or p_abs == target_abs:
                        valid_paths.append(p_abs)
                except: pass
        except Exception: pass
            
    # Sort by length to process most specific paths first
    return sorted(list(set(valid_paths)), key=len)

def get_parent_chain(proc, max_depth=4):
    """ 
    Recurses up the process tree to find parent PIDs and names. 
    Crucial for identifying malware execution chains (e.g., cmd.exe -> powershell.exe).
    """
    chain = []
    curr = proc
    for _ in range(max_depth):
        try:
            if not curr or curr.pid == 0: break
            chain.append({
                "pid": curr.pid,
                "name": curr.name() if hasattr(curr, 'name') else "Unknown",
                "exe": curr.exe() if hasattr(curr, 'exe') else None
            })
            parent = curr.parent()
            if not parent: break
            curr = parent
        except (psutil.NoSuchProcess, psutil.AccessDenied): break
    return chain

def extract_iocs(strings_list):
    """ 
    Extracts IPs, URLs, and Emails from YARA string matches via Regex.
    Returns a dictionary of found IOCs to add to the JSON logs.
    """
    if not strings_list: return {}
    combined = " ".join([s.get('data_full', '') for s in strings_list])
    
    iocs = {
        "ips": list(set(IOC_IP_REGEX.findall(combined))),
        "urls": list(set(IOC_URL_REGEX.findall(combined))),
        "emails": list(set(IOC_EMAIL_REGEX.findall(combined))),
    }
    return {k: v for k, v in iocs.items() if v}

# --- WORKER FUNCTIONS (Multiprocessing) ---

def load_known_good_worker(path):
    """ 
    Loads known-good hash list into a set for O(1) lookups inside the worker. 
    Supports both CSV (hash,filename) and space-separated (hash filename) formats.
    """
    hashes = set()
    if path and os.path.exists(path):
        try:
            with open(path, 'r') as f:
                for line in f:
                    # Robustness: Replace comma with space to handle both CSV and 
                    # standard 'sha256sum' output formats cleanly.
                    line = line.replace(',', ' ')
                    parts = line.strip().split()
                    if not parts: continue
                    
                    h = parts[0].strip().lower()
                    if len(h) == 64: hashes.add(h)
        except Exception: pass
    return hashes

def init_worker(compiled_rules_path, known_good_path, status_queue):
    """
    Initializes a worker process.
    1. Loads compiled YARA rules from temp file (fastest method).
    2. Loads known-good hashes.
    3. Sends "OK" to status_queue (Handshake) so the main process knows we are ready.
    """
    global WORKER_RULES, WORKER_HASHES
    try:
        WORKER_RULES = yara.load(compiled_rules_path)
        if known_good_path:
            WORKER_HASHES = load_known_good_worker(known_good_path)
        
        # Signal Success to Main Process. This prevents the "deadlock" scenario where
        # the main process starts sending files before workers are ready.
        if status_queue:
            status_queue.put("OK")
            
    except Exception as e:
        # Signal Failure
        sys.stderr.write(f"FATAL: Worker init failed: {e}\n")
        if status_queue:
            status_queue.put(f"FAIL: {str(e)}")
        sys.exit(1)

def scan_file_worker(args):
    """
    The main scanning logic running inside each worker process.
    Args:
        args: Tuple of (file_path, config_dict) - passed as tuple for imap compatibility.
    Returns:
        dict: Scan result including matches, metadata, and warnings.
    """
    path, config = args
    result = {
        "status": "OK",
        "path": path,
        "matches": [],
        "warnings": [],
        "scanned": False
    }

    # Symlink Check: Detect loops or sensitive targets
    if os.path.islink(path):
        try:
            target = os.readlink(path)
            t_lower = target.lower()
            if any(p in t_lower for p in SENSITIVE_LINK_TARGETS):
                result['warnings'].append(("SUS", "SYMLINK_SUSPICIOUS", "SENSITIVE_TARGET", f"{path} -> {target}"))
            return result
        except OSError as e:
            result['warnings'].append(("WARN", "SYMLINK_ERROR", "READLINK_FAIL", f"{path}: {e}"))
            return result

    # Extension Filter: Check against fast scan list or skip list
    ext = os.path.splitext(path)[1].lower()
    if config['fast']:
        if ext not in FAST_SCAN_EXTS: return result
    else:
        if ext in DEFAULT_SKIP_EXTS: return result

    try:
        with open(path, 'rb') as f:
            try:
                stat = os.fstat(f.fileno())
            except OSError: return result

            size = stat.st_size
            if size == 0: return result
            # Enforce size limit (prevents processing 50GB logs)
            if size > (config['max_size'] * 1024 * 1024):
                result['warnings'].append(("WARN", "DISK_SKIP", "SIZE_LIMIT", path))
                return result
            
            try:
                file_data = f.read()
            except OSError as e:
                # Reduced noise for IO errors (common in live systems)
                return result

        # Known Good Hash Check (if enabled)
        f_hash = None
        if WORKER_HASHES:
            f_hash = get_buffer_hash(file_data)
            if f_hash and f_hash in WORKER_HASHES:
                # Explicitly delete data before returning to free memory
                del file_data
                return result 

        # Perform Scan using the pre-loaded global rules
        result['scanned'] = True
        matches = WORKER_RULES.match(data=file_data, timeout=config['timeout'], fast=config['fast'])
        
        if matches:
            if not f_hash: f_hash = get_buffer_hash(file_data)
            meta = {"sha256": f_hash or "HASH_FAILED", "size": size}
            
            for m in matches:
                strs = []
                try:
                    for s in m.strings:
                        for instance in s.instances:
                            data_raw = instance.matched_data
                            try:
                                full_decoded = data_raw.decode('utf-8', errors='ignore')
                                preview_display = full_decoded[:50].strip()
                            except:
                                hex_val = data_raw.hex()
                                full_decoded = f"HEX:{hex_val}"
                                preview_display = f"HEX:{hex_val[:50]}"
                                
                            strs.append({"id": s.identifier, "offset": instance.offset, "data_preview": preview_display, "data_full": full_decoded})
                except Exception:
                    result['warnings'].append(("WARN", "YARA_INTERNAL", "STRING_EXTRACT_ERR", path))
                
                # Optimization: Only extract IOCs if strings exist
                if strs:
                    iocs = extract_iocs(strs)
                    if iocs: meta['iocs'] = iocs

                result['matches'].append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "meta": meta,
                    "strings": strs
                })
        
        # Immediate cleanup: Delete file data to prevent memory bloating in the worker process
        del file_data
        
        # Force Garbage Collection for large files to avoid OOM scenarios in long-running workers
        if size > 50 * 1024 * 1024: 
            gc.collect()

    except Exception:
        pass

    return result

# --- LOGGER ---

class DualLogger:
    """ 
    Handles logging to both Console (Stdout), JSONL (File), and HTML (Report). 
    Also tracks statistics for the summary.
    """
    def __init__(self, out_dir, cmd_args):
        self.hostname = platform.node()
        self.start_time_obj = time.time()
        self.start_str = time.strftime("%Y-%m-%d %H:%M:%S")
        ts_file = time.strftime("%Y%m%d_%H%M%S")
        
        json_name = f"scan_{self.hostname}_{ts_file}.jsonl"
        html_name = f"scan_{self.hostname}_{ts_file}.html"
        
        json_path = os.path.join(out_dir, json_name)
        html_path = os.path.join(out_dir, html_name)
        
        print(f"{Fore.GREEN}[*] Log File: {json_name}{Style.RESET_ALL}")
        
        self.json_file = open(json_path, 'a', encoding='utf-8')
        self.html_file = open(html_path, 'w', encoding='utf-8')
        self.html_file.write(HTML_HEADER)
        
        self.cmd_args_raw = " ".join(cmd_args)
        self.stats = {'rules': 0, 'scanned': 0, 'hits': 0, 'suspicious': 0, 'errors': 0}
        self.ext_hits = defaultdict(int)
        self.rule_hit_counts = {} 
        self.noisy_rules = [] 
        self.phase_times = {} 
    
    def start_phase(self, name):
        """ Marks the start time of a scan phase (e.g. 'Memory', 'Disk'). """
        self.phase_times[name] = {"start": time.time(), "end": None}
    
    def end_phase(self, name):
        """ Marks the end time of a scan phase. """
        if name in self.phase_times:
            self.phase_times[name]["end"] = time.time()

    def set_rule_count(self, count):
        self.stats['rules'] = count

    def increment_scanned(self, count=1):
        self.stats['scanned'] += count

    def log(self, level, scan_type, rule_name, target, meta=None, strings=None, source_file=None):
        """
        Main logging function.
        - Writes JSON object to file.
        - Updates HTML report.
        - Prints colored output to console (unless suppressed).
        - Handles "Noisy Rule" logic to prevent flooding the UI.
        """
        ts = time.strftime("%H:%M:%S")
        
        display_rule = rule_name if rule_name else "UNKNOWN_RULE"
        display_meta = meta if meta is not None else {}
        
        suppress_ui = False

        if level == "HIT":
            if rule_name:
                # Noisy Rule Suppression Logic:
                # If a single rule triggers too many hits (e.g., matching 'the'), we stop 
                # printing it to the console/HTML to prevent lag, but keep logging to JSON.
                if rule_name not in self.rule_hit_counts: self.rule_hit_counts[rule_name] = 0
                self.rule_hit_counts[rule_name] += 1
                
                if self.rule_hit_counts[rule_name] > NOISY_RULE_THRESHOLD:
                    suppress_ui = True
                elif self.rule_hit_counts[rule_name] == NOISY_RULE_THRESHOLD:
                    self.noisy_rules.append(rule_name) 
                    level = "WARN"
                    target = f"Rule '{rule_name}' hit limit ({NOISY_RULE_THRESHOLD}). Suppressing UI."
                    display_meta = {"msg": str(target)}
                else:
                    self.stats['hits'] += 1
                    if scan_type == "DISK":
                        ext = os.path.splitext(str(target))[1].lower()
                        if ext: self.ext_hits[ext] += 1
        elif level == "SUS":
            self.stats['suspicious'] += 1
        elif level == "WARN":
            if "NOISY_RULE" not in scan_type:
                self.stats['errors'] += 1

        if level == "HIT" and not suppress_ui:
            term_color = Fore.RED; html_class = "hit"; prefix = "[!] HIT"
        elif level == "SUS":
            term_color = Fore.LIGHTRED_EX; html_class = "sus"; prefix = "[?] SUS"
        elif level == "WARN":
            term_color = Fore.YELLOW; html_class = "warn"; prefix = "[-] WARN"
        else:
            term_color = Fore.GREEN; html_class = "info"; prefix = "[*] INFO"

        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), 
            "level": level, 
            "scan_type": scan_type, 
            "rule": display_rule, 
            "source_file": source_file,
            "target": target, 
            "meta": display_meta, 
            "strings": strings or []
        }
        self.json_file.write(json.dumps(entry) + "\n")

        if not suppress_ui:
            # \033[K clears the line to prevent overlap with the progress bar
            sys.stdout.write("\033[K")
            rule_part = f" | {Fore.MAGENTA}{display_rule}{Style.RESET_ALL}" if rule_name else ""
            print(f"{term_color}{prefix}{Style.RESET_ALL} | {ts} | {scan_type}{rule_part} | {target}")
            
            # --- SECURITY FIX: Explicit quoting for HTML ---
            safe_target = html.escape(str(target), quote=True)
            safe_rule = html.escape(str(display_rule), quote=True)
            source_display = f'<span class="source">{html.escape(source_file)}</span>' if source_file else ""
            
            row = f"""<div class="row"><span class="timestamp">{ts}</span><span class="{html_class}">{prefix}</span><span class="meta">[{scan_type}]</span>{source_display}<b>{safe_rule}</b> : {safe_target}</div>"""
            self.html_file.write(row)

    def close(self):
        """ Closes files and appends final statistics (JS) to the HTML report. """
        end_time_obj = time.time()
        duration = end_time_obj - self.start_time_obj
        sys.stdout.write("\033[K")
        
        safe_cmd_js = json.dumps(self.cmd_args_raw)
        safe_host_js = json.dumps(self.hostname)
        noisy_js_array = json.dumps(self.noisy_rules)
        end_ts = time.strftime('%Y-%m-%d %H:%M:%S')
        top_exts = ', '.join([f'{k}({v})' for k,v in sorted(self.ext_hits.items(), key=lambda x: x[1], reverse=True)[:5]]) or "None"

        phase_rows = ""
        for name, times in self.phase_times.items():
            if times['end']:
                dur = times['end'] - times['start']
                phase_rows += f"<tr><td>Phase: {name}</td><td>{dur:.1f} sec</td></tr>"

        js_footer = f"""
        <h2>Scan Statistics</h2>
        <table class="stat-table">
            <tr><td>Files Scanned:</td><td>{self.stats['scanned']}</td></tr>
            <tr><td>Detections:</td><td>{self.stats['hits']}</td></tr>
            <tr><td>Suspicious Events:</td><td>{self.stats['suspicious']}</td></tr>
            <tr><td>Errors:</td><td>{self.stats['errors']}</td></tr>
            <tr><td>Top Hit Extensions:</td><td>{top_exts}</td></tr>
            {phase_rows}
        </table>
        </div>
        <script>
            document.getElementById('m_host').innerText = {safe_host_js};
            document.getElementById('m_start').innerText = "{self.start_str}";
            document.getElementById('m_end').innerText = "{end_ts}";
            document.getElementById('m_cmd').innerText = {safe_cmd_js}; 
            document.getElementById('d_rules').innerText = "{self.stats['rules']}";
            document.getElementById('d_scanned').innerText = "{self.stats['scanned']}";
            document.getElementById('d_hits').innerText = "{self.stats['hits']}";
            document.getElementById('d_time').innerText = "{duration/60:.1f} min";
            
            var noisyRules = {noisy_js_array};
            if (noisyRules.length > 0) {{
                document.getElementById('noisy_container').style.display = 'block';
                document.getElementById('noisy_list').innerText = noisyRules.join(", ");
            }}
        </script>
        </body></html>
        """
        self.html_file.write(js_footer)
        self.html_file.close()
        self.json_file.close()

def compile_rules_to_file(rule_dir, logger):
    """
    Compiles all .yar/.yara files in directory into a single binary.
    Preserves namespaces (filenames) for attribution.
    Saves to a temporary file for easy loading by workers.
    """
    print(f"{Fore.CYAN}[*] Compiling rules from: {rule_dir}{Style.RESET_ALL}")
    sources = {}
    valid_count = 0
    
    for root, _, files in os.walk(rule_dir):
        for file in files:
            if file.endswith(('.yar', '.yara')):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source_code = f.read()
                    try:
                        yara.compile(source=source_code)
                        rel_path = os.path.relpath(full_path, rule_dir)
                        sources[rel_path] = source_code
                        valid_count += 1
                    except yara.SyntaxError as e:
                        logger.log("WARN", "COMPILATION_ERROR", "SYNTAX", f"{file}: {e}")
                    except yara.Error as e:
                        logger.log("WARN", "COMPILATION_ERROR", "YARA_ERR", f"{file}: {e}")
                except Exception as e:
                    logger.log("WARN", "COMPILATION_ERROR", "READ_FAIL", f"{file}: {e}")

    if not sources:
        print(f"{Fore.RED}[!] No valid rules found.{Style.RESET_ALL}")
        sys.exit(1)

    try:
        compiled_rules = yara.compile(sources=sources)
        fd, temp_path = tempfile.mkstemp(prefix="mass_yara_", suffix=".compiled")
        os.close(fd)
        compiled_rules.save(temp_path)
        print(f"{Fore.CYAN}[*] Rules compiled: {valid_count}. Saved to temp.{Style.RESET_ALL}")
        return compiled_rules, temp_path, valid_count
    except Exception as e:
        logger.log("HIT", "CRITICAL_FAILURE", "LINKER_ERROR", str(e))
        sys.exit(1)

def extract_strings_modern(match_object):
    """ Helper to safely extract string matches from YARA object and decode them. """
    results = []
    try:
        for string_match in match_object.strings:
            try:
                identifier = string_match.identifier
                for instance in string_match.instances:
                    data_raw = instance.matched_data
                    try:
                        full_decoded = data_raw.decode('utf-8', errors='ignore').strip()
                        preview_display = full_decoded[:50].strip() if full_decoded else f"HEX:{data_raw.hex()[:50]}"
                    except:
                        full_decoded = f"HEX:{data_raw.hex()}"
                        preview_display = f"HEX:{data_raw.hex()[:50]}"
                    results.append({"id": identifier, "offset": instance.offset, "data_preview": preview_display, "data_full": full_decoded})
            except: pass
    except: pass
    return results

def get_proc_name(proc):
    try: return proc.name()
    except: return "Unknown"

# --- MAIN ENTRY POINT ---
def main():
    if not is_admin():
        print(f"{Fore.RED}[CRITICAL] This tool requires Administrator/Root privileges.{Style.RESET_ALL}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Mass YARA Scanner v49", formatter_class=argparse.RawTextHelpFormatter)
    input_group = parser.add_argument_group('Input')
    input_group.add_argument('-r', '--rules', required=True, metavar='DIR', help="Directory containing .yara rule files")
    
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-p', '--path', metavar='DIR', help="Scan a directory or file on disk")
    target_group.add_argument('-m', '--memory', action='store_true', help="Scan memory (Linux/Windows only)")

    opt_group = parser.add_argument_group('Optimization')
    opt_group.add_argument('--workers', type=validate_positive_int, default=DEFAULT_WORKERS, help=f"Number of parallel workers (Default: {DEFAULT_WORKERS})")
    opt_group.add_argument('--fast', action='store_true', help="Enable Fast Mode (Short-circuit on 1st match)")
    opt_group.add_argument('--low-priority', action='store_true', help="THROTTLE: Use only 1 CPU core (Overrides --workers)")
    opt_group.add_argument('--known-good', metavar='FILE', help="SHA256 hash list to IGNORE")
    opt_group.add_argument('--max-size', type=validate_positive_int, default=DEFAULT_MAX_SIZE_MB, metavar='MB', help=f"Max file size MB (Default: {DEFAULT_MAX_SIZE_MB})")
    opt_group.add_argument('--max-mem', type=validate_positive_int, default=DEFAULT_MAX_MEM_MB, metavar='MB', help=f"Max Process RAM MB (Default: {DEFAULT_MAX_MEM_MB})")

    out_group = parser.add_argument_group('Output')
    out_group.add_argument('-o', '--out-dir', default=".", metavar='DIR', help="Output directory")

    args = parser.parse_args()
    if not args.path and not args.memory: parser.error("You must specify at least one target.")
    if not os.path.exists(args.out_dir): os.makedirs(args.out_dir)

    if args.low_priority:
        set_low_priority()
        args.workers = 1
    
    logger = DualLogger(args.out_dir, sys.argv)
    temp_rules_path = None
    
    try:
        main_rules, temp_rules_path, rule_count = compile_rules_to_file(args.rules, logger)
        logger.set_rule_count(rule_count)
        
        worker_config = {
            'fast': args.fast,
            'max_size': args.max_size,
            'timeout': DEFAULT_TIMEOUT
        }

        # --- MEMORY SCAN ---
        if args.memory:
            logger.start_phase("Memory")
            current_os = platform.system()
            if current_os == "Darwin":
                print(f"{Fore.YELLOW}[!] INFO: MacOS memory scan not supported. Ignoring.{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[*] Starting Memory Scan (Main Process)...{Style.RESET_ALL}")
                max_mem_bytes = args.max_mem * 1024 * 1024
                attrs = ['pid', 'name', 'exe', 'cmdline', 'cwd', 'username', 'create_time', 'ppid', 'memory_info']

                for proc in psutil.process_iter(attrs):
                    try:
                        info = proc.info
                        if current_os == "Windows" and info['pid'] == 0: continue 
                        
                        if info['memory_info'] and info['memory_info'].rss > max_mem_bytes:
                             logger.log("WARN", "MEMORY_SKIP", "SIZE_LIMIT", f"PID {info['pid']} too large")
                             continue
                        
                        logger.increment_scanned()
                        
                        try:
                            create_ts = info.get('create_time')
                            create_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(create_ts)) if create_ts else "Unknown"
                        except: create_str = "Unknown"

                        proc_meta = {
                            "ppid": info.get('ppid'),
                            "username": info.get('username') or "N/A",
                            "cwd": info.get('cwd') or "N/A",
                            "cmdline": " ".join(info.get('cmdline') or []),
                            "started": create_str,
                            "exe": info.get('exe'),
                            "parent_chain": get_parent_chain(proc)
                        }

                        matches = main_rules.match(pid=info['pid'], timeout=DEFAULT_TIMEOUT, fast=args.fast)
                        proc_name = info.get('name') or "Unknown"
                        
                        for m in matches:
                            target_str = f"{proc_name} [PID:{info['pid']}]"
                            strs = extract_strings_modern(m)
                            iocs = extract_iocs(strs)
                            if iocs: proc_meta['iocs'] = iocs
                            logger.log("HIT", "MEMORY", m.rule, target_str, meta=proc_meta, strings=strs, source_file=m.namespace)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied): continue
                    except Exception as e: 
                        logger.log("WARN", "MEMORY_ERR", "FAIL", f"PID {proc.info.get('pid', '?')} error: {str(e)}")
            logger.end_phase("Memory")

        # --- DISK SCAN ---
        if args.path:
            # --- PERFORMANCE OPTIMIZATION: Resolve absolute path ONCE here ---
            # This ensures os.walk yields absolute paths, so we don't need
            # to call abspath() inside the tight loop below.
            args.path = os.path.abspath(args.path)
            
            print(f"{Fore.CYAN}[*] Scanning Disk: {args.path}{Style.RESET_ALL}")
            
            # Wrapper for safety and logic encapsulation
            def safe_file_generator():
                """ 
                Generates file paths for workers, handling priorities and deduplication.
                Prevents infinite loops by tracking 'processed_dirs'.
                """
                try:
                    processed_dirs = set()
                    priority_list = get_priority_paths(args.path)
                    
                    # PHASE 1: Priority Drop Zones
                    # Scan likely malware locations first to get quick wins
                    if priority_list:
                        print(f"{Fore.MAGENTA}[*] Phase 1: Scanning {len(priority_list)} Priority Targets...{Style.RESET_ALL}")
                        for p_root in priority_list:
                            # Normalize paths once for performance
                            norm_p_root = os.path.normcase(os.path.abspath(p_root))
                            processed_dirs.add(norm_p_root)
                            
                            for root, dirs, files in os.walk(p_root):
                                # Optimization: root is already absolute because p_root is absolute
                                norm_root = os.path.normcase(root)
                                
                                # Filter symlinks and restricted directories
                                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d)) and not should_exclude_path(os.path.join(root, d), platform.system())]
                                
                                for file in files:
                                    full_path = os.path.join(root, file)
                                    if is_safe_path(full_path, args.path):
                                        yield (full_path, worker_config)
                    
                    # PHASE 2: General Scan
                    # Scan whatever is left, skipping what we already covered in Phase 1
                    print(f"{Fore.CYAN}[*] Phase 2: Scanning remaining files in {args.path}...{Style.RESET_ALL}")
                    
                    for root, dirs, files in os.walk(args.path):
                        # Optimization: args.path was forced absolute above, so root is absolute.
                        # We can skip os.path.abspath() here for speed.
                        norm_root = os.path.normcase(root)
                        
                        # Optimization: Prune the tree if we already scanned this folder in Phase 1
                        if norm_root in processed_dirs:
                            dirs[:] = []
                            continue
                        
                        dirs[:] = [
                            d for d in dirs 
                            if not os.path.islink(os.path.join(root, d))
                            and os.path.normcase(os.path.join(root, d)) not in processed_dirs
                            and not should_exclude_path(os.path.join(root, d), platform.system())
                        ]
                        
                        for file in files:
                            full_path = os.path.join(root, file)
                            if is_safe_path(full_path, args.path):
                                yield (full_path, worker_config)
                except Exception as e:
                    print(f"{Fore.RED}[!] Generator Error: {e}{Style.RESET_ALL}")
                    return

            # Initialize Queue for Worker Handshake
            # This ensures all workers are actually ready (rules loaded) before we feed them files.
            manager = multiprocessing.Manager()
            status_queue = manager.Queue()
            
            print(f"{Fore.CYAN}[*] Initializing {args.workers} workers...{Style.RESET_ALL}")
            
            PROG_FMT = f"\r{Fore.CYAN}[*] Progress: {{}} files processed...{Style.RESET_ALL}"

            # Start the Worker Pool
            with multiprocessing.Pool(processes=args.workers, initializer=init_worker, initargs=(temp_rules_path, args.known_good, status_queue)) as pool:
                
                # Check for "OK" messages from all workers
                active_workers = 0
                for _ in range(args.workers):
                    try:
                        msg = status_queue.get(timeout=10) # Wait 10s for init
                        if msg == "OK":
                            active_workers += 1
                        else:
                            print(f"{Fore.RED}[!] Worker Init Failed: {msg}{Style.RESET_ALL}")
                    except:
                        print(f"{Fore.RED}[!] Worker Init Timeout{Style.RESET_ALL}")
                
                if active_workers < args.workers:
                    print(f"{Fore.RED}[CRITICAL] Only {active_workers}/{args.workers} started. Aborting to prevent deadlock.{Style.RESET_ALL}")
                    return

                chunk_size = max(20, args.workers * 5)
                logger.start_phase("Disk")
                
                try:
                    total_files_processed = 0
                    # Use imap_unordered for better performance (we don't care about file order)
                    for result in pool.imap_unordered(scan_file_worker, safe_file_generator(), chunksize=chunk_size):
                        
                        total_files_processed += 1
                        if total_files_processed % PROGRESS_INTERVAL == 0:
                            sys.stdout.write(PROG_FMT.format(total_files_processed))
                            sys.stdout.flush()

                        if result['scanned']:
                            logger.increment_scanned()
                        
                        for m in result['matches']:
                            logger.log("HIT", "DISK", m['rule'], result['path'], meta=m['meta'], strings=m['strings'], source_file=m['namespace'])
                        
                        for w in result['warnings']:
                            logger.log(w[0], w[1], None, w[3], meta={"msg": w[2]})
                            
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Caught Interrupt. Stopping Workers...{Style.RESET_ALL}")
                
                logger.end_phase("Disk")
    
    finally:
        # Cleanup temp rule file
        if temp_rules_path and os.path.exists(temp_rules_path):
            try: os.unlink(temp_rules_path)
            except OSError as e:
                sys.stderr.write(f"[!] Warning: Could not delete temp file: {e}\n")
        
        logger.close()
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Scan Complete{Style.RESET_ALL}")
        print(f"  Files Scanned: {logger.stats['scanned']}")
        print(f"  Detections:    {Fore.RED if logger.stats['hits'] > 0 else Fore.GREEN}{logger.stats['hits']}{Style.RESET_ALL}")
        print(f"  Errors:        {logger.stats['errors']}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()