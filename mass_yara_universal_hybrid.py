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
from colorama import init, Fore, Style

init()

# --- Defaults ---
DEFAULT_MAX_SIZE_MB = 100
DEFAULT_MAX_MEM_MB = 2048

# MODE A: BLOCKLIST (Deep Scan Default)
DEFAULT_SKIP_EXTS = {'.iso', '.vhd', '.vhdx', '.mp4', '.mp3', '.avi', '.mkv', '.db', '.lock', '.wim', '.bmp', '.ttf', '.class'}

# MODE B: ALLOWLIST (Fast Scan)
FAST_SCAN_EXTS = {
    # Scripts & Executables
    '.vbs', '.ps', '.ps1', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl',
    '.crt', '.dll', '.exe', '.hta', '.js', '.lnk', '.msc', '.ocx', '.pcd', '.pif',
    '.reg', '.scr', '.sct', '.sys', '.url', '.vb', '.vbe', '.wsc', '.wsf', '.wsh',
    '.ct', '.t', '.input', '.war', '.jar',
    # PowerShell Specific
    '.psd1', '.psm1', '.ps1xml', '.clixml', '.psc1', '.pssc',
    # Web / Code
    '.jsp', '.jspx', '.php', '.asp', '.aspx', '.pl', '.www',
    # Documents / Configs / Data
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.pot', '.txt', '.conf', '.cfg', '.config', '.ini', '.pwd', '.w',
    '.log', '.dump', '.tmp', '.rar', '.rdp'
}

PLATFORM_EXCLUDES = {
    "Linux":  ["/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker"],
    "Darwin": ["/dev", "/Volumes", "/Network", "/private/var/vm", "/cores"],
    "Windows": [] 
}

HTML_HEADER = """
<!DOCTYPE html>
<html>
<head>
<title>YARA Scan Report</title>
<style>
    body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; padding: 20px; }
    h2 { border-bottom: 1px solid #555; padding-bottom: 10px; }
    .hit { color: #f44336; font-weight: bold; } /* Red */
    .warn { color: #ff9800; font-weight: bold; } /* Orange */
    .info { color: #4caf50; } /* Green */
    .meta { color: #569cd6; } /* Blue */
    .row { border-bottom: 1px solid #333; padding: 6px 0; display: block; }
    .timestamp { color: #808080; margin-right: 15px; }
    .tag { background-color: #333; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; margin-left: 10px; }
</style>
</head>
<body>
<h2>Mass YARA Scanner Report</h2>
<div class="logs">
"""
HTML_FOOTER = "</div></body></html>"

def is_admin():
    try:
        return (os.geteuid() == 0) if platform.system() != "Windows" else ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

def get_file_hash(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except: return None

def load_known_good(path):
    hashes = set()
    if path and os.path.exists(path):
        print(f"{Fore.CYAN}[*] Loading Known-Good Database: {path}{Style.RESET_ALL}")
        try:
            with open(path, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    h = parts[0].strip().lower()
                    if len(h) == 64: hashes.add(h)
            print(f"{Fore.CYAN}[*] Loaded {len(hashes)} unique hashes to skip.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading database: {e}{Style.RESET_ALL}")
    return hashes

def should_exclude_path(root_path, current_os):
    excludes = PLATFORM_EXCLUDES.get(current_os, [])
    norm_root = os.path.abspath(root_path)
    for ex in excludes:
        if norm_root == ex or norm_root.startswith(ex + os.sep):
            return True
    return False

def check_process_masquerade(proc_obj):
    SYSTEM_MAP = {
        "svchost.exe":  ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
        "csrss.exe":    ["c:\\windows\\system32\\"],
        "wininit.exe":  ["c:\\windows\\system32\\"],
        "smss.exe":     ["c:\\windows\\system32\\"],
        "services.exe": ["c:\\windows\\system32\\"],
        "lsass.exe":    ["c:\\windows\\system32\\"],
        "winlogon.exe": ["c:\\windows\\system32\\"],
        "explorer.exe": ["c:\\windows\\"]
    }
    try:
        name = (proc_obj.info['name'] or "").lower()
        exe = (proc_obj.info['exe'] or "").lower()
        if name in SYSTEM_MAP:
            if not any(exe.startswith(p) for p in SYSTEM_MAP[name]):
                return f"MASQUERADE DETECTED: {name} running from {exe}"
    except: pass
    return None

class DualLogger:
    def __init__(self, json_path, html_path):
        self.json_file = open(json_path, 'a', encoding='utf-8')
        self.html_file = open(html_path, 'w', encoding='utf-8')
        self.html_file.write(HTML_HEADER)
    
    def log(self, level, scan_type, rule_name, target, meta=None, strings=None):
        ts = time.strftime("%H:%M:%S")
        ts_full = time.strftime("%Y-%m-%d %H:%M:%S")
        if level == "HIT": term_color = Fore.RED; html_class = "hit"; prefix = "[!] HIT"
        elif level == "WARN": term_color = Fore.YELLOW; html_class = "warn"; prefix = "[?] SUSP"
        else: term_color = Fore.GREEN; html_class = "info"; prefix = "[*] INFO"

        print(f"{term_color}{prefix}{Style.RESET_ALL} | {ts} | {scan_type} | {Fore.MAGENTA}{rule_name}{Style.RESET_ALL} | {target}")

        entry = {"timestamp": ts_full, "level": level, "scan_type": scan_type, "rule": rule_name, "target": target, "meta": meta or {}, "strings": strings or []}
        self.json_file.write(json.dumps(entry) + "\n"); self.json_file.flush()

        safe_target = html.escape(target)
        safe_rule = html.escape(str(rule_name))
        safe_meta = html.escape(str(meta)) if meta else ""
        row = f"""<div class="row"><span class="timestamp">{ts}</span><span class="{html_class}">{prefix}</span><span class="meta">[{scan_type}]</span><b>{safe_rule}</b> : {safe_target}<span class="tag" title="{safe_meta}">Meta</span></div>"""
        self.html_file.write(row); self.html_file.flush()

    def close(self):
        self.html_file.write(HTML_FOOTER); self.html_file.close(); self.json_file.close()

def compile_rules(rule_dir):
    print(f"{Fore.CYAN}[*] Compiling rules from: {rule_dir}{Style.RESET_ALL}")
    valid = {}
    for r, _, fs in os.walk(rule_dir):
        for f in fs:
            if f.endswith(('.yar', '.yara')):
                p = os.path.join(r, f)
                try:
                    yara.compile(source=open(p, 'rb').read().decode('utf-8', 'ignore'))
                    valid[f] = p
                except: pass
    if not valid:
        print(f"{Fore.RED}[ERROR] No valid rules found.{Style.RESET_ALL}")
        sys.exit(1)
    return yara.compile(filepaths=valid)

def main():
    parser = argparse.ArgumentParser(description="Mass YARA Scanner", formatter_class=argparse.RawTextHelpFormatter)
    input_group = parser.add_argument_group('Input')
    input_group.add_argument('-r', '--rules', required=True, metavar='DIR', help="Directory containing .yara rule files")
    
    # CHANGED: No longer Mutually Exclusive
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-p', '--path', metavar='DIR', help="Scan a directory or file on disk")
    target_group.add_argument('-m', '--memory', action='store_true', help="Scan memory (Linux/Windows only)")

    opt_group = parser.add_argument_group('Optimization')
    opt_group.add_argument('--fast', action='store_true', help="FAST MODE: Scan only EVIL_EXTENSIONS")
    opt_group.add_argument('--known-good', metavar='FILE', help="SHA256 hash list to IGNORE")
    opt_group.add_argument('--max-size', type=int, default=DEFAULT_MAX_SIZE_MB, metavar='MB', help=f"Max file size MB (Default: {DEFAULT_MAX_SIZE_MB})")
    opt_group.add_argument('--max-mem', type=int, default=DEFAULT_MAX_MEM_MB, metavar='MB', help=f"Max Process RAM MB (Default: {DEFAULT_MAX_MEM_MB})")

    out_group = parser.add_argument_group('Output')
    out_group.add_argument('-o', '--out-dir', default=".", metavar='DIR', help="Output directory")

    args = parser.parse_args()
    
    # Validating that at least ONE target is selected
    if not args.path and not args.memory:
        parser.error("You must specify at least one target: --path, --memory, or both.")

    if not os.path.exists(args.out_dir): os.makedirs(args.out_dir)
    json_path = os.path.join(args.out_dir, "scan.jsonl")
    html_path = os.path.join(args.out_dir, "scan_report.html")
    logger = DualLogger(json_path, html_path)
    
    rules = compile_rules(args.rules)
    known_hashes = load_known_good(args.known_good)
    max_file_bytes = args.max_size * 1024 * 1024
    max_mem_bytes  = args.max_mem * 1024 * 1024
    current_os = platform.system()
    
    mode_str = "FAST (Allowlist)" if args.fast else "DEEP (Blocklist)"
    print(f"{Fore.GREEN}[*] Engine Started. Mode: {mode_str}. Logs: {args.out_dir}{Style.RESET_ALL}")

    try:
        # STEP 1: MEMORY SCAN (Volatile Data First)
        if args.memory:
            if current_os == "Darwin":
                print(f"{Fore.YELLOW}[!] INFO: MacOS memory scan not supported. Ignoring.{Style.RESET_ALL}")
            else:
                my_pid = os.getpid()
                print(f"{Fore.CYAN}[*] Starting Memory Scan (PID Excl: {my_pid})...{Style.RESET_ALL}")
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'memory_info']):
                    try:
                        pid = proc.info['pid']
                        if current_os == "Windows" and pid in [0, 4]: continue
                        if pid == my_pid: continue
                        if proc.info['memory_info'].rss > max_mem_bytes: continue
                        
                        masq = check_process_masquerade(proc)
                        if masq: logger.log("WARN", "PROC_ANOMALY", "Masquerade_Check", masq)

                        matches = rules.match(pid=pid)
                        for m in matches:
                            name = proc.info['name'] or f"PID:{pid}"
                            logger.log("HIT", "MEMORY", m.rule, f"{name} ({pid})")
                    except: continue

        # STEP 2: DISK SCAN (Persistent Data Second)
        if args.path:
            print(f"{Fore.CYAN}[*] Starting Disk Scan: {args.path}{Style.RESET_ALL}")
            if current_os in PLATFORM_EXCLUDES:
                print(f"{Fore.CYAN}[*] Platform Exclusions: {PLATFORM_EXCLUDES[current_os]}{Style.RESET_ALL}")

            scan_iter = os.walk(args.path, topdown=True) if os.path.isdir(args.path) else [(os.path.dirname(args.path), [], [os.path.basename(args.path)])]
            
            for root, dirs, files in scan_iter:
                dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d), current_os)]

                for file in files:
                    path = os.path.join(root, file)
                    try:
                        ext = os.path.splitext(file)[1].lower()
                        
                        if args.fast:
                            if ext not in FAST_SCAN_EXTS: continue
                        else:
                            if ext in DEFAULT_SKIP_EXTS: continue

                        size = os.path.getsize(path)
                        if size > max_file_bytes: continue
                        
                        f_hash = None
                        if known_hashes:
                            f_hash = get_file_hash(path)
                            if f_hash and f_hash in known_hashes: continue 
                        
                        matches = rules.match(path)
                        if matches:
                            if not f_hash: f_hash = get_file_hash(path)
                            meta = {"sha256": f_hash, "size": size}
                            strs = [{"data": str(s[2])[:50]} for m in matches for s in m.strings]
                            for m in matches: logger.log("HIT", "DISK", m.rule, path, meta, strs)
                    except: continue

    except KeyboardInterrupt: print("\nStopping...")
    finally: logger.close(); print(f"{Fore.GREEN}[*] Done.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()