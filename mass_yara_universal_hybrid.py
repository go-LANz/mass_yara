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
from colorama import init, Fore, Style

init()

# --- Defaults ---
DEFAULT_MAX_SIZE_MB = 50
DEFAULT_MAX_MEM_MB = 2048
DEFAULT_TIMEOUT = 60

# Suppress YARA warnings
warnings.filterwarnings("ignore", category=RuntimeWarning, message="too many matches")

FAST_SCAN_EXTS = {
    '.vbs', '.ps', '.ps1', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl',
    '.crt', '.dll', '.exe', '.hta', '.js', '.lnk', '.msc', '.ocx', '.pcd', '.pif',
    '.reg', '.scr', '.sct', '.sys', '.url', '.vb', '.vbe', '.wsc', '.wsf', '.wsh',
    '.ct', '.t', '.input', '.war', '.jar', '.psd1', '.psm1', '.ps1xml', '.clixml', 
    '.psc1', '.pssc', '.jsp', '.jspx', '.php', '.asp', '.aspx', '.pl', '.www',
    '.doc', '.docx', '.docm', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.pot', '.txt', '.conf', '.cfg', '.config', '.ini', '.pwd', '.w',
    '.log', '.dump', '.tmp', '.rar', '.rdp'
}

DEFAULT_SKIP_EXTS = {
    '.iso', '.vhd', '.vhdx', '.mp4', '.mp3', '.avi', '.mkv', '.db', '.lock', 
    '.wim', '.bmp', '.ttf', '.class', '.jpg', '.png', '.gif'
}

PLATFORM_EXCLUDES = {
    "Linux":  ["/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker"],
    "Darwin": ["/dev", "/Volumes", "/Network", "/private/var/vm", "/cores"],
    "Windows": [] 
}

# --- HTML Template ---
HTML_HEADER = """
<!DOCTYPE html>
<html>
<head>
<title>YARA Triage Report</title>
<style>
    body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; padding: 20px; }
    h2 { border-bottom: 1px solid #555; padding-bottom: 10px; margin-top: 0; }
    .dashboard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
    .card { background-color: #2d2d2d; padding: 15px; border-radius: 6px; border: 1px solid #333; text-align: center; }
    .card .label { display: block; font-size: 0.9em; color: #888; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 1px; }
    .card .value { font-size: 1.8em; font-weight: bold; color: #fff; }
    .card .value.red { color: #f44336; }
    .logs { border-top: 1px solid #333; padding-top: 10px; }
    .hit { color: #f44336; font-weight: bold; } 
    .warn { color: #ff9800; font-weight: bold; } 
    .info { color: #4caf50; } 
    .meta { color: #569cd6; } 
    .row { border-bottom: 1px solid #333; padding: 8px 0; display: block; font-size: 0.95em; }
    .row:hover { background-color: #252526; }
    .timestamp { color: #666; margin-right: 15px; min-width: 80px; display: inline-block; }
    .tag { background-color: #333; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; margin-left: 10px; color: #aaa; }
</style>
</head>
<body>
<div class="dashboard">
    <div class="card"><span class="label">Rules Loaded</span><span id="d_rules" class="value">--</span></div>
    <div class="card"><span class="label">Items Scanned</span><span id="d_scanned" class="value">--</span></div>
    <div class="card"><span class="label">Detections</span><span id="d_hits" class="value red">--</span></div>
    <div class="card"><span class="label">Duration</span><span id="d_time" class="value">--</span></div>
</div>
<h2>Detailed Scan Logs</h2>
<div class="logs">
"""

def is_admin():
    try:
        return (os.geteuid() == 0) if platform.system() != "Windows" else ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

def set_low_priority():
    try:
        p = psutil.Process(os.getpid())
        if platform.system() == "Windows":
            p.nice(psutil.IDLE_PRIORITY_CLASS)
        else:
            os.nice(19)
        if hasattr(p, "cpu_affinity"):
            p.cpu_affinity([0])
        print(f"{Fore.YELLOW}[!] Low Priority Mode Enabled (IDLE Priority + CPU 0){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to set low priority: {e}{Style.RESET_ALL}")

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
        self.stats = {'rules': 0, 'scanned': 0, 'hits': 0, 'start_time': time.time()}
    
    def set_rule_count(self, count):
        self.stats['rules'] = count

    def increment_scanned(self):
        self.stats['scanned'] += 1

    def log(self, level, scan_type, rule_name, target, meta=None, strings=None):
        ts = time.strftime("%H:%M:%S")
        ts_full = time.strftime("%Y-%m-%d %H:%M:%S")
        
        if level == "HIT": 
            term_color = Fore.RED; html_class = "hit"; prefix = "[!] HIT"
            self.stats['hits'] += 1
        elif level == "WARN": 
            term_color = Fore.YELLOW; html_class = "warn"; prefix = "[?] SUSP"
        else: 
            term_color = Fore.GREEN; html_class = "info"; prefix = "[*] INFO"

        print(f"{term_color}{prefix}{Style.RESET_ALL} | {ts} | {scan_type} | {Fore.MAGENTA}{rule_name}{Style.RESET_ALL} | {target}")

        entry = {"timestamp": ts_full, "level": level, "scan_type": scan_type, "rule": rule_name, "target": target, "meta": meta or {}, "strings": strings or []}
        self.json_file.write(json.dumps(entry) + "\n")
        self.json_file.flush()

        safe_target = html.escape(str(target))
        safe_rule = html.escape(str(rule_name))
        safe_meta = html.escape(str(meta)) if meta else ""
        row = f"""<div class="row"><span class="timestamp">{ts}</span><span class="{html_class}">{prefix}</span><span class="meta">[{scan_type}]</span><b>{safe_rule}</b> : {safe_target}<span class="tag" title="{safe_meta}">Meta</span></div>"""
        self.html_file.write(row)
        self.html_file.flush()

    def close(self):
        duration = time.time() - self.stats['start_time']
        duration_str = f"{duration:.2f}s"
        if duration > 60: duration_str = f"{duration/60:.1f}m"

        js_footer = f"""</div><script>
            document.getElementById('d_rules').innerText = "{self.stats['rules']}";
            document.getElementById('d_scanned').innerText = "{self.stats['scanned']}";
            document.getElementById('d_hits').innerText = "{self.stats['hits']}";
            document.getElementById('d_time').innerText = "{duration_str}";
        </script></body></html>"""
        self.html_file.write(js_footer)
        self.html_file.close()
        self.json_file.close()

def compile_rules(rule_dir, out_dir, logger):
    print(f"{Fore.CYAN}[*] Loading rules from: {rule_dir}{Style.RESET_ALL}")
    merged_path = os.path.join(out_dir, "merged_rules.yar")
    valid_count = 0
    
    try:
        with open(merged_path, 'wb') as outfile:
            for root, _, files in os.walk(rule_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, 'rb') as f: content = f.read()
                            yara.compile(source=content.decode('utf-8', 'ignore'))
                            outfile.write(f"\n// SOURCE: {file}\n".encode('utf-8'))
                            outfile.write(content)
                            outfile.write(b"\n")
                            valid_count += 1
                        except yara.SyntaxError as e:
                            logger.log("WARN", "COMPILATION_ERROR", "INVALID_RULE", f"{file}: {e}")
                        except Exception as e:
                            logger.log("WARN", "COMPILATION_ERROR", "BROKEN_FILE", f"{file}: {e}")

        print(f"{Fore.CYAN}[*] Compiled {valid_count} rules.{Style.RESET_ALL}")
        if valid_count == 0:
            logger.log("HIT", "CRITICAL_FAILURE", "NO_RULES", "No valid YARA rules found.")
            sys.exit(1)
        return yara.compile(filepath=merged_path), valid_count
    except Exception as e:
        logger.log("HIT", "CRITICAL_FAILURE", "COMPILER_CRASH", str(e))
        sys.exit(1)

def extract_strings_modern(match_object):
    results = []
    for string_match in match_object.strings:
        try:
            identifier = string_match.identifier
            for instance in string_match.instances:
                data_preview = str(instance.matched_data)[:50]
                results.append({"id": identifier, "offset": instance.offset, "data": data_preview})
        except: continue
    return results

def main():
    parser = argparse.ArgumentParser(description="Mass YARA Triage", formatter_class=argparse.RawTextHelpFormatter)
    input_group = parser.add_argument_group('Input')
    input_group.add_argument('-r', '--rules', required=True, metavar='DIR', help="Directory containing .yara rule files")
    
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-p', '--path', metavar='DIR', help="Scan a directory or file on disk")
    target_group.add_argument('-m', '--memory', action='store_true', help="Scan memory (Linux/Windows only)")

    opt_group = parser.add_argument_group('Optimization')
    opt_group.add_argument('--fast', action='store_true', help="FAST MODE: Scan only EVIL_EXTENSIONS")
    opt_group.add_argument('--low-priority', action='store_true', help="THROTTLE: Use only 1 CPU core and Low Priority")
    opt_group.add_argument('--known-good', metavar='FILE', help="SHA256 hash list to IGNORE")
    opt_group.add_argument('--max-size', type=int, default=DEFAULT_MAX_SIZE_MB, metavar='MB', help=f"Max file size MB (Default: {DEFAULT_MAX_SIZE_MB})")
    opt_group.add_argument('--max-mem', type=int, default=DEFAULT_MAX_MEM_MB, metavar='MB', help=f"Max Process RAM MB (Default: {DEFAULT_MAX_MEM_MB})")

    out_group = parser.add_argument_group('Output')
    out_group.add_argument('-o', '--out-dir', default=".", metavar='DIR', help="Output directory")

    args = parser.parse_args()
    
    if not args.path and not args.memory: parser.error("You must specify at least one target: --path, --memory, or both.")
    if not os.path.exists(args.out_dir): 
        try: os.makedirs(args.out_dir)
        except OSError as e: sys.exit(f"{Fore.RED}[CRITICAL] Cannot create output dir: {e}{Style.RESET_ALL}")

    if args.low_priority:
        set_low_priority()

    json_path = os.path.join(args.out_dir, "scan.jsonl")
    html_path = os.path.join(args.out_dir, "scan_report.html")
    logger = DualLogger(json_path, html_path)
    
    rules, rule_count = compile_rules(args.rules, args.out_dir, logger)
    logger.set_rule_count(rule_count)
    
    known_hashes = load_known_good(args.known_good)
    max_file_bytes = args.max_size * 1024 * 1024
    max_mem_bytes  = args.max_mem * 1024 * 1024
    current_os = platform.system()
    
    mode_str = "FAST (Allowlist)" if args.fast else "DEEP (Blocklist)"
    print(f"{Fore.GREEN}[*] Engine Started. Mode: {mode_str}. Logs: {args.out_dir}{Style.RESET_ALL}")

    try:
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
                        
                        logger.increment_scanned()
                        masq = check_process_masquerade(proc)
                        if masq: logger.log("WARN", "PROC_ANOMALY", "Masquerade_Check", masq)

                        matches = rules.match(pid=pid, timeout=DEFAULT_TIMEOUT, fast=True)
                        
                        for m in matches:
                            name = proc.info['name'] or f"PID:{pid}"
                            strs = extract_strings_modern(m)
                            logger.log("HIT", "MEMORY", m.rule, f"{name} ({pid})", strings=strs)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
                    except yara.TimeoutError:
                        # Fetch name safely from cache or set fallback
                        pname = proc.info.get('name') or "Unknown"
                        logger.log("WARN", "MEMORY_TIMEOUT", "SKIP", f"PID {proc.info['pid']} ({pname}) timed out.")
                    except Exception as e:
                        # Fetch name safely from cache or set fallback
                        pname = proc.info.get('name') or "Unknown"
                        logger.log("WARN", "MEMORY_ERR", "SCAN_FAIL", f"PID {proc.info['pid']} ({pname}) error: {str(e)}")

        if args.path:
            print(f"{Fore.CYAN}[*] Starting Disk Scan: {args.path}{Style.RESET_ALL}")
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
                        
                        logger.increment_scanned()
                        size = os.path.getsize(path)
                        if size > max_file_bytes: continue
                        
                        f_hash = None
                        if known_hashes:
                            f_hash = get_file_hash(path)
                            if f_hash and f_hash in known_hashes: continue 
                        
                        matches = rules.match(path, timeout=DEFAULT_TIMEOUT)
                        if matches:
                            if not f_hash: f_hash = get_file_hash(path)
                            meta = {"sha256": f_hash, "size": size}
                            for m in matches: 
                                strs = extract_strings_modern(m)
                                logger.log("HIT", "DISK", m.rule, path, meta, strs)

                    except (PermissionError, OSError): continue
                    except yara.TimeoutError:
                        logger.log("WARN", "DISK_TIMEOUT", "SKIP", f"{path} timed out.")
                    except Exception as e:
                        logger.log("WARN", "DISK_ERR", "SCAN_FAIL", f"{path} error: {e}")

    except KeyboardInterrupt: print(f"\n{Fore.YELLOW}[!] Stopping...{Style.RESET_ALL}")
    finally: logger.close(); print(f"{Fore.GREEN}[*] Scan Finished.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()