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
import errno
from colorama import init, Fore, Style

init()

# --- Defaults ---
DEFAULT_MAX_SIZE_MB = 100
DEFAULT_MAX_MEM_MB = 2048
DEFAULT_TIMEOUT = 60
NOISY_RULE_THRESHOLD = 50 

warnings.filterwarnings("ignore", category=RuntimeWarning, message="too many matches")

FAST_SCAN_EXTS = {
    '.vbs', '.ps', '.ps1', '.rar', '.bas', '.bat', '.chm', '.cmd', '.com', '.cpl',
    '.crt', '.dll', '.exe', '.hta', '.js', '.lnk', '.msc', '.ocx', '.pcd', '.pif', '.pot',
    '.reg', '.scr', '.sct', '.sys', '.url', '.vb', '.vbe', '.wsc', '.wsf', '.wsh', '.ct', '.t',
    '.input', '.war', '.jsp', '.jspx', '.php', '.asp', '.aspx', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt',
    '.pptx', '.tmp', '.log', '.dump', '.pwd', '.w', '.txt', '.cfg', '.conf', '.config', '.psd1',
    '.psm1', '.ps1xml', '.clixml', '.psc1', '.pssc', '.pl', '.www', '.rdp', '.jar', '.docm', '.sys', '.bin',
    '.elf', '.py', '.sh', '.dat'
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
<title>YARA Scan Report</title>
<style>
    body { background-color: #1e1e1e; color: #d4d4d4; font-family: 'Consolas', 'Courier New', monospace; padding: 20px; }
    h2 { border-bottom: 1px solid #555; padding-bottom: 10px; margin-top: 30px; }
    
    .meta-box { background-color: #252526; padding: 15px; border-radius: 6px; border: 1px solid #333; margin-bottom: 20px; font-size: 0.9em; }
    .meta-row { margin-bottom: 5px; }
    .meta-label { color: #888; display: inline-block; width: 100px; }
    .meta-val { color: #fff; font-weight: bold; }
    .cmd-text { color: #ce9178; font-family: monospace; background: #1e1e1e; padding: 2px 6px; border-radius: 4px; }

    .dashboard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
    .card { background-color: #2d2d2d; padding: 15px; border-radius: 6px; border: 1px solid #333; text-align: center; }
    .card .label { display: block; font-size: 0.9em; color: #888; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 1px; }
    .card .value { font-size: 1.8em; font-weight: bold; color: #fff; }
    .card .value.red { color: #f44336; }
    
    .logs { border-top: 1px solid #333; padding-top: 10px; }
    .hit { color: #f44336; font-weight: bold; }   
    .sus { color: #ff9800; font-weight: bold; }   
    .warn { color: #ffeb3b; font-weight: bold; }  
    .info { color: #4caf50; }                     
    
    .meta { color: #569cd6; } 
    .source { color: #9cdcfe; font-size: 0.9em; margin-right: 10px; } /* New style for source file */
    
    .row { border-bottom: 1px solid #333; padding: 8px 0; display: block; font-size: 0.95em; }
    .row:hover { background-color: #252526; }
    .timestamp { color: #666; margin-right: 15px; min-width: 80px; display: inline-block; }
    .tag { background-color: #333; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; margin-left: 10px; color: #aaa; }
    
    .noisy-box { margin-top: 20px; padding: 10px; background-color: #332b00; border: 1px solid #ffeb3b; border-radius: 4px; display: none; }
    .noisy-title { color: #ffeb3b; font-weight: bold; display: block; margin-bottom: 5px; }
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

def is_admin():
    try:
        return (os.geteuid() == 0) if platform.system() != "Windows" else ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError: return False
    except Exception: return False

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

def is_safe_path(filepath, base_path):
    try:
        real_path = os.path.realpath(filepath)
        real_base = os.path.realpath(base_path)
        return real_path.startswith(real_base)
    except Exception: return False

def get_file_hash(filepath, logger=None):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        if logger: logger.log("WARN", "HASH_ERR", "ACCESS_DENIED", filepath)
        return None
    except OSError as e:
        if logger: logger.log("WARN", "HASH_ERR", "OS_ERROR", f"{filepath}: {e}")
        return None
    except Exception as e:
        if logger: logger.log("WARN", "HASH_ERR", "UNKNOWN", f"{filepath}: {e}")
        return None

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

def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f} sec"
    elif seconds < 3600:
        return f"{seconds/60:.1f} min"
    else:
        return f"{seconds/3600:.2f} hrs"

class DualLogger:
    def __init__(self, out_dir, cmd_args):
        # Generate Dynamic Filenames
        self.hostname = platform.node()
        self.start_time_obj = time.time()
        self.start_str = time.strftime("%Y-%m-%d %H:%M:%S")
        ts_file = time.strftime("%Y%m%d_%H%M%S")
        
        json_name = f"scan_{self.hostname}_{ts_file}.jsonl"
        html_name = f"scan_{self.hostname}_{ts_file}.html"
        
        json_path = os.path.join(out_dir, json_name)
        html_path = os.path.join(out_dir, html_name)
        
        print(f"{Fore.GREEN}[*] Log File: {json_name}{Style.RESET_ALL}")
        
        self.json_file = open(json_path, 'a', encoding='utf-8', buffering=1)
        self.html_file = open(html_path, 'w', encoding='utf-8', buffering=1)
        self.html_file.write(HTML_HEADER)
        
        self.cmd_args_raw = " ".join(cmd_args)
        
        self.stats = {'rules': 0, 'scanned': 0, 'hits': 0}
        self.rule_hit_counts = {} 
        self.noisy_rules = [] 
    
    def set_rule_count(self, count):
        self.stats['rules'] = count

    def increment_scanned(self):
        self.stats['scanned'] += 1

    def log(self, level, scan_type, rule_name, target, meta=None, strings=None, source_file=None):
        ts = time.strftime("%H:%M:%S")
        ts_full = time.strftime("%Y-%m-%d %H:%M:%S")

        # Noisy Rule Detection
        if level == "HIT" and rule_name:
            if rule_name not in self.rule_hit_counts:
                self.rule_hit_counts[rule_name] = 0
            
            self.rule_hit_counts[rule_name] += 1
            
            if self.rule_hit_counts[rule_name] > NOISY_RULE_THRESHOLD:
                return 
            
            if self.rule_hit_counts[rule_name] == NOISY_RULE_THRESHOLD:
                self.noisy_rules.append(rule_name) 
                level = "WARN"
                prefix = "[-] WARN"
                term_color = Fore.YELLOW
                html_class = "warn"
                scan_type = "NOISY_RULE"
                target = f"Rule '{rule_name}' hit limit ({NOISY_RULE_THRESHOLD}). Squelching."
                meta = {"original_target": str(target)}
            else:
                term_color = Fore.RED; html_class = "hit"; prefix = "[!] HIT"
                self.stats['hits'] += 1
        
        elif level == "SUS": 
            term_color = Fore.LIGHTRED_EX; html_class = "sus"; prefix = "[?] SUS"
        elif level == "WARN":
            term_color = Fore.YELLOW; html_class = "warn"; prefix = "[-] WARN"
        else: 
            term_color = Fore.GREEN; html_class = "info"; prefix = "[*] INFO"

        print(f"{term_color}{prefix}{Style.RESET_ALL} | {ts} | {scan_type} | {Fore.MAGENTA}{rule_name or ''}{Style.RESET_ALL} | {target}")

        entry = {
            "timestamp": ts_full, 
            "level": level, 
            "scan_type": scan_type, 
            "rule": rule_name, 
            "source_file": source_file,  # <--- NEW FIELD
            "target": target, 
            "meta": meta or {}, 
            "strings": strings or []
        }
        self.json_file.write(json.dumps(entry) + "\n")
        
        safe_target = html.escape(str(target))
        safe_rule = html.escape(str(rule_name))
        safe_meta = html.escape(json.dumps(meta, sort_keys=True)) if meta else ""
        
        # NEW HTML formatting to include source file
        source_display = f'<span class="source">{html.escape(source_file)}</span>' if source_file else ""
        
        row = f"""<div class="row"><span class="timestamp">{ts}</span><span class="{html_class}">{prefix}</span><span class="meta">[{scan_type}]</span>{source_display}<b>{safe_rule}</b> : {safe_target}<span class="tag" title="{safe_meta}">Meta</span></div>"""
        self.html_file.write(row)
        self.html_file.flush()

    def close(self):
        end_time_obj = time.time()
        end_str = time.strftime("%Y-%m-%d %H:%M:%S")
        duration = end_time_obj - self.start_time_obj
        duration_fmt = format_duration(duration)

        safe_cmd_js = json.dumps(self.cmd_args_raw)
        noisy_js_array = json.dumps(self.noisy_rules)
        
        js_footer = f"""
        </div>
        <script>
            document.getElementById('m_host').innerText = "{self.hostname}";
            document.getElementById('m_start').innerText = "{self.start_str}";
            document.getElementById('m_end').innerText = "{end_str}";
            document.getElementById('m_cmd').innerText = {safe_cmd_js}; 
            
            document.getElementById('d_rules').innerText = "{self.stats['rules']}";
            document.getElementById('d_scanned').innerText = "{self.stats['scanned']}";
            document.getElementById('d_hits').innerText = "{self.stats['hits']}";
            document.getElementById('d_time').innerText = "{duration_fmt}";
            
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

def compile_rules(rule_dir, logger):
    print(f"{Fore.CYAN}[*] Loading rules from: {rule_dir}{Style.RESET_ALL}")
    sources = {}
    valid_count = 0
    total_files = 0
    
    for root, _, files in os.walk(rule_dir):
        for file in files:
            if file.endswith(('.yar', '.yara')):
                total_files += 1
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source_code = f.read()
                    try:
                        yara.compile(source=source_code)
                        # The filename (relative path) becomes the Namespace key
                        rel_path = os.path.relpath(full_path, rule_dir)
                        sources[rel_path] = source_code
                        valid_count += 1
                    except yara.SyntaxError as e:
                        logger.log("WARN", "COMPILATION_ERROR", "SYNTAX", f"{file}: {e}")
                    except yara.Error as e:
                        logger.log("WARN", "COMPILATION_ERROR", "YARA_ERR", f"{file}: {e}")
                except Exception as e:
                    logger.log("WARN", "COMPILATION_ERROR", "READ_FAIL", f"{file}: {e}")

    try:
        print(f"{Fore.CYAN}[*] Compiling {valid_count}/{total_files} rules sources...{Style.RESET_ALL}")
        if not sources:
            print(f"{Fore.RED}[!] No valid rules found.{Style.RESET_ALL}")
            sys.exit(1)
        
        # We assume files don't reference each other (no includes)
        compiled_rules = yara.compile(sources=sources)
        print(f"{Fore.CYAN}[*] Build Complete.{Style.RESET_ALL}")
        return compiled_rules, valid_count
    
    except yara.Error as e:
        logger.log("HIT", "CRITICAL_FAILURE", "LINKER_ERROR", str(e))
        print(f"{Fore.RED}[!] Critical Linker Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        logger.log("HIT", "CRITICAL_FAILURE", "BUILDER_CRASH", str(e))
        sys.exit(1)

def extract_strings_modern(match_object):
    results = []
    try:
        for string_match in match_object.strings:
            try:
                identifier = string_match.identifier
                for instance in string_match.instances:
                    data_raw = instance.matched_data
                    try:
                        data_preview = str(data_raw)[:50]
                    except Exception:
                        data_preview = f"HEX:{data_raw.hex()[:50]}"
                    results.append({"id": identifier, "offset": instance.offset, "data": data_preview})
            except Exception as e:
                results.append({"id": "ERROR", "offset": 0, "data": f"<<STRING_READ_ERR: {str(e)}>>"})
    except Exception as e:
        results.append({"id": "CRITICAL", "offset": 0, "data": f"<<OBJ_READ_ERR: {str(e)}>>"})
    return results

def main():
    parser = argparse.ArgumentParser(description="Mass YARA Scanner", formatter_class=argparse.RawTextHelpFormatter)
    input_group = parser.add_argument_group('Input')
    input_group.add_argument('-r', '--rules', required=True, metavar='DIR', help="Directory containing .yara rule files")
    
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-p', '--path', metavar='DIR', help="Scan a directory or file on disk")
    target_group.add_argument('-m', '--memory', action='store_true', help="Scan memory (Linux/Windows only)")

    opt_group = parser.add_argument_group('Optimization')
    opt_group.add_argument('--fast', action='store_true', help="Enable Fast Mode (Short-circuit on 1st match)")
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

    # Logger now handles filename generation based on host/time
    logger = DualLogger(args.out_dir, sys.argv)
    
    rules, rule_count = compile_rules(args.rules, logger)
    logger.set_rule_count(rule_count)
    
    known_hashes = load_known_good(args.known_good)
    max_file_bytes = args.max_size * 1024 * 1024
    max_mem_bytes  = args.max_mem * 1024 * 1024
    current_os = platform.system()
    
    use_fast_mode = args.fast
    mode_str = "FAST (Short-Circuit)" if use_fast_mode else "DEEP (Exhaustive)"
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
                        
                        rss_size = proc.info['memory_info'].rss
                        if rss_size > max_mem_bytes:
                             logger.log("WARN", "MEMORY_SKIP", "SIZE_LIMIT", f"PID {pid} too large ({rss_size//1024//1024}MB)")
                             continue
                        
                        logger.increment_scanned()
                        
                        matches = rules.match(pid=pid, timeout=DEFAULT_TIMEOUT, fast=use_fast_mode)
                        
                        for m in matches:
                            name = proc.info['name'] or f"PID:{pid}"
                            strs = extract_strings_modern(m)
                            # Pass m.namespace as the source file
                            logger.log("HIT", "MEMORY", m.rule, f"{name} ({pid})", strings=strs, source_file=m.namespace)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
                    except yara.TimeoutError:
                        pname = proc.info.get('name') or "Unknown"
                        logger.log("WARN", "MEMORY_TIMEOUT", "SKIP", f"PID {proc.info['pid']} ({pname}) timed out.")
                    except Exception as e:
                        pname = proc.info.get('name') or "Unknown"
                        logger.log("WARN", "MEMORY_ERR", "SCAN_FAIL", f"PID {proc.info['pid']} ({pname}) error: {str(e)}")

        if args.path:
            print(f"{Fore.CYAN}[*] Starting Disk Scan: {args.path}{Style.RESET_ALL}")
            scan_iter = os.walk(args.path, topdown=True) if os.path.isdir(args.path) else [(os.path.dirname(args.path), [], [os.path.basename(args.path)])]
            for root, dirs, files in scan_iter:
                dirs[:] = [d for d in dirs if not should_exclude_path(os.path.join(root, d), current_os)]
                for file in files:
                    path = os.path.join(root, file)
                    if not is_safe_path(path, args.path):
                        logger.log("SUS", "SECURITY_SKIP", "PATH_TRAVERSAL", f"Blocked unsafe path: {path}")
                        continue
                    if os.path.islink(path): continue
                    try:
                        ext = os.path.splitext(file)[1].lower()
                        if args.fast:
                            if ext not in FAST_SCAN_EXTS: continue
                        else:
                            if ext in DEFAULT_SKIP_EXTS: continue
                        
                        logger.increment_scanned()
                        
                        try: size = os.path.getsize(path)
                        except OSError: continue 
                        
                        if size > max_file_bytes:
                            logger.log("WARN", "DISK_SKIP", "SIZE_LIMIT", path)
                            continue
                            
                        f_hash = None
                        if known_hashes:
                            f_hash = get_file_hash(path, logger)
                            if f_hash is None or f_hash in known_hashes: continue 
                        
                        matches = rules.match(path, timeout=DEFAULT_TIMEOUT, fast=use_fast_mode)
                        
                        if matches:
                            if f_hash is None: f_hash = get_file_hash(path, logger)
                            meta = {"sha256": f_hash or "HASH_FAILED", "size": size}
                            for m in matches: 
                                strs = extract_strings_modern(m)
                                # Pass m.namespace as the source file
                                logger.log("HIT", "DISK", m.rule, path, meta, strs, source_file=m.namespace)
                                
                    except PermissionError: logger.log("WARN", "DISK_ACCESS", "PERM_DENIED", path)
                    except OSError as e:
                        if e.errno != errno.ENOENT: logger.log("WARN", "DISK_ACCESS", "OS_ERROR", f"{path}: {e}")
                    except yara.TimeoutError: logger.log("WARN", "DISK_TIMEOUT", "SKIP", f"{path} timed out.")
                    except Exception as e: logger.log("WARN", "DISK_ERR", "SCAN_FAIL", f"{path} error: {e}")

    except KeyboardInterrupt: print(f"\n{Fore.YELLOW}[!] Stopping...{Style.RESET_ALL}")
    finally: logger.close(); print(f"{Fore.GREEN}[*] Scan Finished.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()