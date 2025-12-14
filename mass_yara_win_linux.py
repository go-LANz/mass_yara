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

# --- Configuration ---
LOG_FILE = "yara_scan_results.jsonl"
ERROR_LOG_FILE = "yara_compile_errors.log"
MATCH_PREVIEW_LEN = 100

def is_admin():
    """Universal Admin/Root check for Windows and Linux."""
    current_os = platform.system()
    try:
        if current_os == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_file_hash(filepath):
    """Calculates SHA256 of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def log_hit(file_handle, scan_type, match, target_path, extra_metadata=None):
    """Logs hit to JSONL."""
    string_matches = []
    for s in match.strings:
        try:
            offset, identifier, data = s
            if isinstance(data, bytes):
                try:
                    data_str = data.decode('utf-8')
                except UnicodeDecodeError:
                    data_str = f"HEX:{data.hex()}"
            else:
                data_str = str(data)
            
            string_matches.append({
                "offset": offset,
                "identifier": identifier,
                "data": data_str[:MATCH_PREVIEW_LEN]
            })
        except Exception:
            continue

    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": scan_type,
        "rule_name": match.rule,
        "target": target_path,
        "tags": match.tags,
        "rule_meta": match.meta,
        "strings": string_matches,
        "file_meta": extra_metadata or {}
    }

    print(f"[!] HIT: {match.rule} on {target_path}")
    if file_handle:
        file_handle.write(json.dumps(entry) + "\n")
        file_handle.flush()

def compile_rules(rule_dir):
    """
    Iteratively compiles rules. If one fails, it logs the error and continues.
    Returns a compiled YARA rules object.
    """
    if not os.path.isdir(rule_dir):
        print(f"[ERROR] Rule directory '{rule_dir}' not found.")
        sys.exit(1)

    print(f"[*] Compiling rules from: {rule_dir}")
    
    # Initialize the Compiler
    compiler = yara.Compiler()
    
    valid_count = 0
    failed_count = 0
    
    # Prepare the error log
    with open(ERROR_LOG_FILE, "w", encoding="utf-8") as err_log:
        err_log.write(f"--- YARA Compilation Error Log ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n\n")

        for root, _, files in os.walk(rule_dir):
            for file in files:
                if file.lower().endswith(('.yara', '.yar')):
                    full_path = os.path.join(root, file)
                    try:
                        # We use add_file so YARA handles reading the content
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            # Namespace set to filename allows tracking which file a rule came from
                            compiler.add_file(f, namespace=file)
                        valid_count += 1
                    except (yara.SyntaxError, yara.Error, Exception) as e:
                        # Log the failure but do not stop
                        failed_count += 1
                        error_msg = f"[!] Failed: {file} | Error: {str(e)}"
                        print(error_msg)
                        err_log.write(f"{error_msg}\nPath: {full_path}\n{'-'*40}\n")

    print(f"[*] Compilation finished. Valid: {valid_count}, Failed: {failed_count}")
    
    if failed_count > 0:
        print(f"[*] check '{ERROR_LOG_FILE}' for details on failed rules.")

    if valid_count == 0:
        print("[CRITICAL] No valid rules were compiled. Exiting.")
        sys.exit(1)

    try:
        # Build the final rules object
        return compiler.build()
    except yara.Error as e:
        print(f"[CRITICAL] Final build failed (possibly undefined externals): {e}")
        sys.exit(1)

def scan_file_system(rules, path, log_handle):
    print(f"[*] Starting Disk Scan on: {path}")
    start_time = time.time()
    
    iterator = [(os.path.dirname(path), [], [os.path.basename(path)])] if os.path.isfile(path) else os.walk(path)

    for root, _, files in iterator:
        for file in files:
            file_path = os.path.join(root, file)
            try:
                matches = rules.match(file_path)
                if matches:
                    f_size = os.path.getsize(file_path)
                    f_hash = get_file_hash(file_path)
                    disk_meta = {"size_bytes": f_size, "sha256": f_hash}
                    for match in matches:
                        log_hit(log_handle, "DISK", match, file_path, disk_meta)
            except (PermissionError, OSError):
                continue
            except Exception as e:
                print(f"[WARN] Error scanning {file_path}: {e}")

    print(f"[*] Disk scan completed in {time.time() - start_time:.2f} seconds.")

def scan_memory(rules, log_handle):
    print("[*] Starting Memory Scan...")
    if not is_admin():
        print("[WARNING] Not running as Root/Admin. Visibility will be limited.")

    start_time = time.time()
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            pid = proc.info['pid']
            matches = rules.match(pid=pid)
            
            if matches:
                exe_path = proc.info.get('exe') or "Unknown"
                user = proc.info.get('username') or "Unknown"
                target_str = f"{proc.info['name']} (PID: {pid})"
                mem_meta = {"process_path": exe_path, "process_user": user}

                for match in matches:
                    log_hit(log_handle, "MEMORY", match, target_str, mem_meta)
        except (psutil.NoSuchProcess, psutil.AccessDenied, yara.Error):
            continue
        except Exception:
            pass

    print(f"[*] Memory scan completed in {time.time() - start_time:.2f} seconds.")

def main():
    parser = argparse.ArgumentParser(description="Mass YARA Scanner (Fault Tolerant)")
    parser.add_argument('-r', '--rules', required=True, help="Directory containing .yara files")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--path', help="Path to scan (File or Directory)")
    group.add_argument('-m', '--memory', action='store_true', help="Scan running process memory")
    parser.add_argument('-o', '--output', help="Output JSONL file", default=LOG_FILE)
    
    args = parser.parse_args()
    
    if platform.system() == "Darwin":
        print("[!] Warning: Use the macOS specific version for better TCC handling on Macs.")

    # 1. Compile (with fault tolerance)
    yara_rules = compile_rules(args.rules)

    # 2. Scan
    try:
        with open(args.output, 'a', encoding='utf-8') as f:
            if args.memory:
                scan_memory(yara_rules, f)
            elif args.path:
                scan_file_system(yara_rules, args.path, f)
            print(f"[*] Results saved to: {args.output}")
    except Exception as e:
        print(f"[ERROR] Output file error: {e}")

if __name__ == "__main__":
    main()