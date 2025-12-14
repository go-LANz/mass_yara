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

# --- Default Filenames ---
FILENAME_JSON   = "yara_scan_results.jsonl"
FILENAME_ERRORS = "yara_compile_errors.log"
FILENAME_MERGED = "merged_rules_debug.yara"
MATCH_PREVIEW_LEN = 100

def is_admin():
    current_os = platform.system()
    try:
        if current_os == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_file_hash(filepath):
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def log_hit(file_handle, scan_type, match, target_path, extra_metadata=None):
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

def compile_rules_robust(rule_dir, error_path, merged_path):
    if not os.path.isdir(rule_dir):
        print(f"[ERROR] Rule directory '{rule_dir}' not found.")
        sys.exit(1)

    print(f"[*] Pre-checking rules in: {rule_dir}")
    
    valid_files = {}
    failed_count = 0
    
    try:
        err_log = open(error_path, "w", encoding="utf-8")
        merged_file = open(merged_path, "w", encoding="utf-8")
        
        err_log.write(f"--- YARA Compilation Error Log ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n\n")
        merged_file.write(f"// AUTO-MERGED YARA RULES | Source: {rule_dir}\n")
        merged_file.write(f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for root, _, files in os.walk(rule_dir):
            for file in files:
                if file.lower().endswith(('.yara', '.yar')):
                    full_path = os.path.join(root, file)
                    namespace = "".join(x for x in file if x.isalnum()) 

                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            source_content = f.read()
                        
                        yara.compile(source=source_content)
                        valid_files[namespace] = full_path
                        
                        merged_file.write(f"\n// -------------------------------------------------\n")
                        merged_file.write(f"// FILE: {file}\n")
                        merged_file.write(f"// -------------------------------------------------\n")
                        merged_file.write(source_content + "\n")
                        
                    except Exception as e:
                        failed_count += 1
                        print(f"[!] Invalid Rule: {file} (Skipping)")
                        err_log.write(f"File: {full_path}\nError: {str(e)}\n{'-'*40}\n")
                        
    except Exception as e:
        print(f"[CRITICAL] Failed to write logs: {e}")
        sys.exit(1)
    finally:
        err_log.close()
        merged_file.close()

    print(f"[*] Pre-check finished. Valid: {len(valid_files)}, Failed: {failed_count}")
    
    if len(valid_files) == 0:
        print("[CRITICAL] No valid rules found. Exiting.")
        sys.exit(1)

    print("[*] Building final engine...")
    try:
        return yara.compile(filepaths=valid_files)
    except Exception as e:
        print(f"[CRITICAL] Final link failed: {e}")
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
    
    # 1. Identify SELF to avoid scanning our own memory
    my_pid = os.getpid()
    print(f"[*] Excluding own PID from scan: {my_pid}")

    if not is_admin():
        print("[WARNING] Not running as Root/Admin. Visibility will be limited.")

    start_time = time.time()
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            pid = proc.info['pid']
            
            # 2. Skip Self
            if pid == my_pid:
                continue

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
    parser = argparse.ArgumentParser(description="Mass YARA Scanner (Self-Excluding)")
    parser.add_argument('-r', '--rules', required=True, help="Directory containing .yara files")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--path', help="Path to scan (File or Directory)")
    group.add_argument('-m', '--memory', action='store_true', help="Scan running process memory")
    parser.add_argument('-d', '--output-dir', help="Folder to save all logs and merged files", default=".")

    args = parser.parse_args()

    out_dir = args.output_dir
    if not os.path.exists(out_dir):
        try:
            os.makedirs(out_dir)
            print(f"[*] Created output directory: {out_dir}")
        except OSError as e:
            print(f"[ERROR] Could not create output directory: {e}")
            sys.exit(1)

    path_json   = os.path.join(out_dir, FILENAME_JSON)
    path_errors = os.path.join(out_dir, FILENAME_ERRORS)
    path_merged = os.path.join(out_dir, FILENAME_MERGED)

    yara_rules = compile_rules_robust(args.rules, path_errors, path_merged)

    try:
        with open(path_json, 'a', encoding='utf-8') as f:
            if args.memory:
                scan_memory(yara_rules, f)
            elif args.path:
                scan_file_system(yara_rules, args.path, f)
            print(f"[*] Scan finished. Results saved to: {path_json}")
    except Exception as e:
        print(f"[ERROR] Failed to write results: {e}")

if __name__ == "__main__":
    main()