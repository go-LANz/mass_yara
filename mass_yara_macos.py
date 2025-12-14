import os
import sys
import argparse
import time
import json
import hashlib
import yara

# --- Configuration ---
LOG_FILE = "yara_scan_results_mac.jsonl"
MATCH_PREVIEW_LEN = 100

def check_full_disk_access(path_to_check):
    """
    Simple heuristic to see if we have permissions.
    If we can't read the directory we are asked to scan, we fail early.
    """
    if not os.access(path_to_check, os.R_OK):
        print(f"[!] WARNING: No read access to '{path_to_check}'.")
        print("[!] Ensure this terminal/binary has 'Full Disk Access' in System Settings > Privacy & Security.")
        return False
    return True

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

def log_hit(file_handle, match, target_path, extra_metadata=None):
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
        "scan_type": "DISK",
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
    if not os.path.isdir(rule_dir):
        print(f"[ERROR] Rule directory '{rule_dir}' not found.")
        sys.exit(1)

    print(f"[*] Compiling rules from: {rule_dir}")
    rule_map = {}
    for root, _, files in os.walk(rule_dir):
        for file in files:
            if file.lower().endswith(('.yara', '.yar')):
                rule_map[file] = os.path.join(root, file)

    if not rule_map:
        print("[ERROR] No .yara files found.")
        sys.exit(1)

    try:
        return yara.compile(filepaths=rule_map)
    except Exception as e:
        print(f"[CRITICAL] Compilation Error: {e}")
        sys.exit(1)

def scan_file_system(rules, path, log_handle):
    print(f"[*] Starting macOS Disk Scan on: {path}")
    start_time = time.time()
    
    iterator = [(os.path.dirname(path), [], [os.path.basename(path)])] if os.path.isfile(path) else os.walk(path)

    for root, _, files in iterator:
        for file in files:
            file_path = os.path.join(root, file)
            # Skip /dev and /proc to avoid loops/hangs on *nix systems
            if file_path.startswith(("/dev", "/proc", "/sys")):
                continue

            try:
                matches = rules.match(file_path)
                if matches:
                    f_size = os.path.getsize(file_path)
                    f_hash = get_file_hash(file_path)
                    disk_meta = {"size_bytes": f_size, "sha256": f_hash}
                    for match in matches:
                        log_hit(log_handle, match, file_path, disk_meta)
            except (PermissionError, OSError):
                # Very common on macOS TCC protected directories
                continue
            except Exception as e:
                print(f"[WARN] Error scanning {file_path}: {e}")

    print(f"[*] Scan completed in {time.time() - start_time:.2f} seconds.")

def main():
    parser = argparse.ArgumentParser(description="Mass YARA Scanner (MacOS - Disk Only)")
    parser.add_argument('-r', '--rules', required=True, help="Directory containing .yara files")
    parser.add_argument('-p', '--path', required=True, help="Path to scan (File or Directory)")
    parser.add_argument('-o', '--output', help="Output JSONL file", default=LOG_FILE)
    
    args = parser.parse_args()

    # TCC Check
    check_full_disk_access(args.path)

    yara_rules = compile_rules(args.rules)

    try:
        with open(args.output, 'a', encoding='utf-8') as f:
            scan_file_system(yara_rules, args.path, f)
            print(f"[*] Results saved to: {args.output}")
    except Exception as e:
        print(f"[ERROR] Output file error: {e}")

if __name__ == "__main__":
    main()