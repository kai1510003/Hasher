#!/usr/bin/env python3
"""
Hash Generator & Verifier (SHA-256, MD5, SHA-512, SHA-1, BLAKE2)

A command-line tool for computing and verifying cryptographic hashes for
files, text strings, and directories to ensure data integrity and detect corruption or tampering.
"""

import argparse
import hashlib
import os
import sys

SUPPORTED_ALGOS = ["sha256", "md5", "sha512", "sha1", "blake2b", "blake2s"]

ALGO_HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "blake2s": 64,
    "sha512": 128,
    "blake2b": 128,
}


def is_valid_hash(hash_str: str, algorithm: str = None) -> bool:
    """
    Validate whether a string is a valid hexadecimal hash digest for supported algorithms.
    """
    if not isinstance(hash_str, str):
        return False
    clean_hash = hash_str.strip()
    if not clean_hash:
        return False
    if not all(c in "0123456789abcdefABCDEF" for c in clean_hash):
        return False
    if algorithm:
        algo_lower = algorithm.lower()
        if algo_lower in ALGO_HASH_LENGTHS:
            return len(clean_hash) == ALGO_HASH_LENGTHS[algo_lower]
    return len(clean_hash) in ALGO_HASH_LENGTHS.values()


def compute_hash(file_path: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """
    Compute the hash digest of a file in chunks to minimize memory consumption.
    """
    algo = algorithm.lower()
    try:
        hash_func = hashlib.new(algo)
    except ValueError:
        raise ValueError(f"Unsupported algorithm: '{algorithm}'. Supported: {', '.join(SUPPORTED_ALGOS)}")

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hash_func.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: '{file_path}'")
    except PermissionError:
        raise PermissionError(f"Permission denied: '{file_path}'")

    return hash_func.hexdigest()


def compute_text_hash(text: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash digest of a text string.
    """
    algo = algorithm.lower()
    try:
        hash_func = hashlib.new(algo)
    except ValueError:
        raise ValueError(f"Unsupported algorithm: '{algorithm}'. Supported: {', '.join(SUPPORTED_ALGOS)}")

    hash_func.update(text.encode("utf-8"))
    return hash_func.hexdigest()


def generate_hash_file(file_path: str, algorithm: str = "sha256") -> str:
    """
    Generate a hash for a file and save it in standard checksum format (<hash>  <filename>)
    to a companion file (e.g. filename.ext.sha256). Returns the created checksum file path.
    """
    digest = compute_hash(file_path, algorithm)
    hash_file_path = f"{file_path}.{algorithm.lower()}"

    with open(hash_file_path, "w", encoding="utf-8") as f:
        f.write(f"{digest}  {os.path.basename(file_path)}\n")

    print(f"[+] {algorithm.upper()} hash saved to: {hash_file_path}")
    print(f"    {digest}")
    return hash_file_path


def verify_file(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify a file's integrity against an expected hash string.
    """
    expected_clean = expected_hash.strip().lower()
    if not is_valid_hash(expected_clean, algorithm):
        raise ValueError(f"Invalid hash format: '{expected_hash}' is not a valid {algorithm.upper()} digest.")

    actual_hash = compute_hash(file_path, algorithm)
    actual_clean = actual_hash.lower()

    match = actual_clean == expected_clean

    print(f"File     : {file_path}")
    print(f"Algorithm: {algorithm.upper()}")
    print(f"Expected : {expected_clean}")
    print(f"Actual   : {actual_clean}")
    if match:
        print("[OK] MATCH -- file integrity verified.")
    else:
        print("[MISMATCH] -- file may be corrupted or tampered with.")

    return match


def verify_from_hash_file(file_path: str, hash_file_path: str, algorithm: str = "sha256") -> bool:
    """
    Verify a file using a companion checksum file.
    """
    try:
        with open(hash_file_path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
            if not first_line:
                raise ValueError("Hash file is empty.")
            expected_hash = first_line.split()[0]
    except FileNotFoundError:
        raise FileNotFoundError(f"Hash file not found: '{hash_file_path}'")
    except UnicodeDecodeError:
        raise ValueError(f"Invalid checksum file format: '{hash_file_path}' does not contain a valid hash digest.")

    if not is_valid_hash(expected_hash, algorithm):
        raise ValueError(f"Invalid checksum file format: '{hash_file_path}' does not contain a valid hash digest.")

    return verify_file(file_path, expected_hash, algorithm)


def hash_directory(dir_path: str, algorithm: str = "sha256") -> dict:
    """
    Recursively compute hashes for all files in a directory.
    """
    results = {}
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"Directory not found: '{dir_path}'")

    for root, _, files in os.walk(dir_path):
        for fname in sorted(files):
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, dir_path).replace("\\", "/")
            try:
                results[rel_path] = compute_hash(full_path, algorithm)
            except Exception as e:
                results[rel_path] = f"ERROR: {e}"
    return results


def print_vt_report(report: dict):
    """Format and print VirusTotal scan report to stdout."""
    print("\n" + "=" * 60)
    print(" VIRUSTOTAL THREAT ANALYSIS REPORT ")
    print("=" * 60)

    if not report.get("success"):
        print(f"[!] VirusTotal Error: {report.get('error')}")
        print("=" * 60)
        return

    if not report.get("found"):
        print(f"[-] Hash       : {report.get('hash')}")
        print(f"[-] Status     : NOT FOUND in VirusTotal database.")
        if report.get("permalink"):
            print(f"[-] Link       : {report.get('permalink')}")
        if report.get("upload_attempted"):
            up_res = report.get("upload_result", {})
            if up_res.get("success"):
                print(f"[+] Upload     : {up_res.get('message')}")
            else:
                print(f"[!] Upload Err : {up_res.get('error')}")
        print("=" * 60)
        return

    stats = report.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    status_str = f"MALICIOUS ({malicious}/{total_engines} engines)" if malicious > 0 else (
        f"SUSPICIOUS ({suspicious}/{total_engines} engines)" if suspicious > 0 else f"CLEAN (0/{total_engines} malicious)"
    )

    print(f"[*] Hash        : {report.get('hash')}")
    print(f"[*] File Name   : {report.get('meaningful_name')}")
    print(f"[*] File Type   : {report.get('type_description')}")
    print(f"[*] File Size   : {report.get('size')} bytes")
    print(f"[*] Threat Stat : {status_str}")
    print(f"[*] Threat Label: {report.get('threat_label')}")
    print(f"[*] Reputation  : {report.get('reputation')}")
    print(f"[*] Scan Date   : {report.get('scan_date')}")
    print(f"[*] Permalink   : {report.get('permalink')}")

    detections = report.get("detections", {})
    if detections:
        print("\n[!] Detections:")
        for eng, info in detections.items():
            print(f"  - {eng:<20}: {info.get('result')} [{info.get('category')}]")
    else:
        print("\n[+] No security vendors flagged this file as malicious.")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Hash Generator & Verifier Tool (SHA-256, MD5, SHA-512, SHA-1, BLAKE2, VirusTotal)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: generate
    gen_parser = subparsers.add_parser("generate", help="Generate a hash for a file, text string, or directory")
    gen_parser.add_argument("--file", help="Path to file to hash")
    gen_parser.add_argument("--text", help="Text string to hash")
    gen_parser.add_argument("--dir", help="Directory path to recursively hash files")
    gen_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm to use (default: sha256)",
    )
    gen_parser.add_argument("--save", action="store_true", help="Save hash to companion file (e.g. file.ext.sha256)")
    gen_parser.add_argument("--vt", action="store_true", help="Perform VirusTotal threat lookup on computed file hash")
    gen_parser.add_argument("--api-key", help="VirusTotal API Key (optional, defaults to VIRUSTOTAL_API_KEY env var)")

    # Subcommand: verify
    ver_parser = subparsers.add_parser("verify", help="Verify a file against an expected hash or hash file")
    ver_parser.add_argument("--file", required=True, help="Path to file to verify")
    ver_parser.add_argument("--hash", help="Expected hash string")
    ver_parser.add_argument("--hash-file", help="Path to a companion .sha256 / .md5 checksum file")
    ver_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm to use (default: sha256)",
    )
    ver_parser.add_argument("--vt", action="store_true", help="Perform VirusTotal threat lookup on file")
    ver_parser.add_argument("--api-key", help="VirusTotal API Key (optional, defaults to VIRUSTOTAL_API_KEY env var)")

    # Subcommand: virustotal
    vt_parser = subparsers.add_parser("virustotal", help="Analyze file or hash digest with VirusTotal API v3")
    vt_parser.add_argument("--file", help="Path to local file to hash and analyze")
    vt_parser.add_argument("--hash", help="Hash string (SHA-256, MD5, SHA-1) to analyze")
    vt_parser.add_argument("--api-key", help="VirusTotal API Key (defaults to VIRUSTOTAL_API_KEY env var)")
    vt_parser.add_argument("--upload", action="store_true", help="Automatically upload file to VirusTotal if not found in database")

    # Subcommand: gui
    subparsers.add_parser("gui", help="Launch the Graphical User Interface (GUI)")

    args = parser.parse_args()

    try:
        if args.command == "gui":
            import hash_gui
            hash_gui.main()

        elif args.command == "virustotal":
            import vt_client
            target = args.file or args.hash
            if not target:
                print("Error: Specify --file or --hash for virustotal analysis.")
                sys.exit(1)
            report = vt_client.analyze_file_or_hash(
                target, api_key=args.api_key, upload_if_missing=args.upload
            )
            print_vt_report(report)

        elif args.command == "generate":
            if args.file is not None:
                if args.save:
                    generate_hash_file(args.file, args.algo)
                else:
                    digest = compute_hash(args.file, args.algo)
                    print(f"{args.algo.upper()}: {digest}  {os.path.basename(args.file)}")

                if args.vt:
                    import vt_client
                    report = vt_client.analyze_file_or_hash(args.file, api_key=args.api_key)
                    print_vt_report(report)

            elif args.text is not None:
                digest = compute_text_hash(args.text, args.algo)
                print(f"{args.algo.upper()}: {digest}")
            elif args.dir is not None:
                print(f"[+] Hashing directory recursively: {args.dir} ({args.algo.upper()})\n")
                dir_hashes = hash_directory(args.dir, args.algo)
                for rel_path, digest in dir_hashes.items():
                    print(f"{digest}  {rel_path}")
            else:
                print("Error: Specify --file, --text, or --dir")
                sys.exit(1)

        elif args.command == "verify":
            match = False
            if args.hash:
                match = verify_file(args.file, args.hash, args.algo)
            elif args.hash_file:
                match = verify_from_hash_file(args.file, args.hash_file, args.algo)
            else:
                print("Error: Specify --hash or --hash-file")
                sys.exit(1)

            if args.vt:
                import vt_client
                report = vt_client.analyze_file_or_hash(args.file, api_key=args.api_key)
                print_vt_report(report)

            sys.exit(0 if match else 1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
