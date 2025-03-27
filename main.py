import argparse
import requests
import os
from datetime import datetime
from report_writer import write_report
from user_groups import run as run_user_groups
from file_shares import run as run_file_shares
from registry_audit import run as run_registry_audit
from services_tasks import run as run_services_tasks
from local_policy import run as run_local_policy
from domain_info import run as run_domain_info
from watcher import monitor_changes

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/dumpsec-py/main/"
GITHUB_VERSION_URL = GITHUB_RAW_BASE + "version.txt"
LOCAL_VERSION_FILE = "version.txt"

FILES_TO_UPDATE = [
    "file_shares.py",
    "risk_engine.py",
    "services_tasks.py",
    "domain_info.py",
    "main.py",
    "misc_audit.py",
    "permisssions.py",
    "registry_audit.py",
    "report_writer.py",
    "watcher.py",
    "local_policy.py"
]

MODULES = {
    "1": ("Users and Groups", run_user_groups),
    "2": ("File and Share Permissions", run_file_shares),
    "3": ("Registry Permissions", run_registry_audit),
    "4": ("Services and Tasks", run_services_tasks),
    "5": ("Local Security Policy", run_local_policy),
    "6": ("Domain Trusts and Sessions", run_domain_info),
}

OUTPUT_FORMATS = ["txt", "json", "pdf", "html", "csv", "all"]
RISK_LEVELS = ["low", "medium", "high"]

def parse_args():
    parser = argparse.ArgumentParser(description="DumpSec-Py - Windows Security Auditor")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, help="Output format: txt, json, pdf, html, csv, all")
    parser.add_argument("--output-file", help="Output filename (without extension)")
    parser.add_argument("--risk-level", choices=RISK_LEVELS, help="Minimum risk severity to include in report")
    parser.add_argument("--watch", action="store_true", help="Enable real-time monitoring mode")
    return parser.parse_args()

def cli_mode(args):
    report_name = args.output_file or f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    fmt_display = args.output_format.upper() if args.output_format != "all" else "ALL FORMATS"
    print(f"[*] Running full DumpSec audit in {fmt_display} mode...\n")

    results = {}
    for key, (label, func) in MODULES.items():
        print(f"[{key}] Running {label}...")
        results[label] = func()

    write_report(results, args.output_format, report_name, args.risk_level)

    if args.output_format == "all":
        print(f"[+] Reports saved as {report_name}.txt, .json, .pdf, .html, and .csv")
    else:
        print(f"[+] Report saved as {report_name}.{args.output_format}")

def interactive_menu():
    try:
        while True:
            print("\n==== DumpSec-Py Interactive Menu ====")
            print("Select modules to run (comma-separated), or type 'all' to run all.")
            for key, (label, _) in MODULES.items():
                print(f"  {key}. {label}")
            print("  0. Exit")

            selected = input("\nEnter module numbers (or 'exit'): ").strip().lower()
            if selected in ("0", "exit", "quit"):
                print("Exiting. Goodbye!")
                return

            selected_keys = MODULES.keys() if selected == "all" else [x.strip() for x in selected.split(",")]

            results = {}
            for key in selected_keys:
                if key in MODULES:
                    label, func = MODULES[key]
                    print(f"\n[*] Running {label}...")
                    results[label] = func()
                else:
                    print(f"[!] Invalid module selection: {key}")

            print("\nAvailable output formats: txt, json, pdf, html, csv, all")
            formats = input("Enter output formats (comma-separated or 'all'): ").strip().lower().split(",")
            formats = [f.strip() for f in formats if f.strip()]

            if "all" in formats:
                formats = ["txt", "json", "pdf", "html", "csv"]
            else:
                formats = [f for f in formats if f in OUTPUT_FORMATS]

            if not formats:
                print("[!] No valid output formats selected. Returning to menu.")
                continue

            default_name = f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name

            min_risk = input("Minimum risk severity to include (low, medium, high)? Leave blank for all: ").strip().lower()
            min_risk = min_risk if min_risk in RISK_LEVELS else None

            for fmt in formats:
                write_report(results, fmt, report_name, min_risk)
                print(f"[+] Saved {report_name}.{fmt}")

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting gracefully.")

def check_for_updates():
    print("\n=== Checking for updates from GitHub... ===")
    updated = False

    try:
        # Step 1: Read local version
        local_version = "0.0.0"
        if os.path.exists(LOCAL_VERSION_FILE):
            with open(LOCAL_VERSION_FILE, "r") as f:
                local_version = f.read().strip()

        # Step 2: Get remote version
        response = requests.get(GITHUB_VERSION_URL, timeout=5)
        if response.status_code != 200:
            print("[!] Could not retrieve remote version info (HTTP {}).".format(response.status_code))
            print("=== Update check skipped ===\n")
            return False

        remote_version = response.text.strip()

        # Step 3: Compare versions
        if remote_version > local_version:
            print(f"[+] New version detected: {remote_version} (current: {local_version})")
            for filename in FILES_TO_UPDATE:
                file_url = GITHUB_RAW_BASE + filename
                file_resp = requests.get(file_url, timeout=10)
                if file_resp.status_code == 200:
                    with open(filename, "wb") as f:
                        f.write(file_resp.content)
                    print(f"    -> Updated {filename}")
                else:
                    print(f"    [!] Failed to update {filename} (HTTP {file_resp.status_code})")

            # Step 4: Update local version record
            with open(LOCAL_VERSION_FILE, "w") as f:
                f.write(remote_version)

            updated = True
            print("[✓] Update complete. Please restart the tool to load latest changes.")
        else:
            print("[✓] Already running the latest version.")

    except Exception as e:
        print(f"[!] Update check failed: {e}")

    print("=== Update check complete ===\n")
    return updated

def main():
    try:
        check_for_updates()

        args = parse_args()

        if args.watch:
            monitor_changes()
            return

        if args.output_format:
            cli_mode(args)
        else:
            interactive_menu()
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting.")

if __name__ == "__main__":
    main()
