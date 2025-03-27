import argparse
from datetime import datetime
from report_writer import write_report
from user_groups import run as run_user_groups
from file_shares import run as run_file_shares
from registry_audit import run as run_registry_audit
from services_tasks import run as run_services_tasks
from local_policy import run as run_local_policy
from domain_info import run as run_domain_info
from watcher import monitor_changes

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
    print("==== DumpSec-Py Interactive Menu ====")
    print("Select modules to run (comma-separated, or type 'all'):")
    for key, (label, _) in MODULES.items():
        print(f"  {key}. {label}")

    selected = input("\nEnter module numbers: ").strip()
    selected_keys = MODULES.keys() if selected.lower() == "all" else [x.strip() for x in selected.split(",")]

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
        print("[!] No valid output formats selected. Exiting.")
        return

    default_name = f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name

    min_risk = input("Minimum risk severity to include (low, medium, high)? Leave blank for all: ").strip().lower()
    min_risk = min_risk if min_risk in RISK_LEVELS else None

    for fmt in formats:
        write_report(results, fmt, report_name, min_risk)
        print(f"[+] Saved {report_name}.{fmt}")

def main():
    args = parse_args()

    if args.watch:
        monitor_changes()
        return

    if args.output_format:
        cli_mode(args)
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
