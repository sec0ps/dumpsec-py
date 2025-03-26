import argparse
from datetime import datetime
from report_writer import write_report
from users_groups import run as run_users_groups
from file_shares import run as run_file_shares
from registry_audit import run as run_registry_audit
from services_tasks import run as run_services_tasks
from local_policy import run as run_local_policy
from domain_info import run as run_domain_info

MODULES = {
    "1": ("Users and Groups", run_users_groups),
    "2": ("File and Share Permissions", run_file_shares),
    "3": ("Registry Permissions", run_registry_audit),
    "4": ("Services and Tasks", run_services_tasks),
    "5": ("Local Security Policy", run_local_policy),
    "6": ("Domain Trusts and Sessions", run_domain_info),
}

OUTPUT_FORMATS = ["txt", "json", "pdf"]


def parse_args():
    parser = argparse.ArgumentParser(description="DumpSec-Py - Windows Security Auditor")
    parser.add_argument("--output-format", choices=OUTPUT_FORMATS, help="Output format: txt, json, or pdf")
    parser.add_argument("--output-file", help="Output filename (without extension)")
    return parser.parse_args()


def cli_mode(args):
    report_name = args.output_file or f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"[*] Running full DumpSec audit in {args.output_format.upper()} mode...\n")

    results = {}
    for key, (label, func) in MODULES.items():
        print(f"[{key}] Running {label}...")
        results[label] = func()

    write_report(results, args.output_format, report_name)
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

    print("\nAvailable output formats: txt, json, pdf")
    formats = input("Enter output formats (comma-separated): ").strip().lower().split(",")
    formats = [f.strip() for f in formats if f.strip() in OUTPUT_FORMATS]

    if not formats:
        print("[!] No valid output formats selected. Exiting.")
        return

    default_name = f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name

    for fmt in formats:
        write_report(results, fmt, report_name)
        print(f"[+] Saved {report_name}.{fmt}")


def main():
    args = parse_args()

    if args.output_format:
        cli_mode(args)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
