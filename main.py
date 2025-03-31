# =============================================================================
# DumpSec-Py - Windows Security Auditing Tool
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script is part of the DumpSec-Py tool, which is designed to
#          perform detailed security audits on Windows systems. It covers
#          user rights, services, registry permissions, file/share permissions,
#          group policy enumeration, risk assessments, and more.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================
import argparse
import requests
import os
from datetime import datetime
import json
import threading
import queue
import ipaddress
import getpass
import platform
import concurrent.futures
from updater import check_for_updates

# Import standard modules
from report_writer import write_report
from user_groups import run as run_user_groups
from file_shares import run as run_file_shares
from registry_audit import run as run_registry_audit
from services_tasks import run as run_services_tasks
from local_policy import run as run_local_policy
from domain_info import run as run_domain_info

# Import new modules
from event_logs import run as run_event_logs
from powershell_audit import run as run_powershell_audit
from defender_atp import run as run_defender_atp
from container_audit import check_wsl_status
from compliance import run as run_compliance
from remote_scanner import scan_multiple_hosts
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
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DumpSec-Py - Windows Security Auditor")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--output-format", choices=["txt", "json", "pdf", "html", "csv", "all"], 
                             help="Output format: txt, json, pdf, html, csv, all")
    output_group.add_argument("--output-file", help="Output filename (without extension)")
    output_group.add_argument("--risk-level", choices=["low", "medium", "high"], 
                             help="Minimum risk severity to include in report")
    
    # Scan modes
    mode_group = parser.add_argument_group("Scan Modes")
    mode_group.add_argument("--watch", action="store_true", help="Enable real-time monitoring mode")
    mode_group.add_argument("--compare", nargs=2, metavar=("OLD_REPORT", "NEW_REPORT"), 
                          help="Compare two previous reports")
    mode_group.add_argument("--remote", action="store_true", help="Scan remote hosts")
    # Add the missing GUI parameter
    mode_group.add_argument("--gui", action="store_true", help="Launch graphical user interface")
    
    # Remote scanning options
    remote_group = parser.add_argument_group("Remote Scanning Options")
    remote_group.add_argument("--hosts", help="List of hosts to scan (comma-separated or file)")
    remote_group.add_argument("--username", help="Username for remote authentication")
    remote_group.add_argument("--key-file", help="SSH private key for remote authentication")
    remote_group.add_argument("--max-threads", type=int, default=5, help="Maximum parallel scans")
    
    # Module selection
    module_group = parser.add_argument_group("Module Selection")
    module_group.add_argument("--modules", help="Modules to run (comma-separated: users,shares,registry,services,policy,domain,events,powershell,defender,containers)")
    
    # Feature flags
    feature_group = parser.add_argument_group("Feature Flags")
    feature_group.add_argument("--scan-event-logs", action="store_true", help="Include Windows Event Log analysis")
    feature_group.add_argument("--scan-powershell", action="store_true", help="Include PowerShell security audit")
    feature_group.add_argument("--scan-defender", action="store_true", help="Include Windows Defender/ATP analysis")
    feature_group.add_argument("--scan-containers", action="store_true", help="Include WSL/Container security audit")
    feature_group.add_argument("--map-compliance", action="store_true", help="Map findings to compliance frameworks")
    
    # Debug options
    debug_group = parser.add_argument_group("Debug Options")
    debug_group.add_argument("--debug", action="store_true", help="Enable debug output")
    
    return parser.parse_args()

def get_all_modules():
    """Get all available audit modules."""
    modules = {}
    
    # Standard modules
    try:
        from user_groups import run as run_user_groups
        modules["users"] = ("Users and Groups", run_user_groups)
    except ImportError:
        print("[!] Warning: user_groups module not found")
    
    try:
        from file_shares import run as run_file_shares
        modules["shares"] = ("File and Share Permissions", run_file_shares)
    except ImportError:
        print("[!] Warning: file_shares module not found")
    
    try:
        from registry_audit import run as run_registry_audit
        modules["registry"] = ("Registry Permissions", run_registry_audit)
    except ImportError:
        print("[!] Warning: registry_audit module not found")
    
    try:
        from services_tasks import run as run_services_tasks
        modules["services"] = ("Services and Tasks", run_services_tasks)
    except ImportError:
        print("[!] Warning: services_tasks module not found")
    
    try:
        from local_policy import run as run_local_policy
        modules["policy"] = ("Local Security Policy", run_local_policy)
    except ImportError:
        print("[!] Warning: local_policy module not found")
    
    try:
        from domain_info import run as run_domain_info
        modules["domain"] = ("Domain Trusts and Sessions", run_domain_info)
    except ImportError:
        print("[!] Warning: domain_info module not found")
    
    # Enhanced modules
    try:
        from event_logs import run as run_event_logs
        modules["events"] = ("Windows Event Logs", run_event_logs)
    except ImportError:
        print("[!] Warning: event_logs module not found or not yet implemented")
    
    try:
        from powershell_audit import run as run_powershell_audit
        modules["powershell"] = ("PowerShell Security", run_powershell_audit)
    except ImportError:
        print("[!] Warning: powershell_audit module not found or not yet implemented")
    
    try:
        from defender_atp import run as run_defender_atp
        modules["defender"] = ("Windows Defender/ATP", run_defender_atp)
    except ImportError:
        print("[!] Warning: defender_atp module not found or not yet implemented")
    
    try:
        from container_audit import check_wsl_status
        modules["containers"] = ("WSL and Container Security", check_wsl_status)
    except ImportError:
        print("[!] Warning: container_audit module not found or not yet implemented")
    
    return modules

def select_modules(args):
    """Select which modules to run based on command line arguments."""
    all_modules = get_all_modules()
    selected_modules = {}
    
    if args.modules:
        module_list = args.modules.split(',')
        for module in module_list:
            if module in all_modules:
                selected_modules[module] = all_modules[module]
    else:
        # Default modules
        for module in ["users", "shares", "registry", "services", "policy", "domain"]:
            selected_modules[module] = all_modules[module]
        
        # Optional modules based on flags
        if args.scan_event_logs:
            selected_modules["events"] = all_modules["events"]
        
        if args.scan_powershell:
            selected_modules["powershell"] = all_modules["powershell"]
        
        if args.scan_defender:
            selected_modules["defender"] = all_modules["defender"]
        
        if args.scan_containers:
            selected_modules["containers"] = all_modules["containers"]
    
    return selected_modules

def cli_mode(args):
    """Run in command-line mode with specified arguments."""
    report_name = args.output_file or f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    fmt_display = args.output_format.upper() if args.output_format != "all" else "ALL FORMATS"
    print(f"[*] Running DumpSec audit in {fmt_display} mode...\n")

    # Get selected modules
    modules = select_modules(args)
    
    results = {}
    all_risks = []
    
    for key, (label, func) in modules.items():
        print(f"[{key}] Running {label}...")
        module_results = func()
        results[label] = module_results
        
        # Collect risks for compliance mapping
        if isinstance(module_results, dict) and "_risks" in module_results:
            all_risks.extend(module_results["_risks"])
    
    # Map findings to compliance frameworks if requested
    if args.map_compliance:
        print("[*] Mapping findings to compliance frameworks...")
        compliance_report = run_compliance(all_risks)
        results["Compliance Mapping"] = compliance_report
    
    # Write report
    write_report(results, args.output_format, report_name, args.risk_level)

    if args.output_format == "all":
        print(f"[+] Reports saved as {report_name}.txt, .json, .pdf, .html, and .csv")
    else:
        print(f"[+] Report saved as {report_name}.{args.output_format}")
        
def compare_reports(args):
    """Compare two existing reports to identify changes."""
    from report_writer import compare_reports
    
    old_report = args.compare[0]
    new_report = args.compare[1]
    
    if not os.path.exists(old_report) or not os.path.exists(new_report):
        print(f"[!] One or both report files not found")
        return
    
    print(f"[*] Comparing reports: {old_report} vs {new_report}")
    
    differences = compare_reports(old_report, new_report)
    output_file = f"diff_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, "w") as f:
        json.dump(differences, f, indent=2)
    
    print(f"[+] Comparison report saved as {output_file}")
    
    # Print summary
    added = sum(len(v) for v in differences["added"].values())
    removed = sum(len(v) for v in differences["removed"].values())
    modified = sum(len(v) for v in differences["modified"].values())
    
    print(f"\nSummary of changes:")
    print(f"  - Added: {added} items")
    print(f"  - Removed: {removed} items")
    print(f"  - Modified: {modified} items")

def remote_mode(args):
    """Scan remote Windows hosts."""
    if not args.hosts:
        print("[!] No hosts specified. Use --hosts option.")
        return
    
    # Get hosts list
    if os.path.exists(args.hosts):
        with open(args.hosts, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        hosts = [h.strip() for h in args.hosts.split(',') if h.strip()]
    
    if not hosts:
        print("[!] No valid hosts found.")
        return
    
    # Get credentials
    username = args.username
    if not username:
        username = input("Enter username for remote authentication: ")
    
    password = None
    if not args.key_file:
        password = getpass.getpass("Enter password (leave empty to use SSH key): ")
        if not password:
            key_file = input("Enter path to SSH private key: ")
        else:
            key_file = None
    else:
        key_file = args.key_file
    
    print(f"[*] Scanning {len(hosts)} remote hosts with {args.max_threads} parallel threads")
    results = scan_multiple_hosts(hosts, username, password, key_file, args.max_threads)
    
    # Save results
    output_file = args.output_file or f"remote_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(f"{output_file}.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Remote scan results saved as {output_file}.json")
    
    # Print summary
    print("\nScan summary:")
    for host, result in results.items():
        if "analysis" in result and "risks" in result["analysis"]:
            risks = result["analysis"]["risks"]
            high = sum(1 for r in risks if r.get("severity") == "high")
            medium = sum(1 for r in risks if r.get("severity") == "medium")
            low = sum(1 for r in risks if r.get("severity") == "low")
            print(f"  - {host}: {len(risks)} findings (High: {high}, Medium: {medium}, Low: {low})")
        else:
            print(f"  - {host}: Scan failed or no findings")

def interactive_menu():
    """Run in interactive menu mode."""
    try:
        while True:
            print("\n==== DumpSec-Py Interactive Menu ====")
            print("1. Run Standard Security Audit")
            print("2. Run Advanced Security Audit (includes Event Logs, PowerShell, Defender)")
            print("3. Scan Remote Windows Systems")
            print("4. Run Real-time Change Monitoring")
            print("5. Compare Previous Reports")
            print("6. Exit")

            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == "1":
                run_standard_audit()
            elif choice == "2":
                run_advanced_audit()
            elif choice == "3":
                run_remote_scan()
            elif choice == "4":
                print("\n[*] Starting real-time change monitoring...")
                monitor_changes()
            elif choice == "5":
                run_report_comparison()
            elif choice == "6":
                print("Exiting. Goodbye!")
                break
            else:
                print("[!] Invalid choice. Please enter a number between 1 and 6.")
    
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting gracefully.")

def check_windows_version():
    """Check Windows version and return compatibility information."""
    import platform
    win_ver = platform.win32_ver()
    
    # Extract major version for compatibility check
    major_version = win_ver[0].split('.')[0]  # Just take the first number
    
    compatibility = {
        "version": win_ver[0],
        "build": win_ver[1],
        "compatible": True,
        "features": []
    }
    
    # Windows 10/11 specific features
    if major_version in ['10', '11']:
        compatibility["features"] = ["AppLocker", "WDAC", "Defender ATP", "Containers"]
    
    return compatibility

def run_standard_audit():
    """Run a standard security audit in interactive mode."""
    modules = {
        "users": ("Users and Groups", run_user_groups),
        "shares": ("File and Share Permissions", run_file_shares),
        "registry": ("Registry Permissions", run_registry_audit),
        "services": ("Services and Tasks", run_services_tasks),
        "policy": ("Local Security Policy", run_local_policy),
        "domain": ("Domain Trusts and Sessions", run_domain_info)
    }
    
    print("\n=== Standard Security Audit ===")
    print("Select modules to run (comma-separated), or type 'all' to run all.")
    for key, (label, _) in modules.items():
        print(f"  {key}. {label}")
    
    selected = input("\nEnter module selection (or 'all'): ").strip().lower()
    
    selected_modules = {}
    if selected == "all":
        selected_modules = modules
    else:
        for key in selected.split(','):
            key = key.strip()
            if key in modules:
                selected_modules[key] = modules[key]
    
    if not selected_modules:
        print("[!] No valid modules selected. Returning to menu.")
        return
    
    # Run selected modules
    results = {}
    all_risks = []
    
    for key, (label, func) in selected_modules.items():
        print(f"\n[*] Running {label}...")
        module_results = func()
        results[label] = module_results
        
        # Collect risks
        if isinstance(module_results, dict) and "_risks" in module_results:
            all_risks.extend(module_results["_risks"])
    
    # Output options
    print("\nAvailable output formats: txt, json, pdf, html, csv, all")
    formats = input("Enter output format(s) (comma-separated or 'all'): ").strip().lower().split(",")
    formats = [f.strip() for f in formats if f.strip()]
    
    if "all" in formats:
        formats = ["txt", "json", "pdf", "html", "csv"]
    
    if not formats:
        print("[!] No valid output formats selected. Using JSON as default.")
        formats = ["json"]
    
    # Report name
    default_name = f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name
    
    # Risk level filtering
    min_risk = input("Minimum risk severity to include (low, medium, high)? Leave blank for all: ").strip().lower()
    min_risk = min_risk if min_risk in ["low", "medium", "high"] else None
    
    # Map to compliance frameworks?
    map_compliance = input("Map findings to compliance frameworks? (y/n): ").strip().lower() == 'y'
    
    if map_compliance:
        print("\n[*] Mapping findings to compliance frameworks...")
        compliance_report = run_compliance(all_risks)
        results["Compliance Mapping"] = compliance_report
    
    # Generate reports
    for fmt in formats:
        write_report(results, fmt, report_name, min_risk)
        print(f"[+] Saved {report_name}.{fmt}")

# Add these functions after the interactive_menu() function

def run_standard_audit():
    """Run a standard security audit in interactive mode."""
    modules = {
        "users": ("Users and Groups", run_user_groups),
        "shares": ("File and Share Permissions", run_file_shares),
        "registry": ("Registry Permissions", run_registry_audit),
        "services": ("Services and Tasks", run_services_tasks),
        "policy": ("Local Security Policy", run_local_policy),
        "domain": ("Domain Trusts and Sessions", run_domain_info)
    }
    
    print("\n=== Standard Security Audit ===")
    print("Select modules to run (comma-separated), or type 'all' to run all.")
    for key, (label, _) in modules.items():
        print(f"  {key}. {label}")
    
    selected = input("\nEnter module selection (or 'all'): ").strip().lower()
    
    selected_modules = {}
    if selected == "all":
        selected_modules = modules
    else:
        for key in selected.split(','):
            key = key.strip()
            if key in modules:
                selected_modules[key] = modules[key]
    
    if not selected_modules:
        print("[!] No valid modules selected. Returning to menu.")
        return
    
    # Run selected modules
    results = {}
    all_risks = []
    
    for key, (label, func) in selected_modules.items():
        print(f"\n[*] Running {label}...")
        module_results = func()
        results[label] = module_results
        
        # Collect risks
        if isinstance(module_results, dict) and "_risks" in module_results:
            all_risks.extend(module_results["_risks"])
    
    # Output options
    print("\nAvailable output formats: txt, json, pdf, html, csv, all")
    formats = input("Enter output format(s) (comma-separated or 'all'): ").strip().lower().split(",")
    formats = [f.strip() for f in formats if f.strip()]
    
    if "all" in formats:
        formats = ["txt", "json", "pdf", "html", "csv"]
    
    if not formats:
        print("[!] No valid output formats selected. Using JSON as default.")
        formats = ["json"]
    
    # Report name
    default_name = f"dumpsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name
    
    # Risk level filtering
    min_risk = input("Minimum risk severity to include (low, medium, high)? Leave blank for all: ").strip().lower()
    min_risk = min_risk if min_risk in ["low", "medium", "high"] else None
    
    # Map to compliance frameworks?
    map_compliance = input("Map findings to compliance frameworks? (y/n): ").strip().lower() == 'y'
    
    if map_compliance:
        print("\n[*] Mapping findings to compliance frameworks...")
        compliance_report = run_compliance(all_risks)
        results["Compliance Mapping"] = compliance_report
    
    # Generate reports
    for fmt in formats:
        write_report(results, fmt, report_name, min_risk)
        print(f"[+] Saved {report_name}.{fmt}")

def run_advanced_audit():
    """Run an advanced security audit with all modules."""
    all_modules = get_all_modules()
    
    if not all_modules:
        print("[!] Error: No audit modules available. Check module installation.")
        return
    
    print("\n=== Advanced Security Audit ===")
    print("This will run all security audit modules, including:")
    print("- Standard modules (Users, Shares, Registry, Services, Policy, Domain)")
    print("- Windows Event Log analysis")
    print("- PowerShell security audit")
    print("- Windows Defender/ATP analysis")
    print("- WSL and Container security audit")
    
    confirm = input("\nThis may take several minutes to complete. Continue? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Advanced audit cancelled.")
        return
    
    # Run all modules
    results = {}
    all_risks = []
    
    for key, (label, func) in all_modules.items():
        print(f"\n[*] Running {label}...")
        try:
            module_results = func()
            
            # Ensure we always have a valid dictionary result
            if module_results is None:
                print(f"[!] Warning: {label} module returned None")
                module_results = {"Error": "Module returned None"}
            
            results[label] = module_results
            
            # Collect risks safely
            if isinstance(module_results, dict) and "_risks" in module_results:
                # Ensure risks is an iterable
                risks = module_results["_risks"]
                if risks is not None:
                    all_risks.extend(risks)
        except Exception as e:
            print(f"[!] Error in {label} module: {str(e)}")
            results[label] = {"Error": str(e)}
    
    # Continue only if we have results
    if not results:
        print("[!] No results collected. Audit failed.")
        return
    
    # Output options
    print("\nAvailable output formats: txt, json, pdf, html, csv, all")
    formats = input("Enter output format(s) (comma-separated or 'all'): ").strip().lower().split(",")
    formats = [f.strip() for f in formats if f.strip()]
    
    if "all" in formats:
        formats = ["txt", "json", "pdf", "html", "csv"]
    
    if not formats:
        print("[!] No valid output formats selected. Using JSON as default.")
        formats = ["json"]
    
    # Report name
    default_name = f"dumpsec_advanced_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_name = input(f"Enter report name (default: {default_name}): ").strip() or default_name
    
    # Risk level filtering
    min_risk = input("Minimum risk severity to include (low, medium, high)? Leave blank for all: ").strip().lower()
    min_risk = min_risk if min_risk in ["low", "medium", "high"] else None
    
    # Map to compliance frameworks (automatic for advanced audit)
    try:
        print("\n[*] Mapping findings to compliance frameworks...")
        from compliance import run as run_compliance
        compliance_report = run_compliance(all_risks)
        results["Compliance Mapping"] = compliance_report
    except ImportError:
        print("[!] Warning: compliance module not found or not yet implemented")
    except Exception as e:
        print(f"[!] Error mapping to compliance frameworks: {str(e)}")
    
    # Generate reports
    for fmt in formats:
        try:
            from report_writer import write_report
            write_report(results, fmt, report_name, min_risk)
            print(f"[+] Saved {report_name}.{fmt}")
        except Exception as e:
            print(f"[!] Error generating {fmt} report: {str(e)}")

def main():
    """Main entry point for DumpSec-Py."""
    args = None  # Initialize args to avoid UnboundLocalError
    try:
        # Print banner
        print("""
    ____                      ____             ____       
   / __ \\__  ______ ___  ____/ / /___ _____   / __ \\__  __
  / / / / / / / __ `__ \\/ __  / / __ `/ __ \\ / /_/ / / / /
 / /_/ / /_/ / / / / / / /_/ / / /_/ / /_/ // ____/ /_/ / 
/_____/\\__,_/_/ /_/ /_/\\__,_/_/\\__,_/ .___//_/    \\__, /  
                                   /_/           /____/   
                                   
 Windows Security Auditing Tool
 (c) 2025 Red Cell Security, LLC
""")
        
        # Check Windows version compatibility
        win_compat = check_windows_version()
        print(f"[*] Windows Version: {win_compat['version']} (Build {win_compat['build']})")
        if not win_compat['compatible']:
            print("[!] Warning: This Windows version may not be fully supported.")
        
        # Check for updates
        from updater import check_for_updates
        updated = check_for_updates()
        if updated:
            print("[*] Please restart the tool to use the updated version.")
            return
        
        # Parse command line arguments
        args = parse_args()
        
        # Handle different modes
        if args.watch:
            print("[*] Starting real-time change monitoring...")
            monitor_changes()
        elif args.compare:
            compare_reports(args)
        elif args.remote:
            remote_mode(args)
        elif args.gui:
            # Import and launch GUI
            try:
                from gui import main as gui_main
                gui_main()
            except ImportError:
                print("[!] GUI dependencies not found. Please install PyQt5.")
                print("    pip install PyQt5")
        elif args.output_format:
            cli_mode(args)
        else:
            # No arguments provided, run in interactive menu
            interactive_menu()
            
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt received. Exiting.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        
        # If debug mode is enabled, print traceback
        if args and hasattr(args, 'debug') and args.debug:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
