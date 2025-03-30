# =============================================================================
# DumpSec-Py - Windows Security Auditing Tool - Updater Module
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
# Purpose: This module provides update checking functionality for DumpSec-Py.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#
# =============================================================================
# Update the import section in main.py
#from updater import check_for_updates

import os
import requests
from datetime import datetime

# GitHub repository information
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/dumpsec-py/main/"
GITHUB_VERSION_URL = GITHUB_RAW_BASE + "version.txt"
LOCAL_VERSION_FILE = "version.txt"

# List of files to update
FILES_TO_UPDATE = [
    "file_shares.py", "risk_engine.py", "services_tasks.py", "domain_info.py",
    "main.py", "misc_audit.py", "permissions.py", "registry_audit.py",
    "report_writer.py", "watcher.py", "local_policy.py", "event_logs.py",
    "powershell_audit.py", "defender_atp.py", "container_audit.py", "compliance.py",
    "remote_scanner.py", "gui.py", "updater.py"
]

def check_for_updates():
    """Check for updates to the DumpSec-Py tool."""
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
            print(f"[!] Could not retrieve remote version info (HTTP {response.status_code}).")
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
            print("[?] Update complete. Please restart the tool to load latest changes.")
        else:
            print("[?] Already running the latest version.")

    except requests.exceptions.ConnectionError:
        print("[!] Update check failed: Unable to connect to GitHub. Check your internet connection.")
    except requests.exceptions.Timeout:
        print("[!] Update check failed: Connection to GitHub timed out.")
    except Exception as e:
        print(f"[!] Update check failed: {e}")

    print("=== Update check complete ===\n")
    return updated

def force_update():
    """Force update all files regardless of version."""
    print("\n=== Forcing update from GitHub... ===")
    updated = False

    try:
        # Get remote version
        response = requests.get(GITHUB_VERSION_URL, timeout=5)
        if response.status_code != 200:
            print(f"[!] Could not retrieve remote version info (HTTP {response.status_code}).")
            print("=== Update failed ===\n")
            return False

        remote_version = response.text.strip()
        
        # Update all files
        for filename in FILES_TO_UPDATE:
            file_url = GITHUB_RAW_BASE + filename
            file_resp = requests.get(file_url, timeout=10)
            if file_resp.status_code == 200:
                with open(filename, "wb") as f:
                    f.write(file_resp.content)
                print(f"    -> Updated {filename}")
                updated = True
            else:
                print(f"    [!] Failed to update {filename} (HTTP {file_resp.status_code})")

        # Update local version record
        with open(LOCAL_VERSION_FILE, "w") as f:
            f.write(remote_version)

        if updated:
            print("[?] Force update complete. Please restart the tool to load latest changes.")
        else:
            print("[!] No files were updated.")

    except requests.exceptions.ConnectionError:
        print("[!] Update check failed: Unable to connect to GitHub. Check your internet connection.")
    except requests.exceptions.Timeout:
        print("[!] Update check failed: Connection to GitHub timed out.")
    except Exception as e:
        print(f"[!] Update check failed: {e}")

    print("=== Update process complete ===\n")
    return updated

if __name__ == "__main__":
    # If run directly, perform update check
    check_for_updates()
