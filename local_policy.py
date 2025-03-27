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

import subprocess
import os
import tempfile
import winreg
import win32security
import win32con


def enable_se_debug_privilege():
    """
    Ensure the SeDebugPrivilege is enabled for the current process.
    """
    try:
        # Open a handle to the current process
        hproc = win32api.GetCurrentProcess()
        proc_handle = win32security.OpenProcessToken(hproc, win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)

        # Enable SeDebugPrivilege
        privs = win32security.AdjustTokenPrivileges(
            proc_handle,
            False,
            [(win32security.LookupPrivilegeValue(None, "SeDebugPrivilege"), win32con.SE_PRIVILEGE_ENABLED)]
        )
        print("SeDebugPrivilege enabled.")
    except Exception as e:
        print(f"Failed to enable SeDebugPrivilege: {e}")


def dump_local_security_policy():
    user_rights = {}
    audit_policy = {}

    # Descriptions for each audit policy setting value
    audit_value_descriptions = {
        "0": "Disabled (No events will be logged)",
        "1": "Success (Only successful events will be logged)",
        "2": "Failure (Only failed events will be logged)",
        "3": "Success and Failure (Both successful and failed events will be logged)"
    }

    with tempfile.NamedTemporaryFile(delete=False, suffix=".inf") as tmpfile:
        inf_path = tmpfile.name

    try:
        result = subprocess.run(
            ["secedit", "/export", "/cfg", inf_path],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            return {
                "User Rights Assignments": {"Error": result.stderr.strip()},
                "Audit Policy Settings": {"Error": result.stderr.strip()}
            }

        with open(inf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_privileges = in_audit = False

        for line in lines:
            if "[Privilege Rights]" in line:
                in_privileges = True
                in_audit = False
                continue
            elif "[Event Audit]" in line:
                in_audit = True
                in_privileges = False
                continue
            elif "[" in line:
                in_privileges = in_audit = False
                continue

            if in_privileges and "=" in line:
                key, val = line.strip().split("=", 1)
                # Fix: split multiple SIDs or values properly into a list
                user_rights[key.strip()] = [entry.strip() for entry in val.strip().split(",") if entry.strip()]

            if in_audit and "=" in line:
                key, val = line.strip().split("=", 1)
                audit_policy[key.strip()] = val.strip()

    finally:
        os.remove(inf_path)

    # Add descriptions for audit policy settings values
    for key, value in audit_policy.items():
        description = audit_value_descriptions.get(value, "Unknown")
        audit_policy[key] = f"{value} - {description}"

    return {
        "User Rights Assignments": user_rights,
        "Audit Policy Settings": audit_policy
    }

def get_password_policy():
    result = []
    try:
        output = subprocess.run(["net", "accounts"], capture_output=True, text=True)
        result = output.stdout.strip().splitlines()
    except Exception as e:
        result.append(f"Error retrieving password policy: {e}")
    return result

def detect_uac_misconfig():
    uac_issues = []
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    checks = {
        "EnableLUA": (1, "UAC must be enabled (EnableLUA = 1)"),
        "ConsentPromptBehaviorAdmin": (5, "Admin prompt should not be '0' (auto-elevate)"),
        "PromptOnSecureDesktop": (1, "Secure Desktop must be enabled for elevation prompts"),
    }

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            for value_name, (expected, reason) in checks.items():
                try:
                    actual, _ = winreg.QueryValueEx(key, value_name)
                    if actual != expected:
                        uac_issues.append({
                            "severity": "medium",
                            "category": "UAC Misconfiguration",
                            "description": f"{value_name} is {actual}, expected {expected}. {reason}"
                        })
                except FileNotFoundError:
                    uac_issues.append({
                        "severity": "medium",
                        "category": "UAC Misconfiguration",
                        "description": f"{value_name} not found in registry."
                    })
    except Exception as e:
        uac_issues.append({
            "severity": "high",
            "category": "UAC Misconfiguration",
            "description": f"Failed to access UAC registry settings: {e}"
        })

    return {"UAC Settings": uac_issues, "_risks": uac_issues}

def run():
    # Enable SeDebugPrivilege before running the policy checks
    enable_se_debug_privilege()

    policy = dump_local_security_policy()
    policy["Password Policy"] = get_password_policy()
    policy.update(detect_uac_misconfig())
    return policy

def main():
    run()


if __name__ == "__main__":
    main()
