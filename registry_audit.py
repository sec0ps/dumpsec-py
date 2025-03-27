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
import winreg
import win32security
import ntsecuritycon
import ctypes
import win32api
import win32con
import re
import base64
from permissions import decode_access_mask
from risk_engine import RiskEngine

risk = RiskEngine()

# Registry hives mapping
HIVES = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT
}

def get_key_permissions(hive_name, subkey):
    results = []
    risks = []
    try:
        hive = HIVES[hive_name]
        reg_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | ntsecuritycon.READ_CONTROL)

        sd = win32security.GetSecurityInfo(
            reg_key,
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()

        if dacl is None:
            results.append("No DACL found.")
        else:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]
                access_mask = ace[1]
                try:
                    user, domain, _ = win32security.LookupAccountSid(None, sid)
                    user_str = f"{domain}\\{user}"
                    results.append(f"{user_str} => {decode_access_mask(access_mask, 'registry')}")
                    risks.extend(risk.evaluate_registry_acl(f"{hive_name}\\{subkey}", user_str, access_mask))
                except Exception:
                    results.append(f"<unresolved SID: {sid}>")
                    risks.extend(risk.evaluate_orphaned_sid(str(sid)))
    except Exception as e:
        results.append(f"<error retrieving permissions: {e}>")

    return results, risks

def audit_autostart_locations():
    autostart_keys = [
        ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]

    results = {}
    risks = []

    for hive_name, path in autostart_keys:
        try:
            hive = HIVES[hive_name]
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                entries = []
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append(f"{name}: {value}")
                        # ✅ FIX: Pass full registry key path, value name, and value (command)
                        full_key_path = f"{hive_name}\\{path}"
                        risks.extend(risk.evaluate_autostart(full_key_path, name, value))
                        i += 1
                    except OSError:
                        break
                results[f"{hive_name}\\{path}"] = entries
        except Exception as e:
            results[f"{hive_name}\\{path}"] = [f"<error reading: {e}>"]

    return results, risks

def audit_lsa_secrets():
    secrets = []
    risks = []

    try:
        # Enable SeBackupPrivilege (required to read the Security hive)
        hToken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        )
        privilege_id = win32security.LookupPrivilegeValue(None, "SeBackupPrivilege")
        win32security.AdjustTokenPrivileges(hToken, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)])

        # Try to open the LSA secrets path
        reg = ctypes.windll.advapi32
        hKey = ctypes.c_void_p()
        result = reg.RegOpenKeyExW(
            win32con.HKEY_LOCAL_MACHINE,
            "SECURITY\\Policy\\Secrets",
            0,
            win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_READ,
            ctypes.byref(hKey)
        )

        if result != 0:
            raise PermissionError("Unable to open LSA secrets registry key (try running as SYSTEM or with SeBackupPrivilege)")

        index = 0
        while True:
            name_buffer = ctypes.create_unicode_buffer(256)
            size = ctypes.c_ulong(256)
            res = reg.RegEnumKeyExW(hKey, index, name_buffer, ctypes.byref(size), None, None, None, None)
            if res != 0:
                break
            secret_name = name_buffer.value
            secrets.append(secret_name)

            # Heuristic risk flagging
            if any(kw in secret_name.lower() for kw in ["service", "password", "cred", "cache"]):
                risks.append({
                    "Severity": "high",
                    "Category": "LSA Secrets",
                    "Description": f"Suspicious or sensitive LSA secret detected: {secret_name}"
                })

            index += 1

        reg.RegCloseKey(hKey)

    except Exception as e:
        secrets.append(f"<error reading LSA secrets: {e}>")

    return secrets, risks

def audit_lsa_secrets():
    secrets_path = r"SECURITY\Policy\Secrets"
    results = []
    risks = []

    try:
        hive = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(hive, secrets_path)

        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                i += 1
                full_path = f"{secrets_path}\\{subkey_name}"
                results.append(subkey_name)

                # Attempt to retrieve default value or related key data
                try:
                    subkey = winreg.OpenKey(hive, full_path)
                    val, _ = winreg.QueryValueEx(subkey, "")
                    risks.extend(risk.evaluate_lsa_secrets(subkey_name, val))
                except Exception:
                    # No direct value, just record key name
                    pass

            except OSError:
                break

    except Exception as e:
        results.append(f"<error accessing LSA secrets: {e}>")

    return results, risks

def run():
    keys_to_check = [
        ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services"),
        ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]

    output = {
        "Registry Permissions": {},
        "Autostart Entries": {},
        "LSA Secrets": []
    }
    all_risks = []

    # Registry key ACLs
    for hive, key in keys_to_check:
        full_path = f"{hive}\\{key}"
        perms, risks = get_key_permissions(hive, key)
        output["Registry Permissions"][full_path] = perms
        all_risks.extend(risks)

    # Autostart locations
    autostart, autostart_risks = audit_autostart_locations()
    output["Autostart Entries"] = autostart
    all_risks.extend(autostart_risks)

    # LSA secrets
    lsa_secrets, lsa_risks = audit_lsa_secrets()
    output["LSA Secrets"] = lsa_secrets
    all_risks.extend(lsa_risks)

    output["_risks"] = all_risks
    return output

def main():
    result = run()
    for section, content in result.items():
        print(f"\n=== {section} ===")
        if isinstance(content, dict):
            for k, v in content.items():
                print(f"{k}:")
                for entry in v:
                    print(f"  - {entry}")
        elif isinstance(content, list):
            for line in content:
                print(f"  - {line}")
        else:
            print(content)


if __name__ == "__main__":
    main()
