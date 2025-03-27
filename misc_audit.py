import psutil
import win32api
import win32con
import win32process
import win32security
import pywintypes
import ctypes
import glob
import os
import winreg

def detect_lsass_access():
    risks = []
    lsass_pid = None

    try:
        # Find LSASS PID
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            if proc.info["name"].lower() == "lsass.exe":
                lsass_pid = proc.info["pid"]
                break

        if not lsass_pid:
            risks.append({
                "severity": "high",
                "category": "LSASS Monitoring",
                "description": "Unable to find LSASS process."
            })
            return {"LSASS Access": risks, "_risks": risks}

        system_sid, _, _ = win32security.LookupAccountName(None, "SYSTEM")

        for proc in psutil.process_iter(attrs=["pid", "name"]):
            pid = proc.info["pid"]
            name = proc.info["name"]
            if pid == lsass_pid:
                continue

            try:
                h_process = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
                token = win32security.OpenProcessToken(h_process, win32con.TOKEN_QUERY)
                user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]

                # Skip SYSTEM processes
                if win32security.EqualSid(user_sid, system_sid):
                    continue

                # Check if process has SeDebugPrivilege
                privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                has_debug = any(p[0] == win32security.LookupPrivilegeValue(None, "SeDebugPrivilege") and p[1] & (win32con.SE_PRIVILEGE_ENABLED)
                                for p in privileges)

                if has_debug:
                    risks.append({
                        "severity": "high",
                        "category": "LSASS Access",
                        "description": f"Process '{name}' (PID {pid}) is running with SeDebugPrivilege"
                    })

                # Try to open LSASS with VM_READ from this process (privilege check)
                PROCESS_VM_READ = 0x0010
                PROCESS_QUERY_INFORMATION = 0x0400

                try:
                    test_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, lsass_pid)
                    if test_handle:
                        ctypes.windll.kernel32.CloseHandle(test_handle)
                        risks.append({
                            "severity": "high",
                            "category": "LSASS Access",
                            "description": f"Process '{name}' (PID {pid}) can open a handle to lsass.exe"
                        })
                except Exception:
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, pywintypes.error):
                continue

    except Exception as e:
        risks.append({
            "severity": "medium",
            "category": "LSASS Access",
            "description": f"Error while scanning processes: {e}"
        })

    return {"LSASS Access": risks, "_risks": risks}

def audit_startup_folders():
    risks = []
    startup_entries = {}

    common_startup = os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup")
    user_profiles = [d for d in os.listdir("C:\\Users") if os.path.isdir(os.path.join("C:\\Users", d))]

    user_startups = [
        os.path.join("C:\\Users", user, "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        for user in user_profiles
    ]

    all_paths = [common_startup] + user_startups

    for path in all_paths:
        label = f"Startup Folder - {path}"
        entries = []

        if not os.path.exists(path):
            continue

        for file in glob.glob(os.path.join(path, "*")):
            try:
                owner_sid = win32security.GetFileSecurity(file, win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                owner = f"{domain}\\{name}"

                entries.append(f"{os.path.basename(file)} (Owner: {owner})")

                if owner.lower() not in ["system", "administrators", "trustedinstaller"]:
                    risks.append({
                        "severity": "high",
                        "category": "Startup Folder Audit",
                        "description": f"{file} is owned by non-privileged user: {owner}"
                    })

            except Exception as e:
                entries.append(f"{os.path.basename(file)} (error: {e})")
                risks.append({
                    "severity": "medium",
                    "category": "Startup Folder Audit",
                    "description": f"Failed to audit startup entry '{file}': {e}"
                })

        if entries:
            startup_entries[label] = entries

    return {"Startup Folder Contents": startup_entries, "_risks": risks}

def is_orphaned_sid(sid):
    try:
        win32security.LookupAccountSid(None, sid)
        return False
    except win32security.error:
        return True

def check_file_acls(paths):
    results = []
    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid = ace[2]
                    if is_orphaned_sid(sid):
                        results.append({
                            "severity": "medium",
                            "category": "Orphaned SID",
                            "description": f"Orphaned SID found in ACL for file: {path}"
                        })
        except Exception as e:
            results.append({
                "severity": "low",
                "category": "Orphaned SID",
                "description": f"Failed to check file ACL for {path}: {e}"
            })
    return results

def check_registry_keys(keys):
    results = []
    for root, subkey in keys:
        try:
            with winreg.OpenKey(root, subkey) as hkey:
                sd = win32security.GetSecurityInfo(hkey, win32security.SE_REGISTRY_KEY, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    for i in range(dacl.GetAceCount()):
                        ace = dacl.GetAce(i)
                        sid = ace[2]
                        if is_orphaned_sid(sid):
                            results.append({
                                "severity": "medium",
                                "category": "Orphaned SID",
                                "description": f"Orphaned SID in ACL for registry key: {subkey}"
                            })
        except Exception as e:
            results.append({
                "severity": "low",
                "category": "Orphaned SID",
                "description": f"Failed to check registry ACL for {subkey}: {e}"
            })
    return results

def check_service_acls():
    results = []
    try:
        scm = win32service.OpenSCManager(None, None, win32con.SC_MANAGER_ENUMERATE_SERVICE)
        statuses = win32service.EnumServicesStatusEx(
            scm, win32service.SC_ENUM_PROCESS_INFO,
            win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL, None
        )
        for service in statuses:
            name = service['ServiceName']
            try:
                svc_handle = win32service.OpenService(scm, name, win32con.READ_CONTROL)
                sd = win32service.QueryServiceObjectSecurity(svc_handle, win32security.DACL_SECURITY_INFORMATION)
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl:
                    for i in range(dacl.GetAceCount()):
                        ace = dacl.GetAce(i)
                        sid = ace[2]
                        if is_orphaned_sid(sid):
                            results.append({
                                "severity": "medium",
                                "category": "Orphaned SID",
                                "description": f"Orphaned SID in service ACL: {name}"
                            })
            except Exception as e:
                results.append({
                    "severity": "low",
                    "category": "Orphaned SID",
                    "description": f"Failed to check service ACL for {name}: {e}"
                })
    except Exception as e:
        results.append({
            "severity": "high",
            "category": "Orphaned SID",
            "description": f"Failed to enumerate services: {e}"
        })
    return results

def detect_orphaned_sids():
    file_targets = [
        os.environ.get("SystemRoot", "C:\\Windows"),
        "C:\\Program Files",
        "C:\\Program Files (x86)"
    ]

    reg_targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
    ]

    findings = []
    findings.extend(check_file_acls(file_targets))
    findings.extend(check_registry_keys(reg_targets))
    findings.extend(check_service_acls())

    return {"Orphaned SID/ACL Checks": findings, "_risks": findings}

def run():
    results = {}
    results.update(detect_lsass_access())
    results.update(audit_startup_folders())
    results.update(detect_orphaned_sids())
    return results

