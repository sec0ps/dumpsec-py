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
import win32service
import win32serviceutil
import win32con
import win32api
import win32security
import win32com.client
from risk_engine import RiskEngine

risk = RiskEngine()

def get_services():
    services = []
    risks = []
    
    try:
        scm_handle = win32service.OpenSCManager(None, None, win32con.SC_MANAGER_ENUMERATE_SERVICE)  # Make sure SC_MANAGER_ENUMERATE_SERVICE is available
        statuses = win32service.EnumServicesStatusEx(
            scm_handle,
            win32service.SC_ENUM_PROCESS_INFO,
            win32service.SERVICE_WIN32,
            win32service.SERVICE_STATE_ALL,
            None
        )

        for service in statuses:
            name = service['ServiceName']
            display_name = service['DisplayName']
            try:
                config = win32service.QueryServiceConfig(
                    win32service.OpenService(scm_handle, name, win32con.SC_MANAGER_ALL_ACCESS)
                )
                start_type = decode_start_type(config[1])
                logon_user = config[7]
                binary_path = config[3]
                status = "Running" if service['CurrentState'] == win32service.SERVICE_RUNNING else "Stopped"

                services.append({
                    "Service Name": name,
                    "Display Name": display_name,
                    "Status": status,
                    "Start Type": start_type,
                    "Logon User": logon_user,
                    "Binary Path": binary_path
                })

                risks.extend(risk.evaluate_service(name, display_name, binary_path, logon_user))

            except Exception as e:
                services.append({
                    "Service Name": name,
                    "Display Name": display_name,
                    "Status": "<error>",
                    "Start Type": "<error>",
                    "Logon User": f"<error: {e}>"
                })

    except Exception as e:
        services.append({"Error": str(e)})

    return services, risks

def decode_start_type(code):
    return {
        win32service.SERVICE_AUTO_START: "Automatic",
        win32service.SERVICE_DEMAND_START: "Manual",
        win32service.SERVICE_DISABLED: "Disabled"
    }.get(code, f"Unknown ({code})")

def get_scheduled_tasks():
    tasks = []
    risks = []

    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folders = [scheduler.GetFolder("\\")]

        while folders:
            folder = folders.pop()
            for task in folder.GetTasks(0):
                name = task.Name
                try:
                    definition = task.Definition
                    user_id = definition.Principal.UserId

                    executable = None
                    for action in definition.Actions:
                        if action.Type == 0:  # TASK_ACTION_EXEC
                            executable = action.Path
                            break

                    tasks.append({
                        "Task Name": name,
                        "Run As": user_id,
                        "Executable": executable or "<none>"
                    })

                    risks.extend(risk.evaluate_task(name, user_id, executable))

                except Exception as e:
                    tasks.append({
                        "Task Name": name,
                        "Run As": f"<error: {e}>",
                        "Executable": "<error extracting action>"
                    })

            folders.extend(folder.GetFolders(0))

    except Exception as e:
        tasks.append({"Error": str(e)})

    return tasks, risks

def detect_hidden_tasks():
    hidden_tasks = []
    risks = []

    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()

        folders = [scheduler.GetFolder("\\")]

        while folders:
            folder = folders.pop()
            for task in folder.GetTasks(0):
                try:
                    if task.Hidden:
                        name = task.Name
                        path = task.Path
                        run_as = task.Definition.Principal.UserId

                        hidden_tasks.append(f"{name} (Path: {path}, RunAs: {run_as})")

                        risks.append({
                            "severity": "medium",
                            "category": "Hidden Scheduled Task",
                            "description": f"Hidden task '{name}' is configured to run as '{run_as}'"
                        })

                except Exception:
                    # Silently skip error unless task.Hidden was confirmed
                    continue

            folders.extend(folder.GetFolders(0))

    except Exception as e:
        # Only report global failure of querying scheduled tasks
        risks.append({
            "severity": "high",
            "category": "Hidden Scheduled Task",
            "description": f"Failed to query scheduled tasks: {e}"
        })

    result = {}
    if hidden_tasks:
        result["Hidden Scheduled Tasks"] = hidden_tasks
        result["_risks"] = risks

    return result

def run():
    services, service_risks = get_services()
    tasks = get_scheduled_tasks()
    hidden = detect_hidden_tasks()

    results = {
        "Services": services,
        "Scheduled Tasks": tasks,
        "_risks": service_risks
    }

    results.update(hidden)
    results["_risks"].extend(hidden.get("_risks", []))

    return results

def main():
    get_services()
    get_scheduled_tasks()


if __name__ == "__main__":
    main()
