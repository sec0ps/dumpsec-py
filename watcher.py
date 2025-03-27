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
import pythoncom
import win32com.client
import datetime
import time
from risk_engine import RiskEngine

risk = RiskEngine()

def monitor_changes():
    print("[*] Monitoring for new or modified services and scheduled tasks... (Press Ctrl+C to stop)")
    pythoncom.CoInitialize()
    wmi = win32com.client.GetObject("winmgmts:")

    service_watcher = wmi.ExecNotificationQuery(
        "SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE "
        "TargetInstance ISA 'Win32_Service'"
    )

    task_watcher = wmi.ExecNotificationQuery(
        "SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE "
        "TargetInstance ISA 'Win32_ScheduledJob'"
    )

    try:
        while True:
            time.sleep(1)
            pythoncom.PumpWaitingMessages()

            for watcher, label in [(service_watcher, "Service"), (task_watcher, "Task")]:
                try:
                    event = watcher.NextEvent(100)  # timeout 100ms
                    time_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    if label == "Service" and hasattr(event, "TargetInstance") and hasattr(event.TargetInstance, "Name"):
                        service_name = event.TargetInstance.Name
                        try:
                            service_info = wmi.ExecQuery(
                                f"SELECT * FROM Win32_Service WHERE Name = '{service_name}'"
                            )
                            for s in service_info:
                                print(f"\n[{time_str}] Service Event: {event.Path_.Class} - {service_name}")
                                print(f"  Display Name : {s.DisplayName}")
                                print(f"  Description  : {s.Description}")
                                print(f"  Binary Path  : {s.PathName}")
                                print(f"  Start Mode   : {s.StartMode}")
                                print(f"  State        : {s.State}")
                                print(f"  Start Name   : {s.StartName}")

                                # ? Real-time risk evaluation using positional args
                                service_risks = risk.evaluate_service(
                                    s.Name,
                                    s.DisplayName,
                                    s.PathName,
                                    s.StartName
                                )

                                if service_risks:
                                    print("  !! Risks Detected:")
                                    for r in service_risks:
                                        print(f"    - [{r['severity'].upper()}] {r['category']}: {r['description']}")
                                else:
                                    print("  No risks detected.")

                        except Exception as e:
                            print(f"[!] Failed to retrieve details for {service_name}: {e}")

                    elif label == "Task":
                        print(f"[{time_str}] Task Event: {event.Path_.Class}")
                        # (Placeholder for future task risk analysis)

                except Exception:
                    continue  # ignore timeout errors

    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
