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

import win32net
import win32netcon
from risk_engine import RiskEngine

risk = RiskEngine()

def list_domain_trusts():
    trusts = []
    try:
        dc_name = win32net.NetGetAnyDCName(None, None)
        trusts.append(f"Trusted domain controller: {dc_name}")
    except Exception as e:
        trusts.append(f"<error: {e}>")
    return trusts

def list_sessions():
    sessions = []
    resume = 0
    try:
        while True:
            results, total, resume = win32net.NetSessionEnum(None, None, None, 10, resume)
            for session in results:
                sessions.append({
                    "User": session.get("user_name", ""),
                    "Client": session.get("client_name", "")
                })
            if resume == 0:
                break
    except Exception as e:
        sessions.append({"Error": str(e)})
    return sessions

def list_open_files():
    open_files = []
    resume = 0
    try:
        while True:
            results, total, resume = win32net.NetFileEnum(None, None, None, 3, resume)
            for file in results:
                open_files.append({
                    "File": file.get("path_name", ""),
                    "Opened By": file.get("user_name", "")
                })
            if resume == 0:
                break
    except Exception as e:
        open_files.append({"Error": str(e)})
    return open_files

def run():
    trusts = list_domain_trusts()
    sessions = list_sessions()
    open_files = list_open_files()

    return {
        "Domain Trusts": trusts,
        "Active Sessions": sessions,
        "Open Files": open_files,
        "_risks": []  # Placeholder for future logic
    }


def main():
    list_domain_trusts()
    list_sessions()
    list_open_files()


if __name__ == "__main__":
    main()
