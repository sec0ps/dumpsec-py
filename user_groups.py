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
import subprocess
from risk_engine import RiskEngine

risk = RiskEngine()


def list_local_users():
    users = []
    resume = 0

    while True:
        try:
            user_data, total, resume = win32net.NetUserEnum(
                None,
                0,
                win32netcon.FILTER_NORMAL_ACCOUNT,
                resume,
                1000
            )
            for user in user_data:
                users.append(user['name'])
            if not resume:
                break
        except Exception:
            break
    return users


def list_local_groups():
    groups = []
    resume = 0

    while True:
        try:
            group_data, total, resume = win32net.NetLocalGroupEnum(
                None,
                0,
                resume,
                1000
            )
            for group in group_data:
                groups.append(group['name'])
            if not resume:
                break
        except Exception:
            break
    return groups

def list_group_memberships(groups):
    memberships = {}
    risks = []

    for group in groups:
        try:
            members, _, _ = win32net.NetLocalGroupGetMembers(None, group, 2)
            member_names = []
            for member in members:
                try:
                    if 'name' in member and member['name']:
                        member_names.append(member['name'])
                    elif 'sid' in member:
                        import win32security
                        name, domain, _ = win32security.LookupAccountSid(None, member['sid'])
                        member_names.append(f"{domain}\\{name}")
                    else:
                        member_names.append("<unknown member>")
                except Exception as e:
                    member_names.append(f"<error resolving member: {e}>")
            memberships[group] = member_names
            risks.extend(risk.evaluate_group_membership(group, member_names))
        except Exception as e:
            memberships[group] = [f"<error retrieving members: {e}>"]

    return memberships, risks

def get_group_policy_results():
    results = {}
    try:
        output = subprocess.run(["gpresult", "/SCOPE:ALL", "/Z"], capture_output=True, text=True)
        if output.returncode == 0:
            lines = output.stdout.strip().splitlines()
            current_section = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.endswith(":") and not line.startswith("    "):
                    current_section = line.rstrip(":")
                    results[current_section] = []
                elif current_section:
                    results[current_section].append(line)
        else:
            results["Error"] = output.stderr.strip()
    except Exception as e:
        results["Error"] = str(e)

    return results


def run():
    users = list_local_users()
    groups = list_local_groups()
    memberships, group_risks = list_group_memberships(groups)
    gpo = get_group_policy_results()

    return {
        "Local Users": users,
        "Local Groups": groups,
        "Group Memberships": memberships,
        "Group Policy": gpo,
        "_risks": group_risks
    }


def main():
    users = list_local_users()
    groups = list_local_groups()
    list_group_memberships(groups)
    get_group_policy_results()


if __name__ == "__main__":
    main()
