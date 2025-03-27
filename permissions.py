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

import win32security
import ntsecuritycon


def decode_access_mask(mask, resource_type="file"):
    permissions = []

    if resource_type == "file":
        if mask & ntsecuritycon.FILE_GENERIC_READ:
            permissions.append("READ")
        if mask & ntsecuritycon.FILE_GENERIC_WRITE:
            permissions.append("WRITE")
        if mask & ntsecuritycon.FILE_GENERIC_EXECUTE:
            permissions.append("EXECUTE")
        if mask & ntsecuritycon.DELETE:
            permissions.append("DELETE")
    elif resource_type == "registry":
        if mask & ntsecuritycon.KEY_READ:
            permissions.append("READ")
        if mask & ntsecuritycon.KEY_WRITE:
            permissions.append("WRITE")
        if mask & ntsecuritycon.KEY_EXECUTE:
            permissions.append("EXECUTE")
        if mask & ntsecuritycon.DELETE:
            permissions.append("DELETE")

    if mask & ntsecuritycon.WRITE_DAC:
        permissions.append("WRITE_DAC")
    if mask & ntsecuritycon.WRITE_OWNER:
        permissions.append("WRITE_OWNER")

    return "|".join(permissions) if permissions else f"RAW: {mask}"


def print_acl(dacl):
    if dacl is None:
        print("    - No DACL found.")
        return

    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        sid = ace[2]
        try:
            user, domain, _ = win32security.LookupAccountSid(None, sid)
            access_mask = ace[1]
            print(f"    - {domain}\\{user} => Access: {access_mask}")
        except Exception as e:
            print(f"    - [!] Failed to resolve SID: {e}")
