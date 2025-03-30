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
import ntsecuritycon
import re
import os
import ctypes
import win32security
import win32net
import win32netcon

class RiskEngine:
    def __init__(self):
        self.risks = []

    def evaluate_service(self, service_name, display_name, binary_path, logon_user):
        findings = []

        if self._is_unquoted_path(binary_path):
            findings.append(self._flag(
                "HIGH",
                "Unquoted Service Path",
                f"{service_name} has an unquoted path: {binary_path}"
            ))

        if self._is_path_writable(binary_path):
            findings.append(self._flag(
                "HIGH",
                "Writable Service Binary",
                f"{service_name} binary is writable by standard users: {binary_path}"
            ))

        if logon_user.lower().startswith("localservice") or logon_user.lower().startswith("networkservice"):
            findings.append(self._flag(
                "MEDIUM",
                "Weak Service Logon Account",
                f"{service_name} runs as {logon_user}"
            ))

        if logon_user.lower() in ("localsystem", "system", "nt authority\\system"):
            findings.append(self._flag(
                "HIGH",
                "High Privilege Token Service",
                f"{service_name} runs with SYSTEM-level privileges"
            ))

        if not self._is_signed(binary_path):
            findings.append(self._flag(
                "MEDIUM",
                "Unsigned Executable",
                f"{service_name} binary is unsigned: {binary_path}"
            ))

        return findings

    def evaluate_task(self, task_name, run_as, executable_path):
        findings = []

        if executable_path:
            exe_lower = executable_path.lower()
            if any(s in exe_lower for s in ["\\temp", "\\appdata", "\\downloads"]):
                findings.append(self._flag(
                    "HIGH",
                    "Anomalous Scheduled Task",
                    f"{task_name} runs from unusual path: {executable_path}"
                ))

            if not self._is_signed(executable_path):
                findings.append(self._flag(
                    "MEDIUM",
                    "Unsigned Task Executable",
                    f"{task_name} executable is unsigned: {executable_path}"
                ))

        if run_as and run_as.lower() in ("system", "localsystem", "nt authority\\system"):
            findings.append(self._flag(
                "HIGH",
                "High Privilege Task",
                f"{task_name} runs as SYSTEM"
            ))

        return findings

    def evaluate_permissions(self, access_mask, sid, user_or_group, resource_type="file"):
        findings = []

        if sid.startswith("S-1-5-32-545") or user_or_group.lower() in ("everyone", "users", "authenticated users"):
            if access_mask & (ntsecuritycon.FILE_ALL_ACCESS | ntsecuritycon.GENERIC_ALL):
                findings.append(self._flag(
                    "HIGH",
                    "Overly Permissive ACL",
                    f"{user_or_group} has full access to {resource_type}"
                ))

        return findings

    def evaluate_registry_acl(self, key_path, user_or_group, access_mask):
        if access_mask & ntsecuritycon.KEY_ALL_ACCESS:
            return [self._flag(
                "HIGH",
                "Overly Permissive Registry ACL",
                f"{user_or_group} has full access to registry key: {key_path}"
            )]
        return []

    def evaluate_group_membership(self, group_name, members):
        findings = []

        if group_name.lower() in ("administrators", "domain admins") and len(members) > 0:
            findings.append(self._flag(
                "HIGH",
                "Privileged Group Membership",
                f"{group_name} contains: {', '.join(members)}"
            ))

        return findings

    def evaluate_orphaned_sid(self, sid):
        return [self._flag(
            "MEDIUM",
            "Orphaned SID",
            f"SID {sid} could not be resolved"
        )]

    def _flag(self, severity, category, description):
        return {
            "severity": severity,
            "category": category,
            "description": description
        }

    def _is_unquoted_path(self, path):
        if path and " " in path and not path.strip().startswith("\""):
            return True
        return False

    def _is_path_writable(self, path):
        try:
            if not path or not os.path.exists(path):
                return False
            return os.access(path, os.W_OK)
        except Exception:
            return False

    def _is_signed(self, path):
        # Stub — later can use pefile or ctypes with WinVerifyTrust
        if not path or not os.path.exists(path):
            return False
        return False  # treat as unsigned until logic is added

    def evaluate_autostart(self, key_path, value_name, command):
        findings = []

        if not command:
            return findings

        lower_cmd = command.lower()

        # Risk: Script-based autostart
        if any(ext in lower_cmd for ext in ['.vbs', '.js', '.bat', 'powershell', 'wscript', 'cscript']):
            findings.append(self._flag(
                "MEDIUM",
                "Script-Based Autostart",
                f"Autostart entry '{value_name}' in {key_path} uses a scripting engine: {command}"
            ))

        # Risk: Executable from non-standard location
        if not lower_cmd.startswith("c:\\windows") and not lower_cmd.startswith("c:\\program files"):
            findings.append(self._flag(
                "MEDIUM",
                "Non-Standard Autostart Path",
                f"Autostart entry '{value_name}' in {key_path} points to suspicious location: {command}"
            ))

        # Risk: AppData/Temp location (common persistence tactic)
        if "appdata" in lower_cmd or "temp" in lower_cmd:
            findings.append(self._flag(
                "HIGH",
                "Persistence via Autostart",
                f"Autostart entry '{value_name}' in {key_path} runs from AppData or Temp: {command}"
            ))

        # Risk: Unsigned executable
        if not self._is_signed(command.split()[0]):
            findings.append(self._flag(
                "MEDIUM",
                "Unsigned Autostart Binary",
                f"The binary for '{value_name}' in {key_path} is unsigned: {command}"
            ))

        return findings

    def evaluate_share(self, share_name, share_path):
        findings = []
                                 
        # Check if share name suggests a sensitive folder
        if any(keyword in share_name.lower() for keyword in ['admin', 'confidential', 'backup', 'sensitive']):
            findings.append(self._flag(
                "HIGH",
                "Sensitive Shared Folder",
                f"Shared folder '{share_name}' located at '{share_path}' might contain sensitive data."
            ))
    
        # Check if the share path is in a non-standard location
        if not share_path.lower().startswith("c:\\windows") and not share_path.lower().startswith("c:\\program files"):
            findings.append(self._flag(
                "MEDIUM",
                "Non-Standard Share Location",
                f"Shared folder '{share_name}' located at '{share_path}' is outside of standard directories."
            ))
    
        # Check if the share has writable access for low-privilege users (e.g., Everyone or Users group)
        try:
            sd = win32security.GetFileSecurity(share_path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            
            if dacl is None:
                findings.append(self._flag(
                    "HIGH",
                    "No DACL Found",
                    f"Shared folder '{share_name}' at '{share_path}' has no defined ACLs."
                ))
            else:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid = ace[2]
                    access_mask = ace[1]
                    try:
                        user, domain, _ = win32security.LookupAccountSid(None, sid)
                        user_str = f"{domain}\\{user}"
    
                        # Check for overly permissive access for Everyone, Users, or other low-privilege groups
                        if user_str.lower() in ("everyone", "users", "authenticated users"):
                            if access_mask & (ntsecuritycon.FILE_ALL_ACCESS | ntsecuritycon.GENERIC_ALL):
                                findings.append(self._flag(
                                    "HIGH",
                                    "Overly Permissive Share ACL",
                                    f"{user_str} has full access to shared folder '{share_name}' at '{share_path}'."
                                ))
                        
                        # Check for specific high-risk groups with full control (e.g., Administrators)
                        if user_str.lower() in ("administrators", "domain admins"):
                            if access_mask & (ntsecuritycon.FILE_ALL_ACCESS | ntsecuritycon.GENERIC_ALL):
                                findings.append(self._flag(
                                    "HIGH",
                                    "Administrator Full Access",
                                    f"Administrator group has full access to shared folder '{share_name}' at '{share_path}'."
                                ))
    
                    except Exception as e:
                        findings.append(self._flag(
                            "LOW",
                            "Unresolved SID",
                            f"SID {sid} in shared folder '{share_name}' at '{share_path}' could not be resolved."
                        ))
    
        except Exception as e:
            findings.append(self._flag(
                "HIGH",
                "ACL Retrieval Failed",
                f"Failed to retrieve ACLs for shared folder '{share_name}' at '{share_path}': {e}"
            ))
    
        # Check for password protection or anonymous access
        try:
            share_info = win32net.NetShareGetInfo(None, share_name, 502)
            if not share_info.get('password', None):
                findings.append(self._flag(
                    "HIGH",
                    "No Password Protection",
                    f"Shared folder '{share_name}' at '{share_path}' is not password protected."
                ))
        except Exception as e:
            findings.append(self._flag(
                "MEDIUM",
                "Password Protection Check Failed",
                f"Failed to check password protection for shared folder '{share_name}' at '{share_path}': {e}"
            ))
    
        # Check for hidden shares (ending with $)
        if share_name.endswith("$"):
            findings.append(self._flag(
                "MEDIUM",
                "Hidden Share",
                f"Shared folder '{share_name}' at '{share_path}' is a hidden share."
            ))
    
        return findings

    def calculate_risk_score(risks):
        """Calculate an overall risk score based on findings."""
        risk_weights = {
            "low": 1,
            "medium": 3,
            "high": 5
        }
        
        total_score = 0
        max_possible = 0
        
        for risk in risks:
            severity = risk.get("severity", "").lower()
            if severity in risk_weights:
                total_score += risk_weights[severity]
                
        # Calculate total findings count by severity
        severity_counts = {
            "low": 0,
            "medium": 0,
            "high": 0
        }
        
        for risk in risks:
            severity = risk.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate maximum possible score (if all high)
        max_possible = len(risks) * risk_weights["high"]
        
        # Normalize to 0-100 scale
        normalized_score = (total_score / max_possible * 100) if max_possible > 0 else 0
        
        result = {
            "score": round(normalized_score),
            "findings": {
                "total": len(risks),
                "by_severity": severity_counts
            }
        }
        
        return result
