import ntsecuritycon
import re
import os
import ctypes

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
