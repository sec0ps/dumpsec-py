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
import winreg
import os
import json
import re
from risk_engine import RiskEngine

risk = RiskEngine()

def get_powershell_version():
    """Get the installed PowerShell version."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", "$PSVersionTable.PSVersion | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0:
            return output.stdout.strip()
        return "Failed to retrieve version"
    except Exception as e:
        return f"Error: {e}"

def get_execution_policy():
    """Get the PowerShell execution policy settings."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", "Get-ExecutionPolicy -List | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0:
            return json.loads(output.stdout)
        return "Failed to retrieve execution policy"
    except Exception as e:
        return f"Error: {e}"

def get_module_logging_settings():
    """Get PowerShell module logging settings."""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            enabled, _ = winreg.QueryValueEx(key, "EnableModuleLogging")
            return {"Enabled": bool(enabled)}
    except FileNotFoundError:
        return {"Enabled": False, "Note": "Module logging not configured"}
    except Exception as e:
        return {"Error": str(e)}

def get_script_block_logging_settings():
    """Get PowerShell script block logging settings."""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            enabled, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
            return {"Enabled": bool(enabled)}
    except FileNotFoundError:
        return {"Enabled": False, "Note": "Script block logging not configured"}
    except Exception as e:
        return {"Error": str(e)}

def get_transcript_settings():
    """Get PowerShell transcription settings."""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            enabled, _ = winreg.QueryValueEx(key, "EnableTranscripting")
            include_invocation_header, _ = winreg.QueryValueEx(key, "IncludeInvocationHeader")
            output_directory, _ = winreg.QueryValueEx(key, "OutputDirectory")
            
            return {
                "Enabled": bool(enabled),
                "IncludeInvocationHeader": bool(include_invocation_header),
                "OutputDirectory": output_directory
            }
    except FileNotFoundError:
        return {"Enabled": False, "Note": "Transcription not configured"}
    except Exception as e:
        return {"Error": str(e)}

def scan_for_scripts(directories):
    """Scan for PowerShell scripts in specified directories."""
    scripts = []
    for directory in directories:
        if not os.path.exists(directory):
            continue
            
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.ps1'):
                    script_path = os.path.join(root, file)
                    scripts.append(script_path)
    
    return scripts

def analyze_script(script_path):
    """Analyze a PowerShell script for security concerns."""
    risks = []
    
    try:
        with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Check for encoded commands
        if "-EncodedCommand" in content or "-enc " in content.lower():
            risks.append({
                "severity": "high",
                "category": "PowerShell Script",
                "description": f"Script '{script_path}' contains encoded commands, which can be used to obfuscate malicious code"
            })
        
        # Check for execution bypass
        if "-ExecutionPolicy Bypass" in content or "-exec bypass" in content.lower():
            risks.append({
                "severity": "high",
                "category": "PowerShell Script",
                "description": f"Script '{script_path}' attempts to bypass execution policy"
            })
        
        # Check for downloading content
        if "Invoke-WebRequest" in content or "wget " in content or "curl " in content or "Net.WebClient" in content:
            risks.append({
                "severity": "medium",
                "category": "PowerShell Script",
                "description": f"Script '{script_path}' downloads content from the Internet"
            })
        
        # Check for suspicious commands
        suspicious_cmds = ["Hidden", "Invoke-Expression", "IEX", "Invoke-Command", "Invoke-Mimikatz", 
                          "Get-Credential", "ConvertTo-SecureString", "PSCredential", "Start-Process"]
        
        for cmd in suspicious_cmds:
            if cmd in content:
                risks.append({
                    "severity": "medium",
                    "category": "PowerShell Script",
                    "description": f"Script '{script_path}' uses potentially risky command: {cmd}"
                })
        
        # Check for Windows API access
        if "[DllImport" in content or "Add-Type" in content and (".dll" in content.lower() or "DllImport" in content):
            risks.append({
                "severity": "medium",
                "category": "PowerShell Script",
                "description": f"Script '{script_path}' uses Windows API calls, which can bypass security controls"
            })
    
    except Exception as e:
        risks.append({
            "severity": "low",
            "category": "PowerShell Script",
            "description": f"Failed to analyze script '{script_path}': {e}"
        })
    
    return risks

def run():
    """Run the PowerShell security audit."""
    results = {}
    all_risks = []
    
    # Get PowerShell version
    results["PowerShell Version"] = get_powershell_version()
    
    # Get execution policy
    execution_policy = get_execution_policy()
    results["Execution Policy"] = execution_policy
    
    # Check if execution policy is too permissive
    if isinstance(execution_policy, list):
        for policy in execution_policy:
            if isinstance(policy, dict) and policy.get("ExecutionPolicy") in ["Unrestricted", "Bypass"]:
                all_risks.append({
                    "severity": "high",
                    "category": "PowerShell Security",
                    "description": f"Execution policy '{policy.get('ExecutionPolicy')}' at scope '{policy.get('Scope')}' allows unsigned scripts to run"
                })
    
    # Get logging settings
    module_logging = get_module_logging_settings()
    script_block_logging = get_script_block_logging_settings()
    transcript_settings = get_transcript_settings()
    
    results["Module Logging"] = module_logging
    results["Script Block Logging"] = script_block_logging
    results["Transcription"] = transcript_settings
    
    # Check for missing logging features
    if not module_logging.get("Enabled", False):
        all_risks.append({
            "severity": "medium",
            "category": "PowerShell Security",
            "description": "PowerShell module logging is not enabled, reducing audit capabilities"
        })
    
    if not script_block_logging.get("Enabled", False):
        all_risks.append({
            "severity": "high",
            "category": "PowerShell Security",
            "description": "PowerShell script block logging is not enabled, potentially allowing malicious scripts to run undetected"
        })
    
    if not transcript_settings.get("Enabled", False):
        all_risks.append({
            "severity": "medium",
            "category": "PowerShell Security",
            "description": "PowerShell transcription is not enabled, reducing audit capabilities"
        })
    
    # Scan for PowerShell scripts in common locations
    script_dirs = [
        os.path.expandvars(r"%SystemRoot%\System32\WindowsPowerShell\v1.0"),
        os.path.expandvars(r"%ProgramFiles%\WindowsPowerShell"),
        os.path.expandvars(r"%ProgramFiles(x86)%\WindowsPowerShell"),
        os.path.expandvars(r"%USERPROFILE%\Documents"),
        os.path.expandvars(r"%USERPROFILE%\Downloads")
    ]
    
    scripts = scan_for_scripts(script_dirs)
    results["PowerShell Scripts"] = scripts
    
    # Analyze each script
    for script in scripts:
        script_risks = analyze_script(script)
        all_risks.extend(script_risks)
    
    results["_risks"] = all_risks
    return results
