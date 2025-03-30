# =============================================================================
# DumpSec-Py - Windows Security Auditing Tool - Defender ATP Module
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
#
# =============================================================================

import winreg
import subprocess
import json
import os
import ctypes
from datetime import datetime

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_defender_status():
    """Get the current status of Windows Defender."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", 
             "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled, AntivirusEnabled, TamperProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, BehaviorMonitorEnabled | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0 and output.stdout.strip():
            return json.loads(output.stdout)
        return {"Error": "Failed to retrieve Defender status"}
    except Exception as e:
        return {"Error": str(e)}

def get_defender_preferences():
    """Get Windows Defender preferences."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", 
             "Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableScriptScanning, DisableIOAVProtection, DisableIntrusionPreventionSystem, SubmitSamplesConsent, CloudBlockLevel, CloudExtendedTimeout, EnableNetworkProtection, EnableControlledFolderAccess | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0 and output.stdout.strip():
            return json.loads(output.stdout)
        return {"Error": "Failed to retrieve Defender preferences"}
    except Exception as e:
        return {"Error": str(e)}

def get_defender_exclusions():
    """Get Windows Defender exclusions."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", 
             "$exclusions = @{}; $exclusions.Paths = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionPath); $exclusions.Extensions = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension); $exclusions.Processes = @(Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess); $exclusions | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0 and output.stdout.strip():
            return json.loads(output.stdout)
        return {"Error": "Failed to retrieve Defender exclusions", "Paths": [], "Extensions": [], "Processes": []}
    except Exception as e:
        return {"Error": str(e), "Paths": [], "Extensions": [], "Processes": []}

def get_atp_onboarding_status():
    """Check if the system is onboarded to Microsoft Defender for Endpoint (ATP)."""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            onboarded, _ = winreg.QueryValueEx(key, "OnboardingState")
            org_id, _ = winreg.QueryValueEx(key, "OrgId")
            
            return {
                "Onboarded": bool(onboarded),
                "OrganizationID": org_id
            }
    except FileNotFoundError:
        return {"Onboarded": False, "Note": "System not onboarded to Microsoft Defender for Endpoint"}
    except Exception as e:
        return {"Error": str(e)}

def get_edr_config():
    """Get EDR configuration settings."""
    try:
        key_path = r"SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
        settings = {}
        
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, "ForceDefenderPassiveMode")
                settings["PassiveMode"] = bool(value)
            except:
                settings["PassiveMode"] = False
                
            try:
                value, _ = winreg.QueryValueEx(key, "DisableAntiSpyware")
                settings["AntiSpywareDisabled"] = bool(value)
            except:
                settings["AntiSpywareDisabled"] = False
        
        return settings
    except FileNotFoundError:
        return {"Note": "Microsoft Defender for Endpoint policies not configured"}
    except Exception as e:
        return {"Error": str(e)}

def get_recent_threats():
    """Get recent threat detections."""
    try:
        output = subprocess.run(
            ["powershell", "-Command", 
             "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10 | Select-Object ThreatName, SeverityID, Category, InitialDetectionTime, ProcessName, Resources | ConvertTo-Json"],
            capture_output=True, text=True
        )
        if output.returncode == 0 and output.stdout.strip():
            return json.loads(output.stdout)
        return []
    except Exception as e:
        return {"Error": str(e)}

def run():
    """Run the Microsoft Defender for Endpoint audit."""
    results = {}
    all_risks = []
    
    if not is_admin():
        results["Error"] = "Administrator privileges required for complete Microsoft Defender analysis"
        all_risks.append({
            "severity": "medium",
            "category": "Defender ATP",
            "description": "Script not running with administrator privileges, which limits visibility into Defender settings"
        })
    
    # Get Defender status
    defender_status = get_defender_status()
    results["Defender Status"] = defender_status
    
    # Evaluate risks based on Defender status
    if isinstance(defender_status, dict):
        if defender_status.get("Error"):
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": f"Failed to retrieve Windows Defender status: {defender_status.get('Error')}"
            })
        else:
            if not defender_status.get("RealTimeProtectionEnabled", True):
                all_risks.append({
                    "severity": "high",
                    "category": "Defender ATP",
                    "description": "Real-time protection is disabled in Windows Defender"
                })
            
            if not defender_status.get("AntivirusEnabled", True):
                all_risks.append({
                    "severity": "high",
                    "category": "Defender ATP",
                    "description": "Antivirus protection is disabled in Windows Defender"
                })
                
            if not defender_status.get("TamperProtectionEnabled", True):
                all_risks.append({
                    "severity": "high",
                    "category": "Defender ATP",
                    "description": "Tamper Protection is disabled in Windows Defender"
                })
                
            if not defender_status.get("BehaviorMonitorEnabled", True):
                all_risks.append({
                    "severity": "medium",
                    "category": "Defender ATP",
                    "description": "Behavior Monitoring is disabled in Windows Defender"
                })
    
    # Get Defender preferences
    defender_prefs = get_defender_preferences()
    results["Defender Preferences"] = defender_prefs
    
    # Evaluate risks based on preferences
    if isinstance(defender_prefs, dict):
        if defender_prefs.get("DisableRealtimeMonitoring", False):
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": "Real-time monitoring is disabled in Windows Defender preferences"
            })
            
        if defender_prefs.get("DisableBehaviorMonitoring", False):
            all_risks.append({
                "severity": "medium",
                "category": "Defender ATP",
                "description": "Behavior monitoring is disabled in Windows Defender preferences"
            })
            
        if defender_prefs.get("DisableScriptScanning", False):
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": "Script scanning is disabled in Windows Defender"
            })
            
        if not defender_prefs.get("EnableNetworkProtection", 0) == 1:
            all_risks.append({
                "severity": "medium",
                "category": "Defender ATP",
                "description": "Network protection is not enabled in Windows Defender"
            })
            
        if not defender_prefs.get("EnableControlledFolderAccess", 0) == 1:
            all_risks.append({
                "severity": "medium",
                "category": "Defender ATP",
                "description": "Controlled folder access (anti-ransomware) is not enabled"
            })
    
    # Get exclusions
    exclusions = get_defender_exclusions()
    results["Defender Exclusions"] = exclusions
    
    # Check for risky exclusions
    if isinstance(exclusions, dict) and not exclusions.get("Error"):
        paths = exclusions.get("Paths", []) or []  # Ensure it's a list, even if None
        extensions = exclusions.get("Extensions", []) or []
        processes = exclusions.get("Processes", []) or []
        
        # Look for risky path exclusions
        risky_paths = [p for p in paths if p and any(dangerous in str(p).lower() for dangerous in 
                      ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\", "\\users\\public\\"])]
        if risky_paths:
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": f"Potentially dangerous path exclusions in Windows Defender: {', '.join(risky_paths)}"
            })
        
        # Look for risky extension exclusions
        risky_extensions = [e for e in extensions if e and str(e).lower() in [".exe", ".dll", ".ps1", ".bat", ".cmd", ".js", ".vbs"]]
        if risky_extensions:
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": f"High-risk extension exclusions in Windows Defender: {', '.join(risky_extensions)}"
            })
    
    # Get ATP/EDR onboarding status
    atp_status = get_atp_onboarding_status()
    results["Defender for Endpoint Status"] = atp_status
    
    # Check if not onboarded to ATP
    if not atp_status.get("Onboarded", False) and not atp_status.get("Error"):
        all_risks.append({
            "severity": "high",
            "category": "Defender ATP",
            "description": "System is not onboarded to Microsoft Defender for Endpoint (ATP)"
        })
    
    # Get EDR configuration
    edr_config = get_edr_config()
    results["EDR Configuration"] = edr_config
    
    # Check for passive mode
    if edr_config.get("PassiveMode", False):
        all_risks.append({
            "severity": "high",
            "category": "Defender ATP",
            "description": "Microsoft Defender for Endpoint is configured in passive mode"
        })
    
    # Get recent threats
    recent_threats = get_recent_threats()
    results["Recent Threats"] = recent_threats
    
    # Check for recent threat detections
    if isinstance(recent_threats, list) and len(recent_threats) > 0:
        for threat in recent_threats:
            all_risks.append({
                "severity": "high",
                "category": "Defender ATP",
                "description": f"Recent threat detected: {threat.get('ThreatName', 'Unknown')} on {threat.get('InitialDetectionTime', 'Unknown date')}"
            })
    
    results["_risks"] = all_risks
    return results

if __name__ == "__main__":
    # Direct script execution 
    result = run()
    print(json.dumps(result, indent=2))
