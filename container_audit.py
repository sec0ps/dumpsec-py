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
import json
import os

def check_wsl_status():
    """Check WSL installation status and security posture."""
    wsl_info = {}
    risks = []
    
    try:
        # Check if WSL is installed
        output = subprocess.run(
            ["wsl", "--status"],
            capture_output=True, text=True
        )
        
        if output.returncode != 0:
            wsl_info["installed"] = False
            return {"WSL Status": wsl_info, "_risks": risks}
        
        wsl_info["installed"] = True
        
        # Get list of distributions
        output = subprocess.run(
            ["wsl", "--list", "--verbose"],
            capture_output=True, text=True
        )
        
        if output.returncode == 0:
            wsl_info["distributions"] = output.stdout.strip()
            
            # Check for WSL 1 distributions (less secure)
            if "1" in output.stdout:
                risks.append({
                    "severity": "medium",
                    "category": "WSL Security",
                    "description": "WSL 1 distributions detected, which have weaker isolation than WSL 2"
                })
    except Exception as e:
        wsl_info["error"] = str(e)
    
    # Check Docker Desktop/Windows Containers
    try:
        output = subprocess.run(
            ["docker", "info", "--format", "{{json .}}"],
            capture_output=True, text=True
        )
        
        if output.returncode == 0:
            docker_info = json.loads(output.stdout)
            wsl_info["docker"] = {
                "version": docker_info.get("ServerVersion", "Unknown"),
                "isolation": docker_info.get("Isolation", "Unknown")
            }
            
            # Check container isolation mode
            if docker_info.get("Isolation", "").lower() != "hyperv":
                risks.append({
                    "severity": "high",
                    "category": "Container Security",
                    "description": "Docker containers not using Hyper-V isolation"
                })
    except Exception:
        wsl_info["docker"] = "Not installed or not running"
    
    return {"WSL and Container Status": wsl_info, "_risks": risks}
