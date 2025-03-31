# =============================================================================
# DumpSec-Py - Windows Security Auditing Tool (Container Audit Module)
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
#          perform detailed security audits on Windows systems. This module
#          specifically handles WSL and container security auditing.
#
# =============================================================================

import subprocess
import json
import os
import re
import platform
import time
import signal
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path



def check_wsl_status():
    """
    Check WSL installation status and security posture.
    Legacy function maintained for backward compatibility.
    
    Returns:
        dict: Basic WSL status information with risk assessment
    """
    # Original function implementation
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

def _try_filesystem_detection(results):
    """
    Try to detect WSL distributions by checking for distribution data dynamically.
    """
    try:
        print("Trying dynamic WSL distribution detection...")
        
        # Use PowerShell to get WSL distribution information from registry
        ps_command = r'''
        $wslDistros = @()
        
        # Check registry for WSL distributions
        $lxssKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
        if (Test-Path $lxssKey) {
            Get-ChildItem $lxssKey | ForEach-Object {
                $distroKey = $_
                $distroName = (Get-ItemProperty -Path $distroKey.PSPath -Name "DistributionName" -ErrorAction SilentlyContinue).DistributionName
                $version = (Get-ItemProperty -Path $distroKey.PSPath -Name "Version" -ErrorAction SilentlyContinue).Version
                if ($distroName) {
                    $wslDistros += [PSCustomObject]@{
                        Name = $distroName
                        Version = if ($version -eq 2) { 2 } else { 1 }
                    }
                }
            }
        }
        
        # Also check system registry
        $lxssKeySystem = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
        if (Test-Path $lxssKeySystem) {
            Get-ChildItem $lxssKeySystem | ForEach-Object {
                $distroKey = $_
                $distroName = (Get-ItemProperty -Path $distroKey.PSPath -Name "DistributionName" -ErrorAction SilentlyContinue).DistributionName
                $version = (Get-ItemProperty -Path $distroKey.PSPath -Name "Version" -ErrorAction SilentlyContinue).Version
                if ($distroName) {
                    # Only add if not already found
                    $found = $false
                    foreach ($d in $wslDistros) {
                        if ($d.Name -eq $distroName) {
                            $found = $true
                            break
                        }
                    }
                    if (-not $found) {
                        $wslDistros += [PSCustomObject]@{
                            Name = $distroName
                            Version = if ($version -eq 2) { 2 } else { 1 }
                        }
                    }
                }
            }
        }
        
        # If no distributions found through registry, try running wsl command
        if ($wslDistros.Count -eq 0) {
            try {
                $output = & wsl.exe --list
                $lines = $output -split "`n"
                foreach ($line in $lines) {
                    $line = $line.Trim()
                    if ($line -and -not $line.StartsWith("Windows") -and $line -ne "") {
                        $name = $line -replace "\\(Default\\)", "" 
                        $name = $name.Trim()
                        $wslDistros += [PSCustomObject]@{
                            Name = $name
                            Version = 2  # Assume WSL 2
                        }
                    }
                }
            } catch {
                Write-Output "Error running wsl --list: $_"
            }
        }
        
        $wslDistros | ConvertTo-Json
        '''
        
        cmd = ["powershell", "-Command", ps_command]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and output.stdout.strip():
            try:
                # Parse the JSON output
                distro_data = json.loads(output.stdout.strip())
                
                # Convert to array if single object
                if isinstance(distro_data, dict):
                    distro_data = [distro_data]
                
                # Add each distribution
                for distro in distro_data:
                    distro_name = distro.get("Name", "")
                    if distro_name and not "\u0000" in distro_name:
                        results["wsl"]["distributions"].append({
                            "name": distro_name,
                            "state": "Unknown",  # Can't determine state from registry
                            "version": int(distro.get("Version", 2))  # Default to WSL 2
                        })
                
                # If we found distributions, add a finding
                if results["wsl"]["distributions"]:
                    results["findings"].append({
                        "severity": "info",
                        "category": "WSL Detection",
                        "description": "WSL distributions were detected. Some security checks may be limited.",
                        "remediation": "Ensure WSL is properly configured for security."
                    })
            except json.JSONDecodeError:
                print("Failed to parse PowerShell output as JSON")
    except Exception as e:
        print(f"Error in WSL detection: {str(e)}")

def _check_wsl_distro_security(distro_name, target_system=None, credentials=None):
    """
    Check security configuration of a specific WSL distribution.
    
    Args:
        distro_name (str): Name of the WSL distribution
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
        
    Returns:
        dict: Security findings for the specified distribution
    """
    results = {
        "distribution": distro_name,
        "findings": [],
        "security_data": {}
    }
    
    # Validate distribution name
    if not distro_name or "\u0000" in distro_name:
        print(f"Invalid distro name: {repr(distro_name)}")
        return results
    
    # Simple check to see if distribution is running
    print(f"Testing if {distro_name} responds...")
    try:
        cmd = ["wsl", "-d", distro_name, "--exec", "echo", "WSL_TEST_OK"]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if output.returncode == 0 and "WSL_TEST_OK" in output.stdout:
            print(f"✓ Distribution {distro_name} is responsive")
            results["security_data"]["status"] = "Running"
        else:
            print(f"✗ Distribution {distro_name} is not responsive")
            results["security_data"]["status"] = "Not responding"
            results["findings"].append({
                "severity": "info",
                "category": "WSL Status",
                "description": f"Distribution '{distro_name}' is not currently running or responsive",
                "remediation": "Start the distribution to perform security checks"
            })
            return results
    except Exception as e:
        print(f"! Error testing distribution {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Status",
            "description": f"Error testing WSL distribution: {str(e)}"
        })
        return results
    
    # Check for sensitive mounts
    try:
        print(f"Checking mounts for {distro_name}...")
        wsl_command = f"mount | grep -E '/mnt/[cd]|/mnt/host' || echo 'No system mounts found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", distro_name, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", distro_name, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No system mounts found" not in output.stdout:
            results["findings"].append({
                "severity": "high",
                "category": "WSL File System",
                "description": "System drives automatically mounted in WSL, presenting potential data exfiltration risk",
                "remediation": "Consider unmounting sensitive drives or restricting access",
                "compliance": ["CIS 1.1.3"]
            })
    except Exception as e:
        print(f"Error checking WSL mounts for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Mounts",
            "description": f"Error checking WSL mounts: {str(e)}"
        })
    
    # Check for privileged users
    try:
        print(f"Checking privileged users for {distro_name}...")
        wsl_command = "grep -E '^sudo|^wheel' /etc/group | cut -d: -f4 || echo 'No sudo users found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", distro_name, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", distro_name, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No sudo users found" not in output.stdout and output.stdout.strip():
            sudo_users = output.stdout.strip().split(',')
            if len(sudo_users) > 1:
                results["findings"].append({
                    "severity": "medium",
                    "category": "WSL Privileges",
                    "description": f"Multiple users ({len(sudo_users)}) have sudo privileges in WSL distribution",
                    "remediation": "Limit privileged access to required users only",
                    "compliance": ["CIS 1.1.5"]
                })
    except Exception as e:
        print(f"Error checking WSL privileged users for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Users",
            "description": f"Error checking WSL privileged users: {str(e)}"
        })
    
    # Check for exposed network services
    try:
        print(f"Checking network services for {distro_name}...")
        wsl_command = "netstat -tuln | grep 'LISTEN' | grep -v '127.0.0.1' | grep -v '::1' || echo 'No exposed services found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", distro_name, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", distro_name, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No exposed services found" not in output.stdout and output.stdout.strip():
            service_count = len(output.stdout.strip().split('\n'))
            if service_count > 0:
                results["findings"].append({
                    "severity": "high",
                    "category": "WSL Network",
                    "description": f"{service_count} network services exposed beyond localhost in WSL distribution",
                    "remediation": "Configure services to listen only on localhost or restrict with firewall",
                    "compliance": ["CIS 1.1.6", "NIST SP 800-190"]
                })
    except Exception as e:
        print(f"Error checking WSL network services for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Network",
            "description": f"Error checking WSL network services: {str(e)}"
        })
    
    # Check for container engines within WSL
    try:
        print(f"Checking container engines for {distro_name}...")
        wsl_command = "command -v docker podman containerd cri-o >/dev/null && echo 'Container engine found' || echo 'No container engine found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", distro_name, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", distro_name, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "Container engine found" in output.stdout:
            results["findings"].append({
                "severity": "medium",
                "category": "WSL Containers",
                "description": "Container engine detected within WSL distribution, creating nested container scenario",
                "remediation": "Consider security implications of nested containers and potential privilege escalation",
                "compliance": ["NIST SP 800-190"]
            })
    except Exception as e:
        print(f"Error checking for container engines in WSL for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Containers",
            "description": f"Error checking for container engines in WSL: {str(e)}"
        })
    
    return results

def check_wsl_and_container_security(target_system=None, credentials=None):
    """
    Comprehensive WSL and container security audit with enhanced detection capabilities.
    
    Args:
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
        
    Returns:
        dict: Detailed WSL and container security findings with risk assessments
    """
    # Start time for performance tracking
    start_time = time.time()
    
    results = {
        "wsl": {
            "installed": False,
            "version": None,
            "distributions": [],
            "security_settings": {}
        },
        "containers": {
            "docker_desktop": {
                "installed": False,
                "version": None,
                "isolation": None,
                "settings": {}
            },
            "windows_containers": {
                "enabled": False,
                "isolation": None
            },
            "podman": {
                "installed": False,
                "version": None
            }
        },
        "integration": {
            "kubernetes": False,
            "docker_compose": False
        },
        "findings": [],
        "compliance": {
            "cis": [],
            "nist": []
        }
    }
    
    # Check if running on Windows
    if platform.system() != "Windows" and not target_system:
        results["findings"].append({
            "severity": "info",
            "category": "Environment",
            "description": "Audit running from non-Windows system without remote target specified"
        })
    
    # WSL version and status check
    try:
        print("Checking WSL installation status...")
        cmd = ["wsl", "--status"]
        if target_system:
            # Use remote PowerShell execution for remote systems
            cmd = _create_remote_command(cmd, target_system, credentials)
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if output.returncode == 0:
            results["wsl"]["installed"] = True
            
            # Extract WSL version information
            version_match = re.search(r"WSL version: (\d+\.\d+\.\d+)", output.stdout)
            if version_match:
                results["wsl"]["version"] = version_match.group(1)
            
            # Check kernel version
            kernel_match = re.search(r"Kernel version: (\d+\.\d+\.\d+)", output.stdout)
            if kernel_match:
                results["wsl"]["security_settings"]["kernel_version"] = kernel_match.group(1)
                
                # Check if kernel is outdated (example threshold)
                kernel_version = kernel_match.group(1).split('.')
                if int(kernel_version[0]) < 5 or (int(kernel_version[0]) == 5 and int(kernel_version[1]) < 10):
                    results["findings"].append({
                        "severity": "medium",
                        "category": "WSL Security",
                        "description": f"Outdated WSL kernel version {kernel_match.group(1)} may contain security vulnerabilities",
                        "remediation": "Update WSL with 'wsl --update'",
                        "compliance": ["CIS 1.1.2", "NIST SP 800-190"]
                    })
        else:
            # Check if WSL is installed but disabled
            print("WSL status check failed, checking Windows features...")
            wsl_components = _check_windows_features(["Microsoft-Windows-Subsystem-Linux"], target_system, credentials)
            if wsl_components.get("Microsoft-Windows-Subsystem-Linux", False):
                results["wsl"]["installed"] = True
                results["wsl"]["enabled"] = False
                
                results["findings"].append({
                    "severity": "info",
                    "category": "WSL Status",
                    "description": "WSL is installed but may be disabled or not properly configured"
                })
    except Exception as e:
        print(f"Error checking WSL status: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Detection",
            "description": f"Error checking WSL status: {str(e)}"
        })
    
    # Detect WSL distributions
    if results["wsl"]["installed"]:
        try:
            print("Checking for WSL distributions...")
            # Try to get distributions with basic command
            cmd = ["wsl", "-l"]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if output.returncode == 0:
                # Simple parsing of output
                output_lines = output.stdout.strip().split('\n')
                
                # Skip the header line if it exists
                start_idx = 0
                for i, line in enumerate(output_lines):
                    if "Windows Subsystem for Linux Distributions:" in line:
                        start_idx = i + 1
                        break
                
                # Process each distribution line
                for i in range(start_idx, len(output_lines)):
                    line = output_lines[i].strip()
                    if not line:
                        continue
                        
                    # Handle possible "(Default)" marker
                    distro_name = line.replace("(Default)", "").strip()
                    
                    # Skip lines with null characters
                    if "\u0000" in distro_name:
                        continue
                        
                    # Add to our list
                    results["wsl"]["distributions"].append({
                        "name": distro_name,
                        "state": "Unknown",
                        "version": 2  # Default to WSL 2
                    })
            
            # If we didn't find any distributions, try PowerShell approach
            if not results["wsl"]["distributions"]:
                print("Basic approach failed, trying PowerShell approach...")
                _try_filesystem_detection(results)
        except Exception as e:
            print(f"Error detecting WSL distributions: {str(e)}")
            results["findings"].append({
                "severity": "error",
                "category": "WSL Distributions",
                "description": f"Error enumerating WSL distributions: {str(e)}"
            })
    
    # Check WSL distro security configurations
    if results["wsl"]["distributions"]:
        print(f"Found {len(results['wsl']['distributions'])} WSL distributions, checking security...")
        
        # Process each distribution sequentially for reliability
        for distro in results["wsl"]["distributions"]:
            try:
                print(f"Checking security for {distro['name']}...")
                distro_results = _check_wsl_distro_security(distro["name"])
                
                # Add distribution-specific findings to main results
                if "findings" in distro_results:
                    for finding in distro_results["findings"]:
                        finding["distro"] = distro["name"]
                        results["findings"].append(finding)
                
                # Add security data to distribution info
                if "security_data" in distro_results:
                    distro["security_data"] = distro_results["security_data"]
            except Exception as e:
                print(f"Error during security check for {distro['name']}: {str(e)}")
                results["findings"].append({
                    "severity": "error",
                    "category": "WSL Security",
                    "description": f"Error performing security checks for {distro['name']}: {str(e)}",
                    "distro": distro["name"]
                })
    else:
        # No distributions found
        if results["wsl"]["installed"]:
            results["findings"].append({
                "severity": "info",
                "category": "WSL Configuration",
                "description": "WSL is installed but no distributions were detected"
            })
    
    # Docker Desktop checks
    try:
        print("Checking Docker Desktop installation...")
        docker_path = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"
        if target_system:
            # Check for Docker Desktop installation remotely
            cmd = _create_remote_command(
                ["powershell", "-Command", f"Test-Path '{docker_path}'"],
                target_system, credentials
            )
        else:
            # Local check
            cmd = ["powershell", "-Command", f"Test-Path '{docker_path}'"]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if output.returncode == 0 and "True" in output.stdout:
            results["containers"]["docker_desktop"]["installed"] = True
            
            # Get Docker version and settings
            docker_cmd = [docker_path, "info", "--format", "{{json .}}"]
            if target_system:
                docker_cmd = _create_remote_command(docker_cmd, target_system, credentials)
                
            docker_output = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=15)
            
            if docker_output.returncode == 0:
                try:
                    docker_info = json.loads(docker_output.stdout)
                    results["containers"]["docker_desktop"]["version"] = docker_info.get("ServerVersion", "Unknown")
                    results["containers"]["docker_desktop"]["isolation"] = docker_info.get("Isolation", "Unknown")
                    
                    # Security checks
                    if docker_info.get("Isolation", "").lower() != "hyperv":
                        results["findings"].append({
                            "severity": "high",
                            "category": "Container Security",
                            "description": "Docker Desktop not using Hyper-V isolation, which reduces container security boundaries",
                            "remediation": "Enable Hyper-V isolation in Docker Desktop settings",
                            "compliance": ["CIS 2.8", "NIST SP 800-190"]
                        })
                    
                    # Check for insecure container configurations
                    security_options = docker_info.get("SecurityOptions", [])
                    if not any("selinux" in opt.lower() for opt in security_options) and \
                       not any("apparmor" in opt.lower() for opt in security_options):
                        results["findings"].append({
                            "severity": "medium",
                            "category": "Container Security",
                            "description": "No advanced Linux security modules (AppArmor/SELinux) detected for Docker containers",
                            "remediation": "Enable security profiles for containers",
                            "compliance": ["CIS 2.6", "NIST SP 800-190"]
                        })
                    
                    # Check for running containers
                    docker_ps_cmd = [docker_path, "ps", "--format", "{{json .}}"]
                    if target_system:
                        docker_ps_cmd = _create_remote_command(docker_ps_cmd, target_system, credentials)
                        
                    ps_output = subprocess.run(docker_ps_cmd, capture_output=True, text=True, timeout=10)
                    
                    if ps_output.returncode == 0 and ps_output.stdout.strip():
                        container_count = len(ps_output.stdout.strip().split('\n'))
                        results["containers"]["docker_desktop"]["running_containers"] = container_count
                        
                        if container_count > 0:
                            results["findings"].append({
                                "severity": "info",
                                "category": "Container Usage",
                                "description": f"{container_count} running containers detected",
                                "remediation": "Audit container permissions and mounted volumes for security risks"
                            })
                except json.JSONDecodeError:
                    results["findings"].append({
                        "severity": "error",
                        "category": "Docker Info",
                        "description": "Failed to parse Docker information output"
                    })
    except Exception as e:
        print(f"Error checking Docker Desktop status: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "Docker Detection",
            "description": f"Error checking Docker Desktop status: {str(e)}"
        })
    
    # Windows native container feature
    try:
        print("Checking Windows Container features...")
        container_features = _check_windows_features(
            ["Containers", "Microsoft-Hyper-V", "Microsoft-Hyper-V-All"],
            target_system, credentials
        )
        
        if container_features.get("Containers", False):
            results["containers"]["windows_containers"]["enabled"] = True
            
            # Check isolation mode
            if container_features.get("Microsoft-Hyper-V", False) or container_features.get("Microsoft-Hyper-V-All", False):
                results["containers"]["windows_containers"]["isolation"] = "hyperv"
            else:
                results["containers"]["windows_containers"]["isolation"] = "process"
                results["findings"].append({
                    "severity": "high",
                    "category": "Windows Containers",
                    "description": "Windows Containers enabled without Hyper-V, using less secure process isolation",
                    "remediation": "Enable Hyper-V feature for container isolation",
                    "compliance": ["CIS 2.8", "NIST SP 800-190"]
                })
    except Exception as e:
        print(f"Error checking Windows Container features: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "Windows Containers",
            "description": f"Error checking Windows Container features: {str(e)}"
        })
    
    # Check for container orchestration
    try:
        print("Checking for container orchestration...")
        # Kubernetes check
        k8s_paths = [
            "C:\\Program Files\\Kubernetes\\",
            f"{os.environ.get('USERPROFILE', 'C:\\Users\\Default')}\\AppData\\Local\\Microsoft\\WindowsApps\\kubectl.exe"
        ]
        
        for path in k8s_paths:
            if target_system:
                cmd = _create_remote_command(
                    ["powershell", "-Command", f"Test-Path '{path}'"],
                    target_system, credentials
                )
            else:
                cmd = ["powershell", "-Command", f"Test-Path '{path}'"]
                
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if output.returncode == 0 and "True" in output.stdout:
                results["integration"]["kubernetes"] = True
                results["findings"].append({
                    "severity": "info",
                    "category": "Container Orchestration",
                    "description": "Kubernetes tooling detected, additional security considerations apply",
                    "remediation": "Ensure RBAC is properly configured for Kubernetes deployments"
                })
                break
        
        # Docker Compose check
        if target_system:
            cmd = _create_remote_command(
                ["powershell", "-Command", "Get-ChildItem -Path $env:USERPROFILE -Filter docker-compose.yml -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName"],
                target_system, credentials
            )
        else:
            cmd = ["powershell", "-Command", "Get-ChildItem -Path $env:USERPROFILE -Filter docker-compose.yml -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName"]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if output.returncode == 0 and output.stdout.strip():
            results["integration"]["docker_compose"] = True
            results["findings"].append({
                "severity": "info",
                "category": "Container Orchestration",
                "description": "Docker Compose configuration detected, consider reviewing for security configurations",
                "remediation": "Ensure sensitive data is not stored in compose files and networks are properly segmented"
            })
    except Exception as e:
        print(f"Error checking container orchestration: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "Container Orchestration",
            "description": f"Error checking container orchestration: {str(e)}"
        })
    
    # Map findings to compliance frameworks
    print("Mapping findings to compliance frameworks...")
    for finding in results["findings"]:
        if "compliance" in finding:
            for compliance_id in finding["compliance"]:
                if compliance_id.startswith("CIS"):
                    results["compliance"]["cis"].append({
                        "id": compliance_id,
                        "finding": finding["description"],
                        "severity": finding["severity"]
                    })
                elif compliance_id.startswith("NIST"):
                    results["compliance"]["nist"].append({
                        "id": compliance_id,
                        "finding": finding["description"],
                        "severity": finding["severity"]
                    })
    
    # Record execution time for performance tracking
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Container audit completed in {execution_time:.2f} seconds")
    
    return results

def _try_registry_detection(results, target_system=None, credentials=None):
    """
    Try to detect WSL distributions via registry query if other methods fail.
    
    Args:
        results (dict): Results dictionary to update
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
    """
    try:
        print("Trying registry detection for WSL distributions...")
        # PowerShell command to get WSL distributions from registry
        ps_command = '''
        $wslDistros = @()
        $lxssKey = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
        if (Test-Path $lxssKey) {
            Get-ChildItem $lxssKey | ForEach-Object {
                $distroKey = $_
                $distroName = (Get-ItemProperty -Path $distroKey.PSPath -Name "DistributionName" -ErrorAction SilentlyContinue).DistributionName
                $version = (Get-ItemProperty -Path $distroKey.PSPath -Name "Version" -ErrorAction SilentlyContinue).Version
                if ($distroName) {
                    $wslDistros += [PSCustomObject]@{
                        Name = $distroName
                        Version = if ($version -eq 2) { 2 } else { 1 }
                    }
                }
            }
        }
        
        # Also check system-wide registry path
        $lxssKeySystem = "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
        if (Test-Path $lxssKeySystem) {
            Get-ChildItem $lxssKeySystem | ForEach-Object {
                $distroKey = $_
                $distroName = (Get-ItemProperty -Path $distroKey.PSPath -Name "DistributionName" -ErrorAction SilentlyContinue).DistributionName
                $version = (Get-ItemProperty -Path $distroKey.PSPath -Name "Version" -ErrorAction SilentlyContinue).Version
                if ($distroName) {
                    $found = $false
                    foreach ($d in $wslDistros) {
                        if ($d.Name -eq $distroName) {
                            $found = $true
                            break
                        }
                    }
                    if (-not $found) {
                        $wslDistros += [PSCustomObject]@{
                            Name = $distroName
                            Version = if ($version -eq 2) { 2 } else { 1 }
                        }
                    }
                }
            }
        }
        
        $wslDistros | ConvertTo-Json
        '''
        
        if target_system:
            cmd = _create_remote_command(["powershell", "-Command", ps_command], target_system, credentials)
        else:
            cmd = ["powershell", "-Command", ps_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and output.stdout.strip():
            try:
                # Parse the JSON output
                distro_data = json.loads(output.stdout.strip())
                
                # Convert to array if single object
                if isinstance(distro_data, dict):
                    distro_data = [distro_data]
                
                # Format each distribution
                distribution_list = []
                for distro in distro_data:
                    distribution_list.append({
                        "name": distro.get("Name", "Unknown"),
                        "state": "Unknown",  # Can't get state from registry
                        "version": int(distro.get("Version", 2))  # Default to WSL 2
                    })
                
                # Update the results
                results["wsl"]["distributions"] = distribution_list
                
                # Add findings for WSL1 distributions
                for distro in distribution_list:
                    if distro["version"] == 1:
                        results["findings"].append({
                            "severity": "medium", 
                            "category": "WSL Security",
                            "description": f"Distribution '{distro['name']}' uses WSL 1, which has weaker isolation than WSL 2",
                            "remediation": f"Convert to WSL 2 with 'wsl --set-version {distro['name']} 2'",
                            "compliance": ["CIS 1.1.1", "NIST SP 800-190"]
                        })
            except json.JSONDecodeError:
                # If JSON parsing fails, try one more fallback
                print("Registry detection failed, trying last resort method...")
                _try_last_resort_detection(results, target_system, credentials)
    except Exception as e:
        print(f"Error during registry detection: {str(e)}")
        # Try fallback detection as last resort
        _try_last_resort_detection(results, target_system, credentials)

def _try_last_resort_detection(results, target_system=None, credentials=None):
    """
    Last resort detection method for WSL distributions.
    
    Args:
        results (dict): Results dictionary to update
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
    """
    try:
        print("Using last resort detection for WSL distributions...")
        # Simple command to check for Ubuntu folder in Windows apps
        ps_command = '''
        $ubuntuFolder = Test-Path "$env:LOCALAPPDATA\\Packages\\CanonicalGroupLimited.Ubuntu*"
        $kaliFolder = Test-Path "$env:LOCALAPPDATA\\Packages\\KaliLinux*"
        $debianFolder = Test-Path "$env:LOCALAPPDATA\\Packages\\TheDebianProject.DebianGNULinux*"
        $suseFolder = Test-Path "$env:LOCALAPPDATA\\Packages\\*SUSE*"
        $fedoraFolder = Test-Path "$env:LOCALAPPDATA\\Packages\\*Fedora*"
        $found = @()
        
        if ($ubuntuFolder) { $found += "Ubuntu" }
        if ($kaliFolder) { $found += "Kali Linux" }
        if ($debianFolder) { $found += "Debian" }
        if ($suseFolder) { $found += "SUSE" }
        if ($fedoraFolder) { $found += "Fedora" }
        
        # Basic check for running WSL process
        $wslProcess = Get-Process -Name "wsl" -ErrorAction SilentlyContinue
        $wslRunning = $wslProcess -ne $null
        
        ConvertTo-Json @{
            'DistrosFound' = $found
            'WslRunning' = $wslRunning
        }
        '''
        
        if target_system:
            cmd = _create_remote_command(["powershell", "-Command", ps_command], target_system, credentials)
        else:
            cmd = ["powershell", "-Command", ps_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and output.stdout.strip():
            try:
                data = json.loads(output.stdout.strip())
                distros_found = data.get('DistrosFound', [])
                wsl_running = data.get('WslRunning', False)
                
                # Create entries for found distributions
                distribution_list = []
                for distro_name in distros_found:
                    distribution_list.append({
                        "name": distro_name,
                        "state": "Running" if wsl_running else "Stopped",
                        "version": 2  # Assume WSL 2
                    })
                
                # Update the results if we found distributions
                if distribution_list:
                    results["wsl"]["distributions"] = distribution_list
                    print(f"Last resort detection found distributions: {', '.join(distros_found)}")
                    
                    # Add a warning about the detection method
                    results["findings"].append({
                        "severity": "warning",
                        "category": "WSL Detection",
                        "description": "WSL distributions were detected using a fallback method. Some security checks may be limited.",
                        "remediation": "Ensure WSL is properly configured and accessible."
                    })
            except json.JSONDecodeError:
                print("Failed to parse last resort detection output")
                # No distributions found or parsing failed
                results["findings"].append({
                    "severity": "info",
                    "category": "WSL Configuration",
                    "description": "Could not reliably detect WSL distributions"
                })
    except Exception as e:
        print(f"Error in last resort detection: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Detection",
            "description": f"All detection methods failed: {str(e)}"
        })

def _check_wsl_distro_security(distro_name, target_system=None, credentials=None):
    """
    Check security configuration of a specific WSL distribution.
    
    Args:
        distro_name (str): Name of the WSL distribution
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
        
    Returns:
        dict: Security findings for the specified distribution
    """
    results = {
        "distribution": distro_name,
        "findings": []
    }
    
    # Clean distribution name - remove null characters and other problematic characters
    cleaned_distro = distro_name
    if not cleaned_distro or "\u0000" in cleaned_distro:
        # Skip distributions with null characters
        results["findings"].append({
            "severity": "warning",
            "category": "WSL Distribution",
            "description": f"Skipping distribution with invalid name: {repr(distro_name)}"
        })
        return results
    
    # Check for sensitive mounts with timeout protection
    try:
        print(f"Checking mounts for {distro_name}...")
        wsl_command = f"mount | grep -E '/mnt/[cd]|/mnt/host' || echo 'No system mounts found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", cleaned_distro, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", cleaned_distro, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No system mounts found" not in output.stdout:
            results["findings"].append({
                "severity": "high",
                "category": "WSL File System",
                "description": "System drives automatically mounted in WSL, presenting potential data exfiltration risk",
                "remediation": "Consider unmounting sensitive drives or restricting access",
                "compliance": ["CIS 1.1.3"]
            })
    except Exception as e:
        print(f"Error checking WSL mounts for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Mounts",
            "description": f"Error checking WSL mounts: {str(e)}"
        })
    
    # Check for privileged users with timeout protection
    try:
        print(f"Checking privileged users for {distro_name}...")
        wsl_command = "grep -E '^sudo|^wheel' /etc/group | cut -d: -f4 || echo 'No sudo users found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", cleaned_distro, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", cleaned_distro, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No sudo users found" not in output.stdout and output.stdout.strip():
            sudo_users = output.stdout.strip().split(',')
            if len(sudo_users) > 1:
                results["findings"].append({
                    "severity": "medium",
                    "category": "WSL Privileges",
                    "description": f"Multiple users ({len(sudo_users)}) have sudo privileges in WSL distribution",
                    "remediation": "Limit privileged access to required users only",
                    "compliance": ["CIS 1.1.5"]
                })
    except Exception as e:
        print(f"Error checking WSL privileged users for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Users",
            "description": f"Error checking WSL privileged users: {str(e)}"
        })
    
    # Check for exposed network services with timeout protection
    try:
        print(f"Checking network services for {distro_name}...")
        wsl_command = "netstat -tuln | grep 'LISTEN' | grep -v '127.0.0.1' | grep -v '::1' || echo 'No exposed services found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", cleaned_distro, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", cleaned_distro, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "No exposed services found" not in output.stdout and output.stdout.strip():
            service_count = len(output.stdout.strip().split('\n'))
            if service_count > 0:
                results["findings"].append({
                    "severity": "high",
                    "category": "WSL Network",
                    "description": f"{service_count} network services exposed beyond localhost in WSL distribution",
                    "remediation": "Configure services to listen only on localhost or restrict with firewall",
                    "compliance": ["CIS 1.1.6", "NIST SP 800-190"]
                })
    except Exception as e:
        print(f"Error checking WSL network services for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Network",
            "description": f"Error checking WSL network services: {str(e)}"
        })
    
    # Check for container engines within WSL with timeout protection
    try:
        print(f"Checking container engines for {distro_name}...")
        wsl_command = "command -v docker podman containerd cri-o >/dev/null && echo 'Container engine found' || echo 'No container engine found'"
        
        if target_system:
            cmd = _create_remote_command(
                ["wsl", "-d", cleaned_distro, "bash", "-c", f"'{wsl_command}'"],
                target_system, credentials
            )
        else:
            cmd = ["wsl", "-d", cleaned_distro, "bash", "-c", wsl_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and "Container engine found" in output.stdout:
            results["findings"].append({
                "severity": "medium",
                "category": "WSL Containers",
                "description": "Container engine detected within WSL distribution, creating nested container scenario",
                "remediation": "Consider security implications of nested containers and potential privilege escalation",
                "compliance": ["NIST SP 800-190"]
            })
    except Exception as e:
        print(f"Error checking for container engines in WSL for {distro_name}: {str(e)}")
        results["findings"].append({
            "severity": "error",
            "category": "WSL Containers",
            "description": f"Error checking for container engines in WSL: {str(e)}"
        })
    
    return results

def _check_windows_features(feature_names, target_system=None, credentials=None):
    """
    Check if specific Windows features are installed.
    
    Args:
        feature_names (list): List of Windows feature names to check
        target_system (str): Remote system to audit (None for local)
        credentials (dict): Authentication details for remote access
        
    Returns:
        dict: Mapping of feature names to boolean installation status
    """
    results = {}
    
    feature_list = ','.join([f"'{feature}'" for feature in feature_names])
    ps_command = f"Get-WindowsOptionalFeature -Online | Where-Object {{ ${feature_list} -contains $_.FeatureName }} | Select-Object FeatureName, State | ConvertTo-Json"
    
    try:
        if target_system:
            cmd = _create_remote_command(
                ["powershell", "-Command", ps_command],
                target_system, credentials
            )
        else:
            cmd = ["powershell", "-Command", ps_command]
            
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if output.returncode == 0 and output.stdout.strip():
            try:
                features_data = json.loads(output.stdout)
                # Handle single item not being in a list
                if not isinstance(features_data, list):
                    features_data = [features_data]
                    
                for feature in features_data:
                    results[feature["FeatureName"]] = (feature["State"] == "Enabled")
            except json.JSONDecodeError:
                # No results or invalid JSON
                pass
    except Exception:
        # Error running command, features assumed not installed
        pass
    
    # Set default value for features not found
    for feature in feature_names:
        if feature not in results:
            results[feature] = False
    
    return results

def _create_remote_command(command, target_system, credentials):
    """
    Create a command for remote execution via WinRM/PowerShell.
    
    Args:
        command (list): Local command to convert for remote execution
        target_system (str): Target system hostname or IP
        credentials (dict): Authentication details for remote access
        
    Returns:
        list: Command modified for remote execution
    """
    # Convert command list to string
    cmd_str = ' '.join(command)
    
    # Create remote PowerShell command
    remote_cmd = [
        "powershell",
        "-Command",
        f"$secpass = ConvertTo-SecureString '{credentials.get('password', '')}' -AsPlainText -Force; " +
        f"$cred = New-Object System.Management.Automation.PSCredential('{credentials.get('username', '')}', $secpass); " +
        f"Invoke-Command -ComputerName {target_system} -Credential $cred -ScriptBlock {{ {cmd_str} }}"
    ]
    
    return remote_cmd
