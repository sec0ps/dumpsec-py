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
# Purpose: Remote scanner module for DumpSec-Py. Provides functionality to scan
#          remote Windows systems from any platform with Python and SSH.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#
# =============================================================================

import paramiko
import json
import tempfile
import os
import socket
import threading
import queue
import time
from datetime import datetime

class RemoteWindowsScanner:
    def __init__(self, hostname, username=None, password=None, key_file=None, port=22, timeout=10):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.ssh = None
        self.scan_results = {}
        self.remote_script_dir = None
    
    def connect(self):
        """Establish SSH connection to the remote Windows host."""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.key_file:
                self.ssh.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=self.timeout
                )
            else:
                self.ssh.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                )
                
            # Create a random temporary directory name
            temp_dir = f"dumpsec_audit_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            stdin, stdout, stderr = self.ssh.exec_command(f'powershell -command "New-Item -ItemType Directory -Path $env:TEMP\\{temp_dir} -Force | Select-Object -ExpandProperty FullName"')
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                raise Exception(f"Failed to create temporary directory: {stderr.read().decode()}")
                
            self.remote_script_dir = stdout.read().decode().strip()
            return True
        except Exception as e:
            self.scan_results["Connection Error"] = str(e)
            return False
    
    def upload_audit_scripts(self):
        """Upload audit scripts to the remote system."""
        try:
            sftp = self.ssh.open_sftp()
            
            # List of scripts to upload
            scripts = {
                "remote_audit.py": """
import os
import platform
import json
import subprocess
import ctypes
import socket
import datetime

def get_system_info():
    info = {}
    info['hostname'] = socket.gethostname()
    info['windows_version'] = platform.platform()
    info['processor'] = platform.processor()
    info['python_version'] = platform.python_version()
    return info

def check_installed_software():
    software = []
    try:
        output = subprocess.run(['powershell', '-Command', 
                                'Get-ItemProperty HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            software = json.loads(output.stdout)
    except Exception as e:
        software.append({'Error': str(e)})
    return software

def check_windows_firewall():
    firewall = {}
    try:
        output = subprocess.run(['powershell', '-Command', 
                                'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            firewall['profiles'] = json.loads(output.stdout)
            
        # Get firewall rules
        output = subprocess.run(['powershell', '-Command', 
                                'Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True" -and $_.Direction -eq "Inbound"} | Select-Object -First 20 DisplayName,Enabled,Profile,Action | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            firewall['inbound_rules'] = json.loads(output.stdout)
    except Exception as e:
        firewall['error'] = str(e)
    return firewall

def check_running_services():
    services = []
    try:
        output = subprocess.run(['powershell', '-Command', 
                                'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name,DisplayName,StartType | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            services = json.loads(output.stdout)
    except Exception as e:
        services.append({'Error': str(e)})
    return services

def check_user_accounts():
    accounts = []
    try:
        output = subprocess.run(['powershell', '-Command',
                                'Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordExpires,LastLogon,SID | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            accounts = json.loads(output.stdout)
    except Exception as e:
        accounts.append({'Error': str(e)})
    return accounts

def check_admin_accounts():
    admins = []
    try:
        output = subprocess.run(['powershell', '-Command',
                                'Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            admins = json.loads(output.stdout)
    except Exception as e:
        admins.append({'Error': str(e)})
    return admins

def check_shared_folders():
    shares = []
    try:
        output = subprocess.run(['powershell', '-Command',
                                'Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            shares = json.loads(output.stdout)
    except Exception as e:
        shares.append({'Error': str(e)})
    return shares

def check_scheduled_tasks():
    tasks = []
    try:
        output = subprocess.run(['powershell', '-Command',
                                'Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            tasks = json.loads(output.stdout)
    except Exception as e:
        tasks.append({'Error': str(e)})
    return tasks

def check_windows_defender():
    defender = {}
    try:
        # Check if Defender is enabled
        output = subprocess.run(['powershell', '-Command',
                                'Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,IoavProtectionEnabled | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            defender['status'] = json.loads(output.stdout)
        
        # Check exclusions
        output = subprocess.run(['powershell', '-Command',
                                'Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            defender['exclusions'] = json.loads(output.stdout)
    except Exception as e:
        defender['error'] = str(e)
    return defender

def check_powershell_settings():
    powershell = {}
    try:
        # Get PowerShell version
        output = subprocess.run(['powershell', '-Command',
                                '$PSVersionTable | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            powershell['version'] = json.loads(output.stdout)
        
        # Get execution policy
        output = subprocess.run(['powershell', '-Command',
                                'Get-ExecutionPolicy -List | ConvertTo-Json -Compress'],
                                capture_output=True, text=True)
        if output.returncode == 0:
            powershell['execution_policy'] = json.loads(output.stdout)
    except Exception as e:
        powershell['error'] = str(e)
    return powershell

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def main():
    results = {
        'timestamp': datetime.datetime.now().isoformat(),
        'is_admin': is_admin(),
        'system_info': get_system_info(),
        'installed_software': check_installed_software(),
        'firewall': check_windows_firewall(),
        'running_services': check_running_services(),
        'user_accounts': check_user_accounts(),
        'admin_accounts': check_admin_accounts(),
        'shared_folders': check_shared_folders(),
        'scheduled_tasks': check_scheduled_tasks(),
        'windows_defender': check_windows_defender(),
        'powershell': check_powershell_settings()
    }
    
    with open('audit_results.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
""",
                "analyzer.py": """
import json
import os
import sys

def analyze_results(results):
    risks = []
    
    # Check admin accounts
    admin_accounts = results.get('admin_accounts', [])
    if len(admin_accounts) > 2:  # More than Administrator and a managed admin account
        risks.append({
            'severity': 'high',
            'category': 'Excessive Admin Accounts',
            'description': f'Found {len(admin_accounts)} administrative accounts'
        })
    
    # Check firewall
    firewall = results.get('firewall', {})
    profiles = firewall.get('profiles', [])
    
    for profile in profiles:
        if not profile.get('Enabled', True):
            risks.append({
                'severity': 'high',
                'category': 'Firewall Disabled',
                'description': f'Firewall profile {profile.get("Name", "Unknown")} is disabled'
            })
    
    # Check user accounts
    user_accounts = results.get('user_accounts', [])
    for user in user_accounts:
        if user.get('Enabled', False) and not user.get('PasswordRequired', True):
            risks.append({
                'severity': 'high',
                'category': 'Weak Authentication',
                'description': f'User {user.get("Name", "Unknown")} has no password requirement'
            })
    
    # Check services
    services = results.get('running_services', [])
    for service in services:
        name = service.get('Name', '').lower()
        if 'remote' in name or 'telnet' in name or 'ftp' in name:
            risks.append({
                'severity': 'medium',
                'category': 'Insecure Services',
                'description': f'Potentially insecure service running: {service.get("DisplayName", name)}'
            })
    
    # Check shared folders
    shares = results.get('shared_folders', [])
    for share in shares:
        if share.get('Name', '').endswith('$'):
            continue  # Skip administrative shares
        
        risks.append({
            'severity': 'medium',
            'category': 'Data Exposure',
            'description': f'Non-administrative share: {share.get("Name", "Unknown")} at {share.get("Path", "Unknown")}'
        })
    
    # Check Windows Defender
    defender = results.get('windows_defender', {})
    status = defender.get('status', {})
    
    if not status.get('RealTimeProtectionEnabled', True):
        risks.append({
            'severity': 'high',
            'category': 'Antivirus Protection',
            'description': 'Windows Defender real-time protection is disabled'
        })
    
    # Check PowerShell execution policy
    powershell = results.get('powershell', {})
    execution_policy = powershell.get('execution_policy', [])
    
    for policy in execution_policy:
        if isinstance(policy, dict) and policy.get('ExecutionPolicy') in ['Unrestricted', 'Bypass']:
            risks.append({
                'severity': 'high',
                'category': 'PowerShell Security',
                'description': f'PowerShell execution policy {policy.get("ExecutionPolicy")} at scope {policy.get("Scope")} allows unsigned scripts'
            })
    
    return {
        'system_info': results.get('system_info', {}),
        'is_admin': results.get('is_admin', False),
        'risks': risks,
        'risk_count': len(risks),
        'risk_severity': {
            'high': len([r for r in risks if r.get('severity') == 'high']),
            'medium': len([r for r in risks if r.get('severity') == 'medium']),
            'low': len([r for r in risks if r.get('severity') == 'low'])
        }
    }

def main():
    if not os.path.exists('audit_results.json'):
        print('No audit results file found')
        sys.exit(1)
    
    with open('audit_results.json', 'r') as f:
        results = json.load(f)
    
    analysis = analyze_results(results)
    
    with open('analysis_results.json', 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f'Analysis complete. Found {len(analysis["risks"])} risks.')

if __name__ == '__main__':
    main()
"""
            }
            
            for script_name, script_content in scripts.items():
                script_path = os.path.join(self.remote_script_dir, script_name)
                with sftp.open(script_path, 'w') as f:
                    f.write(script_content.strip())
            
            sftp.close()
            return True
        except Exception as e:
            self.scan_results["Script Upload Error"] = str(e)
            return False
    
    def run_remote_audit(self):
        """Execute the audit script on the remote system."""
        try:
            # Run the audit script
            stdin, stdout, stderr = self.ssh.exec_command(f'cd {self.remote_script_dir} && python remote_audit.py')
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                raise Exception(f"Audit script failed: {stderr.read().decode()}")
            
            # Run the analyzer
            stdin, stdout, stderr = self.ssh.exec_command(f'cd {self.remote_script_dir} && python analyzer.py')
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                raise Exception(f"Analysis script failed: {stderr.read().decode()}")
            
            # Download results
            sftp = self.ssh.open_sftp()
            
            # Get the raw audit data
            remote_path = os.path.join(self.remote_script_dir, 'audit_results.json')
            with sftp.open(remote_path, 'r') as f:
                self.scan_results['raw_data'] = json.load(f)
            
            # Get the analysis results
            remote_path = os.path.join(self.remote_script_dir, 'analysis_results.json')
            with sftp.open(remote_path, 'r') as f:
                self.scan_results['analysis'] = json.load(f)
            
            sftp.close()
            return True
        except Exception as e:
            self.scan_results["Audit Execution Error"] = str(e)
            return False
    
    def cleanup(self):
        """Clean up temporary files on the remote system."""
        if self.ssh and self.remote_script_dir:
            try:
                self.ssh.exec_command(f'powershell -command "Remove-Item -Path \"{self.remote_script_dir}\" -Recurse -Force"')
            except:
                pass  # Ignore cleanup errors
        
        if self.ssh:
            self.ssh.close()
    
    def scan(self):
        """Perform a complete scan of the remote Windows system."""
        try:
            if not self.connect():
                return self.scan_results
            
            if not self.upload_audit_scripts():
                self.cleanup()
                return self.scan_results
            
            if not self.run_remote_audit():
                self.cleanup()
                return self.scan_results
            
            self.cleanup()
            return self.scan_results
        except Exception as e:
            self.scan_results["Scan Error"] = str(e)
            self.cleanup()
            return self.scan_results

def scan_multiple_hosts(hosts, username, password=None, key_file=None, max_threads=5):
    """Scan multiple Windows hosts in parallel."""
    results = {}
    threads = []
    result_queue = queue.Queue()
    
    def worker(host):
        scanner = RemoteWindowsScanner(host, username, password, key_file)
        host_results = scanner.scan()
        result_queue.put((host, host_results))
    
    # Start worker threads
    for host in hosts:
        if len(threads) >= max_threads:
            # Wait for a thread to complete
            for t in threads:
                if not t.is_alive():
                    threads.remove(t)
                    break
            if len(threads) >= max_threads:
                time.sleep(1)
                continue
        
        t = threading.Thread(target=worker, args=(host,))
        t.start()
        threads.append(t)
    
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Collect results
    while not result_queue.empty():
        host, host_results = result_queue.get()
        results[host] = host_results
    
    return results

def remote_mode(args):
    """Command-line interface for remote scanning mode."""
    if not args.hosts:
        print("[!] No hosts specified. Use --hosts option.")
        return
    
    # Get hosts list
    if os.path.exists(args.hosts):
        with open(args.hosts, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        hosts = [h.strip() for h in args.hosts.split(',') if h.strip()]
    
    if not hosts:
        print("[!] No valid hosts found.")
        return
    
    # Get credentials
    username = args.username
    if not username:
        username = input("Enter username for remote authentication: ")
    
    password = None
    key_file = args.key_file
    
    if not key_file:
        import getpass
        password = getpass.getpass("Enter password (leave empty to use SSH key): ")
        if not password:
            key_file = input("Enter path to SSH private key: ")
    
    print(f"[*] Scanning {len(hosts)} remote hosts with {args.max_threads} parallel threads")
    results = scan_multiple_hosts(hosts, username, password, key_file, args.max_threads)
    
    # Save results
    output_file = args.output_file or f"remote_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    with open(f"{output_file}.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Remote scan results saved as {output_file}.json")
    
    # Print summary
    print("\nScan summary:")
    for host, result in results.items():
        if "analysis" in result and "risks" in result["analysis"]:
            risks = result["analysis"]["risks"]
            high = sum(1 for r in risks if r.get("severity") == "high")
            medium = sum(1 for r in risks if r.get("severity") == "medium")
            low = sum(1 for r in risks if r.get("severity") == "low")
            print(f"  - {host}: {len(risks)} findings (High: {high}, Medium: {medium}, Low: {low})")
        else:
            print(f"  - {host}: Scan failed or no findings")

if __name__ == "__main__":
    # If run directly, parse arguments and execute scan
    import argparse
    
    parser = argparse.ArgumentParser(description="DumpSec-Py Remote Scanner")
    parser.add_argument("--hosts", required=True, help="List of hosts to scan (comma-separated or file)")
    parser.add_argument("--username", required=True, help="Username for remote authentication")
    parser.add_argument("--key-file", help="SSH private key for remote authentication")
    parser.add_argument("--max-threads", type=int, default=5, help="Maximum parallel scans")
    parser.add_argument("--output-file", help="Output filename (without extension)")
    
    args = parser.parse_args()
    remote_mode(args)
