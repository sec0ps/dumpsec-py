# DumpSec-Py: Enhanced Windows Security Auditing Tool (Community Edition)

## Overview
DumpSec-Py is a Windows security auditing tool designed for security professionals, system administrators, and penetration testers. This enhanced version builds on the classic DumpSec functionality with modern security features supporting Windows 10/11 and Server 2019/2022 environments. The tool performs detailed security assessments across users, permissions, services, registry, policies, and more—providing actionable findings with risk-based prioritization.

## Key Features

### Core Security Auditing
- **User and Group Analysis**: Enumerate local/domain users, group memberships, and detect privileged account issues
- **NTFS and Registry Permissions**: Audit access controls on critical system components
- **Service and Task Security**: Analyze configurations for security weaknesses and persistence mechanisms
- **Local Security Policies**: Assess password policies, UAC settings, and other security controls

### Enhanced Security Features (New!)
- **Windows Event Log Analysis**: Detect suspicious login attempts, account changes, audit log tampering, and privilege escalation
- **PowerShell Security Assessment**: Audit execution policies, script block logging, transcription settings, and scan for suspicious scripts
- **Microsoft Defender Analysis**: Check real-time protection, exclusion policies, and ATP/EDR settings
- **Container & WSL Security**: Evaluate Windows Subsystem for Linux configurations and container isolation

### Cross-Platform Capabilities (New!)
- **Remote Scanning**: Audit Windows systems from non-Windows platforms via SSH
- **Parallel Processing**: Scan multiple systems simultaneously for efficient enterprise auditing
- **Secure Credential Handling**: Support for password and key-based authentication

### Improved Reporting & Analysis
- **Compliance Framework Mapping**: Automatically map findings to NIST, CIS, ISO27001, GDPR and HIPAA controls
- **Risk Assessment Dashboard**: Interactive severity-based classification of findings
- **Differential Reporting**: Compare scans over time to identify changes
- **Multiple Export Formats**: Generate reports in TXT, JSON, PDF, HTML and CSV formats

### User Experience Improvements (New!)
- **Interactive CLI Menu**: Simplified interface for running standard or advanced audits
- **Real-time Monitoring**: Detect changes to services, tasks, and security settings as they occur

## Examples of Detected Issues
- Unquoted service paths and writable directories enabling privilege escalation
- Weak PowerShell security controls that could allow malicious script execution
- Excessive administrative accounts and privilege assignments
- Disabled security features in Windows Defender/Microsoft Defender for Endpoint
- Suspicious login patterns and authentication attempts
- Misconfigured UAC settings reducing system security
- Insecure container configurations lacking proper isolation

## Usage Modes
- **CLI Mode**: Command-line operation with extensive options
- **Interactive Menu**: Guided selection of audit modules and options
- **GUI Mode**: Visual interface for security assessment and reporting
- **Watch Mode**: Real-time monitoring of system security changes

## Technical Requirements
- Python 3.7+
- Windows 10/11 or Server 2019/2022 (for local scanning)
- Administrative privileges (for complete results)
- PyQt5 (for GUI interface)
- Paramiko (for cross-platform scanning)

## Getting Started
```bash
# Install dependencies
pip install -r requirements.txt

# Run standard audit
python main.py

# Run advanced audit with all modules
python main.py --modules users,shares,registry,services,policy,domain,events,powershell,defender,containers

# Monitor for security changes
python main.py --watch

```
## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

**Purpose**: This script is part of the DumpSec-Py tool, which is designed to perform detailed security audits on Windows systems. It covers user rights, services, registry permissions, file/share permissions, group policy enumeration, risk assessments, and more.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)


> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
