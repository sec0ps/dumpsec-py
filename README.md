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
MIT License - Copyright (c) 2025 Red Cell Security, LLC
