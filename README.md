# DumpSec-Py: Windows Security Auditing Tool

## Overview  
**DumpSec-Py** is a modernized version of the classic DumpSec tool, designed to help security professionals and system administrators conduct thorough security audits on Windows systems. It performs detailed checks on system configuration, user rights, services, security policies, and more, and provides a variety of output formats for easy reporting.

---

## Key Features

### User Rights and Group Memberships Auditing
- Enumerates all local users and groups, as well as their memberships (including nested group memberships).
- Checks for errors when retrieving group members and provides a detailed breakdown.
- Adds descriptions for each user and group, making it easy to understand the audit results.
- Detects orphaned SIDs in ACLs and provides alerts for unresolved group memberships.

---

### Registry Permissions Audit
- Audits NTFS file and registry permissions, focusing on DACLs (Discretionary Access Control Lists).
- Detects unresolved SIDs and flags orphaned SIDs.
- Checks access rights to registry keys and assesses potential risks for excessive privileges.
- Includes descriptions of the audit policy settings values.
- **Includes autostart location audits**, highlighting potentially malicious persistence entries.

---

### File and Share Permissions
- Audits shared folders and their permissions, providing details about share names and their paths.
- Performs NTFS permissions checks on critical file system paths like `C:\Users`, `C:\Program Files`, and `C:\Windows\System32`.
- Detects vulnerabilities in file share configurations and access rights.
- **Flags writable shares, hidden admin shares, password-protected shares**, and ACL misconfigurations.

---

### Service and Task Audits
- Enumerates all installed services, their configuration, and running status.
- Detects unquoted service paths, writable service binaries, and unsigned executable binaries.
- Analyzes task schedules and triggers to detect hidden or abnormal scheduled tasks, with a focus on tasks with elevated privileges.
- Real-time service and task monitoring mode to detect new or modified services and scheduled tasks.
- Includes risk assessments for each service and task.
- **Detects hidden scheduled tasks, orphaned SID ownership**, and **anomalous task configurations**.

---

### Audit Policy and Local Security Policies
- Audits local security policies, including auditing settings for system events, logon events, object access, and more.
- Adds descriptions for each audit policy setting value, making it easier to understand the meaning and impact of each configuration.
- Includes policy settings for user rights assignments and password policies.
- Flags misconfigurations, such as overly permissive policies, in a clear and easy-to-read format.
- **Includes UAC misconfiguration checks**, flagging unsafe elevation policies.

---

### LSA Secrets and UAC Misconfigurations
- Detects potential misconfigurations in Local Security Authority (LSA) secrets.
- Flags known dangerous secrets **only if they have populated values** (e.g., `DefaultPassword`, `AutoAdminLogon`).
- Analyzes UAC (User Account Control) settings to ensure that they are appropriately configured to prevent privilege escalation.
- Includes the ability to audit kernel-mode services and drivers, ensuring that they are secure and signed, with checks for elevated privileges.

---

### Group Policy Enumeration
- Enumerates the group policy settings applied to the system, providing insights into system and network security configurations.
- Identifies and reports errors related to group policy settings to ensure proper configuration.
- Helps in tracking down any misconfigured policies that could lead to vulnerabilities.

---

### Real-Time Monitoring Mode (`--watch`)
- Provides a real-time monitoring feature, where the tool watches for changes to services, tasks, and other system configurations.
- Triggers alerts when services or scheduled tasks are modified or added, and logs these changes for further analysis.
- Useful for identifying unauthorized changes in critical system settings, providing immediate alerts for security monitoring.

---

### Risk Assessment Dashboard and Reporting
- A detailed risk summary dashboard that consolidates all identified risks and vulnerabilities across all audits.
- Provides a severity-based classification for each identified issue (e.g., low, medium, high risk).
- Exports risk findings alongside the system configuration details to easily assess the overall security posture of the system.
- Risk flags are **context-aware**, considering factors like user context, path sensitivity, signature status, and permission level.

---

### Multiple Report Formats
Supports multiple output formats for audit results, including:

- **Text**: Human-readable text output for quick reviews.  
- **JSON**: Structured, linearly formatted JSON output for integration with other tools or systems.  
- **PDF**: Professionally formatted PDF reports for sharing with clients or management.  
- **HTML**: Clean HTML reports with per-entry detail and summary sections.  
- **CSV**: Tabular CSV export for further analysis or importing into spreadsheets.

Option to export in all formats at once, ensuring flexibility in reporting and documentation.

---

### Audit Enhancements and Customizable Risk Evaluation
- Includes a **pluggable Risk Engine** that evaluates services, tasks, registry keys, file permissions, and more.
- Cross-references known exploit patterns and best practices to flag potential escalation paths or stealthy persistence.
- Uses a clear **linear format** across all output types for easy auditing, with one issue per entry.

---

### Additional Security Audits
- **Driver and Kernel-Mode Service Audits**: Detects unsigned or misconfigured drivers that could present security risks.
- **Task Trigger Schedule Analysis**: Reviews scheduled tasks for abnormal timing or privilege elevation.
- **Autostart Locations Audit**: Identifies autostart locations in the registry and startup folders.
- **Startup Folder Audits**: Flags suspicious items in per-user and system-wide startup folders.
- **Hidden Scheduled Tasks**: Detects tasks configured to run invisibly or under unusual triggers.
- **LSASS Access Check**: Detects if unprivileged accounts have dangerous access to LSASS.
- **Startup Path Hijack Detection**: Identifies writable directories in service/task executable paths.

---

## Usage

### Command Line Mode  
Use the `--output-format` option to specify the desired output format (e.g., txt, json, pdf, html, csv). Example:
```bash
python main.py --output-format pdf --output-file dumpsec_report --risk-level high
```

### Interactive Mode  
Run `python main.py` without any arguments to interactively select which audits to run. Choose output formats and customize the report content based on risk levels.

### Real-Time Monitoring Mode  
Use the `--watch` flag to monitor system changes in real-time:
```bash
python main.py --watch
