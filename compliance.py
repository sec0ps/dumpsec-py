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
import json
import re
import os

# Load compliance frameworks definitions
COMPLIANCE_DATA = {
    "CIS": {
        "1": "Account Policies",
        "1.1": "Password Policy",
        "1.1.1": "Ensure 'Enforce password history' is set to '24 or more passwords'",
        "1.1.2": "Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'",
        # ... many more CIS controls
        "5.2": "Configure System Services",
        "5.3": "Ensure default service accounts have strong passwords",
        "13.6": "Ensure permissions on sensitive filesystem resources are properly restricted",
        "16.9": "Ensure expired user accounts are disabled",
        "2.3.17": "User Account Control"
    },
    "NIST": {
        "AC-2": "Account Management",
        "AC-3": "Access Enforcement",
        "AC-6": "Least Privilege",
        "CM-6": "Configuration Settings",
        "CM-7": "Least Functionality",
        "AU-12": "Audit Generation",
        # ... many more NIST controls
    },
    "ISO27001": {
        "A.9.2.3": "Management of privileged access rights",
        "A.9.4.1": "Information access restriction",
        "A.9.4.4": "Use of privileged utility programs",
        "A.12.5.1": "Installation of software on operational systems",
        "A.12.6.1": "Management of technical vulnerabilities",
        "A.9.2.6": "Removal or adjustment of access rights"
        # ... many more ISO controls
    },
    "GDPR": {
        "Article 5": "Principles relating to processing of personal data",
        "Article 25": "Data protection by design and by default",
        "Article 32": "Security of processing"
        # ... many more GDPR articles
    },
    "HIPAA": {
        "164.308(a)(1)(i)": "Security Management Process",
        "164.308(a)(3)": "Workforce Security",
        "164.308(a)(5)": "Security Awareness and Training",
        "164.312(a)(1)": "Access Control",
        "164.312(c)(1)": "Integrity Controls"
        # ... many more HIPAA rules
    }
}

def load_risk_to_compliance_mapping():
    """Load mapping from risk categories to compliance controls."""
    return {
        "Unquoted Service Path": {
            "CIS": ["5.2"],
            "NIST": ["CM-6", "CM-7"],
            "ISO27001": ["A.12.5.1"]
        },
        "Writable Service Binary": {
            "CIS": ["5.2", "5.3"],
            "NIST": ["CM-6", "CM-7"],
            "ISO27001": ["A.12.5.1"]
        },
        "High Privilege Token Service": {
            "CIS": ["5.2"],
            "NIST": ["AC-6", "CM-7"],
            "ISO27001": ["A.9.2.3"]
        },
        "Overly Permissive ACL": {
            "CIS": ["5.1", "13.6"],
            "NIST": ["AC-3", "AC-6"],
            "ISO27001": ["A.9.2.3", "A.9.4.1"],
            "GDPR": ["Article 25", "Article 32"]
        },
        "Orphaned SID": {
            "CIS": ["16.9"],
            "NIST": ["AC-2"],
            "ISO27001": ["A.9.2.6"]
        },
        "UAC Misconfiguration": {
            "CIS": ["2.3.17"],
            "NIST": ["AC-6", "CM-6"],
            "ISO27001": ["A.9.4.4"]
        },
        "PowerShell Security": {
            "CIS": ["5.8"],
            "NIST": ["CM-7", "AU-12"],
            "ISO27001": ["A.12.6.1"]
        },
        "Defender ATP": {
            "CIS": ["1.7", "8.1"],
            "NIST": ["SI-3", "SI-4"],
            "ISO27001": ["A.12.2.1"]
        },
        "Weak Authentication": {
            "CIS": ["1.1.1", "1.1.2"],
            "NIST": ["IA-5"],
            "ISO27001": ["A.9.4.3"],
            "GDPR": ["Article 32"],
            "HIPAA": ["164.308(a)(5)"]
        },
        "Container Security": {
            "CIS": ["5.29"],
            "NIST": ["CM-7", "SC-7"],
            "ISO27001": ["A.13.1.3"]
        }
        # Add more risk categories and their compliance mappings
    }

def map_to_compliance_frameworks(risks):
    """Map findings to compliance frameworks."""
    compliance_map = {
        "CIS": {},
        "NIST": {},
        "ISO27001": {},
        "GDPR": {},
        "HIPAA": {}
    }
    
    # Load risk to compliance mapping
    mapping = load_risk_to_compliance_mapping()
    
    for risk in risks:
        category = risk.get("category")
        if category in mapping:
            for framework, controls in mapping[category].items():
                for control in controls:
                    if control not in compliance_map[framework]:
                        compliance_map[framework][control] = []
                    compliance_map[framework][control].append(risk)
    
    return compliance_map

def generate_compliance_report(compliance_map):
    """Generate a structured compliance report."""
    report = {}
    
    for framework, controls in compliance_map.items():
        if not controls:
            continue
            
        framework_report = {
            "name": framework,
            "controls": {},
            "coverage": {
                "total_controls": len(COMPLIANCE_DATA.get(framework, {})),
                "controls_with_findings": len(controls),
                "high_risk_controls": 0,
                "medium_risk_controls": 0,
                "low_risk_controls": 0
            }
        }
        
        for control_id, findings in controls.items():
            control_name = COMPLIANCE_DATA.get(framework, {}).get(control_id, "Unknown Control")
            
            # Determine highest risk in this control
            highest_risk = "low"
            for finding in findings:
                severity = finding.get("severity", "").lower()
                if severity == "high":
                    highest_risk = "high"
                    framework_report["coverage"]["high_risk_controls"] += 1
                    break
                elif severity == "medium" and highest_risk != "high":
                    highest_risk = "medium"
            
            if highest_risk == "medium":
                framework_report["coverage"]["medium_risk_controls"] += 1
            elif highest_risk == "low":
                framework_report["coverage"]["low_risk_controls"] += 1
            
            framework_report["controls"][control_id] = {
                "name": control_name,
                "highest_risk": highest_risk,
                "findings": findings
            }
        
        report[framework] = framework_report
    
    return report

def run(risks):
    """Run the compliance mapping and generate a report."""
    compliance_map = map_to_compliance_frameworks(risks)
    report = generate_compliance_report(compliance_map)
    return report
