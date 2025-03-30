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
import os
import csv
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

def filter_risks(data, min_risk):
    if not min_risk:
        return data
    filtered = {}
    threshold = SEVERITY_ORDER[min_risk]
    for section, content in data.items():
        if isinstance(content, dict) and "_risks" in content:
            content["_risks"] = [r for r in content["_risks"] if SEVERITY_ORDER[r['severity'].lower()] >= threshold]
        filtered[section] = content
    return filtered

def write_report(data, output_format, filename, min_risk=None):
    data = filter_risks(data, min_risk)

    formats = []
    if output_format == "all":
        formats = ["txt", "json", "pdf", "html", "csv"]
    else:
        formats = [output_format]

    for fmt in formats:
        try:
            if fmt == "txt":
                write_txt(data, filename + ".txt")
            elif fmt == "json":
                write_json(data, filename + ".json")
            elif fmt == "pdf":
                write_pdf(data, filename + ".pdf")
            elif fmt == "html":
                write_html(data, filename + ".html")
            elif fmt == "csv":
                write_csv(data, filename + ".csv")
            else:
                print(f"[!] Unsupported format: {fmt}")
        except Exception as e:
            print(f"[!] Failed to write {fmt.upper()} report: {e}")
    
def compare_reports(old_report_path, new_report_path):
    """Compare two previous reports and generate a differential report."""
    try:
        with open(old_report_path, 'r') as f:
            old_data = json.load(f)
        
        with open(new_report_path, 'r') as f:
            new_data = json.load(f)
        
        differences = {
            "added": {},
            "removed": {},
            "modified": {}
        }
        
        # Compare sections
        all_sections = set(list(old_data.keys()) + list(new_data.keys()))
        
        for section in all_sections:
            # Section in new but not old
            if section not in old_data and section in new_data:
                differences["added"][section] = new_data[section]
                continue
                
            # Section in old but not new
            if section in old_data and section not in new_data:
                differences["removed"][section] = old_data[section]
                continue
                
            # Compare content within sections
            if isinstance(old_data[section], dict) and isinstance(new_data[section], dict):
                section_diff = {}
                old_section = old_data[section]
                new_section = new_data[section]
                
                # Find keys in new but not in old
                for key in new_section:
                    if key not in old_section:
                        if "added" not in section_diff:
                            section_diff["added"] = {}
                        section_diff["added"][key] = new_section[key]
                
                # Find keys in old but not in new
                for key in old_section:
                    if key not in new_section:
                        if "removed" not in section_diff:
                            section_diff["removed"] = {}
                        section_diff["removed"][key] = old_section[key]
                
                # Compare values for common keys
                for key in set(old_section.keys()) & set(new_section.keys()):
                    if old_section[key] != new_section[key]:
                        if "modified" not in section_diff:
                            section_diff["modified"] = {}
                        section_diff["modified"][key] = {
                            "old": old_section[key],
                            "new": new_section[key]
                        }
                
                if section_diff:
                    differences["modified"][section] = section_diff
        
        return differences
    except Exception as e:
        return {"error": str(e)}

def write_txt(data, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            for section, content in data.items():
                if section == "_risks":
                    continue
                f.write(f"=== {section} ===\n")

                if isinstance(content, dict):
                    for key, value in content.items():
                        if key == "_risks":
                            continue
                        f.write(f"{key}:\n")
                        if isinstance(value, list):
                            for item in value:
                                f.write(f"  - {item}\n")
                        elif isinstance(value, dict):
                            for subkey, subval in value.items():
                                f.write(f"  {subkey}:\n")
                                if isinstance(subval, list):
                                    if subval:
                                        for subitem in subval:
                                            f.write(f"    - {subitem}\n")
                                    else:
                                        f.write("    (no members)\n")
                                elif isinstance(subval, str):
                                    f.write(f"    {subval}\n")
                                else:
                                    f.write(f"    (unsupported type: {type(subval)})\n")
                        elif isinstance(value, str):
                            f.write(f"  {value}\n")
                        else:
                            f.write(f"  (unsupported type: {type(value)})\n")

                    # Add risk findings if present
                    if "_risks" in content and content["_risks"]:
                        f.write("!! Risk Findings:\n")
                        for risk in content["_risks"]:
                            f.write(f"  [{risk['severity']}] {risk['category']}: {risk['description']}\n")

                elif isinstance(content, list):
                    for item in content:
                        f.write(f"  - {item}\n")
                elif isinstance(content, str):
                    f.write(f"{content}\n")
                else:
                    f.write(f"(unsupported section type: {type(content)})\n")

                f.write("\n")
    except Exception as e:
        print(f"[!] Failed to write TXT: {e}")

def write_json(data, path):
    try:
        flattened = {}

        for section, content in data.items():
            if section == "_risks":
                continue

            flat_section = {}

            if isinstance(content, dict):
                for key, value in content.items():
                    if key == "_risks":
                        continue
                    if isinstance(value, list):
                        flat_section[key] = value
                    elif isinstance(value, dict):
                        flat_section[key] = {k: v for k, v in value.items()}
                    else:
                        flat_section[key] = value

                if "_risks" in content and content["_risks"]:
                    flat_section["Risk Findings"] = [
                        {
                            "Severity": r["severity"],
                            "Category": r["category"],
                            "Description": r["description"]
                        } for r in content["_risks"]
                    ]
            elif isinstance(content, list):
                flat_section["Entries"] = content
            else:
                flat_section["Value"] = str(content)

            flattened[section] = flat_section

        with open(path, "w", encoding="utf-8") as f:
            json.dump(flattened, f, indent=4)

    except Exception as e:
        print(f"[!] Failed to write JSON: {e}")

def write_pdf(data, path):
    """Write report in PDF format."""
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    try:
        doc = SimpleDocTemplate(
            path,
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, leading=18, spaceAfter=10, spaceBefore=20, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='SubHeader', fontSize=12, leading=16, spaceAfter=8, spaceBefore=10, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='Content', fontSize=10.5, leading=14, alignment=TA_LEFT))
        styles.add(ParagraphStyle(name='Risk-High', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.red))
        styles.add(ParagraphStyle(name='Risk-Medium', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.orange))
        styles.add(ParagraphStyle(name='Risk-Low', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.blue))

        elements = []
        elements.append(Paragraph("DumpSec-Py Security Audit Report", styles["Title"]))
        elements.append(Spacer(1, 0.25 * inch))

        # Process each section
        for section, content in data.items():
            if section.startswith("_"):
                continue  # Skip internal sections
                
            elements.append(Paragraph(section, styles["SectionHeader"]))
            
            # Special handling for Compliance Mapping
            if section == "Compliance Mapping" and isinstance(content, dict):
                for framework, framework_data in content.items():
                    if framework == "_risks":
                        continue
                        
                    elements.append(Paragraph(framework, styles["SubHeader"]))
                    
                    # Display framework coverage information
                    if isinstance(framework_data, dict) and "coverage" in framework_data:
                        coverage = framework_data["coverage"]
                        elements.append(Paragraph("Coverage Information:", styles["Content"]))
                        
                        coverage_data = [
                            ["Metric", "Value"],
                            ["Total Controls", str(coverage.get('total_controls', 0))],
                            ["Controls with Findings", str(coverage.get('controls_with_findings', 0))],
                            ["High Risk Controls", str(coverage.get('high_risk_controls', 0))],
                            ["Medium Risk Controls", str(coverage.get('medium_risk_controls', 0))],
                            ["Low Risk Controls", str(coverage.get('low_risk_controls', 0))]
                        ]
                        
                        t = Table(coverage_data, colWidths=[2*inch, 1*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (1, 0), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                            ('BACKGROUND', (0, 3), (0, 3), colors.pink),
                            ('BACKGROUND', (0, 4), (0, 4), colors.lightorange),
                            ('BACKGROUND', (0, 5), (0, 5), colors.lightblue),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 0.2 * inch))
                    
                    # Display individual controls with findings
                    if isinstance(framework_data, dict) and "controls" in framework_data:
                        controls = framework_data["controls"]
                        elements.append(Paragraph("Control Findings:", styles["Content"]))
                        
                        for control_id, control_data in controls.items():
                            highest_risk = control_data.get('highest_risk', 'low')
                            style = styles["Risk-High"] if highest_risk == "high" else \
                                    styles["Risk-Medium"] if highest_risk == "medium" else \
                                    styles["Risk-Low"]
                            
                            elements.append(Paragraph(
                                f"{control_id}: {control_data.get('name', 'Unknown Control')}",
                                style
                            ))
                            
                            # List findings for this control
                            findings = control_data.get("findings", [])
                            if findings:
                                for finding in findings:
                                    severity = finding.get("severity", "").lower()
                                    style = styles["Risk-High"] if severity == "high" else \
                                            styles["Risk-Medium"] if severity == "medium" else \
                                            styles["Risk-Low"]
                                    
                                    elements.append(Paragraph(
                                        f"• {finding.get('description', 'No description')}",
                                        style
                                    ))
                            
                            elements.append(Spacer(1, 0.1 * inch))
            
            # Special handling for Windows Event Logs
            elif section == "Windows Event Logs" and isinstance(content, dict) and "Recent Events" in content:
                # Process other content first
                for key, value in content.items():
                    if key == "Recent Events" or key == "_risks":
                        continue
                    
                    elements.append(Paragraph(key, styles["SubHeader"]))
                    
                    if isinstance(value, dict):
                        for subkey, subval in value.items():
                            elements.append(Paragraph(f"{subkey}: {subval}", styles["Content"]))
                    elif isinstance(value, list):
                        for item in value:
                            elements.append(Paragraph(f"• {item}", styles["Content"]))
                    else:
                        elements.append(Paragraph(f"{value}", styles["Content"]))
                    
                    elements.append(Spacer(1, 0.1 * inch))
                
                # Format recent events in a table
                recent_events = content.get("Recent Events", [])
                if recent_events and isinstance(recent_events, list) and len(recent_events) > 0:
                    elements.append(Paragraph("Recent Events", styles["SubHeader"]))
                    
                    if isinstance(recent_events[0], dict):
                        # Create table headers
                        table_data = [["Time", "Event ID", "Description"]]
                        
                        # Add rows for each event (limit to 20 events to avoid huge PDFs)
                        for event in recent_events[:20]:
                            table_data.append([
                                event.get('Time', ''),
                                str(event.get('EventID', '')),
                                event.get('Description', '')
                            ])
                        
                        # Create and style the table
                        t = Table(table_data, colWidths=[1.5*inch, 0.75*inch, 3.5*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 0.2 * inch))
                        
                        # Add note about event details
                        elements.append(Paragraph(
                            "Note: Detailed event data is available in the HTML report format for better readability.",
                            styles["Content"]
                        ))
                
                # Add risk findings
                if "_risks" in content and content["_risks"]:
                    elements.append(Paragraph("Risk Findings", styles["SubHeader"]))
                    for risk in content["_risks"]:
                        severity = risk.get("severity", "").lower()
                        style = styles["Risk-High"] if severity == "high" else \
                                styles["Risk-Medium"] if severity == "medium" else \
                                styles["Risk-Low"]
                        
                        elements.append(Paragraph(
                            f"[{risk['severity']}] {risk['category']}: {risk['description']}",
                            style
                        ))
            
            # Standard processing for other sections
            else:
                if isinstance(content, dict):
                    for key, value in content.items():
                        if key == "_risks":
                            continue
                            
                        elements.append(Paragraph(key, styles["SubHeader"]))
                        
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict):
                                    item_text = ", ".join([f"{k}: {v}" for k, v in item.items()])
                                    elements.append(Paragraph(f"• {item_text}", styles["Content"]))
                                else:
                                    elements.append(Paragraph(f"• {str(item)}", styles["Content"]))
                        elif isinstance(value, dict):
                            for subkey, subval in value.items():
                                if isinstance(subval, list):
                                    elements.append(Paragraph(f"{subkey}:", styles["Content"]))
                                    for item in subval:
                                        elements.append(Paragraph(f"    • {item}", styles["Content"]))
                                else:
                                    elements.append(Paragraph(f"{subkey}: {subval}", styles["Content"]))
                        else:
                            elements.append(Paragraph(f"{value}", styles["Content"]))
                            
                        elements.append(Spacer(1, 0.1 * inch))
                    
                    # Add risk findings
                    if "_risks" in content and content["_risks"]:
                        elements.append(Paragraph("Risk Findings", styles["SubHeader"]))
                        for risk in content["_risks"]:
                            severity = risk.get("severity", "").lower()
                            style = styles["Risk-High"] if severity == "high" else \
                                   styles["Risk-Medium"] if severity == "medium" else \
                                   styles["Risk-Low"]
                            
                            elements.append(Paragraph(
                                f"[{risk['severity']}] {risk['category']}: {risk['description']}",
                                style
                            ))
                
                elif isinstance(content, list):
                    for item in content:
                        elements.append(Paragraph(f"• {str(item)}", styles["Content"]))
                else:
                    elements.append(Paragraph(str(content), styles["Content"]))
                
                elements.append(Spacer(1, 0.2 * inch))

        doc.build(elements)
    except Exception as e:
        print(f"[!] Failed to write PDF: {e}")

def write_pdf(data, path):
    """Write report in PDF format."""
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib.units import inch
    from reportlab.lib import colors

    try:
        doc = SimpleDocTemplate(
            path,
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, leading=18, spaceAfter=10, spaceBefore=20, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='SubHeader', fontSize=12, leading=16, spaceAfter=8, spaceBefore=10, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='Content', fontSize=10.5, leading=14, alignment=TA_LEFT))
        styles.add(ParagraphStyle(name='Risk-High', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.red))
        styles.add(ParagraphStyle(name='Risk-Medium', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.orange))
        styles.add(ParagraphStyle(name='Risk-Low', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor=colors.blue))

        elements = []
        elements.append(Paragraph("DumpSec-Py Security Audit Report", styles["Title"]))
        elements.append(Spacer(1, 0.25 * inch))

        # Process each section
        for section, content in data.items():
            if section.startswith("_"):
                continue  # Skip internal sections
                
            elements.append(Paragraph(section, styles["SectionHeader"]))
            
            # Special handling for Compliance Mapping
            if section == "Compliance Mapping" and isinstance(content, dict):
                for framework, framework_data in content.items():
                    if framework == "_risks":
                        continue
                        
                    elements.append(Paragraph(framework, styles["SubHeader"]))
                    
                    # Display framework coverage information
                    if isinstance(framework_data, dict) and "coverage" in framework_data:
                        coverage = framework_data["coverage"]
                        elements.append(Paragraph("Coverage Information:", styles["Content"]))
                        
                        coverage_data = [
                            ["Metric", "Value"],
                            ["Total Controls", str(coverage.get('total_controls', 0))],
                            ["Controls with Findings", str(coverage.get('controls_with_findings', 0))],
                            ["High Risk Controls", str(coverage.get('high_risk_controls', 0))],
                            ["Medium Risk Controls", str(coverage.get('medium_risk_controls', 0))],
                            ["Low Risk Controls", str(coverage.get('low_risk_controls', 0))]
                        ]
                        
                        t = Table(coverage_data, colWidths=[2*inch, 1*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (1, 0), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                            ('BACKGROUND', (0, 3), (0, 3), colors.pink),
                            ('BACKGROUND', (0, 4), (0, 4), colors.orange), # Changed from lightorange to orange
                            ('BACKGROUND', (0, 5), (0, 5), colors.lightblue),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 0.2 * inch))
                    
                    # Display individual controls with findings
                    if isinstance(framework_data, dict) and "controls" in framework_data:
                        controls = framework_data["controls"]
                        elements.append(Paragraph("Control Findings:", styles["Content"]))
                        
                        for control_id, control_data in controls.items():
                            highest_risk = control_data.get('highest_risk', 'low')
                            style = styles["Risk-High"] if highest_risk == "high" else \
                                    styles["Risk-Medium"] if highest_risk == "medium" else \
                                    styles["Risk-Low"]
                            
                            elements.append(Paragraph(
                                f"{control_id}: {control_data.get('name', 'Unknown Control')}",
                                style
                            ))
                            
                            # List findings for this control
                            findings = control_data.get("findings", [])
                            if findings:
                                for finding in findings:
                                    severity = finding.get("severity", "").lower()
                                    style = styles["Risk-High"] if severity == "high" else \
                                            styles["Risk-Medium"] if severity == "medium" else \
                                            styles["Risk-Low"]
                                    
                                    elements.append(Paragraph(
                                        f"• {finding.get('description', 'No description')}",
                                        style
                                    ))
                            
                            elements.append(Spacer(1, 0.1 * inch))
            
            # Special handling for Windows Event Logs
            elif section == "Windows Event Logs" and isinstance(content, dict) and "Recent Events" in content:
                # Process other content first
                for key, value in content.items():
                    if key == "Recent Events" or key == "_risks":
                        continue
                    
                    elements.append(Paragraph(key, styles["SubHeader"]))
                    
                    if isinstance(value, dict):
                        for subkey, subval in value.items():
                            elements.append(Paragraph(f"{subkey}: {subval}", styles["Content"]))
                    elif isinstance(value, list):
                        for item in value:
                            elements.append(Paragraph(f"• {item}", styles["Content"]))
                    else:
                        elements.append(Paragraph(f"{value}", styles["Content"]))
                    
                    elements.append(Spacer(1, 0.1 * inch))
                
                # Format recent events in a table
                recent_events = content.get("Recent Events", [])
                if recent_events and isinstance(recent_events, list) and len(recent_events) > 0:
                    elements.append(Paragraph("Recent Events", styles["SubHeader"]))
                    
                    if isinstance(recent_events[0], dict):
                        # Create table headers
                        table_data = [["Time", "Event ID", "Description"]]
                        
                        # Add rows for each event (limit to 20 events to avoid huge PDFs)
                        for event in recent_events[:20]:
                            table_data.append([
                                event.get('Time', ''),
                                str(event.get('EventID', '')),
                                event.get('Description', '')
                            ])
                        
                        # Create and style the table
                        t = Table(table_data, colWidths=[1.5*inch, 0.75*inch, 3.5*inch])
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ]))
                        elements.append(t)
                        elements.append(Spacer(1, 0.2 * inch))
                        
                        # Add note about event details
                        elements.append(Paragraph(
                            "Note: Detailed event data is available in the HTML report format for better readability.",
                            styles["Content"]
                        ))
                
                # Add risk findings
                if "_risks" in content and content["_risks"]:
                    elements.append(Paragraph("Risk Findings", styles["SubHeader"]))
                    for risk in content["_risks"]:
                        severity = risk.get("severity", "").lower()
                        style = styles["Risk-High"] if severity == "high" else \
                                styles["Risk-Medium"] if severity == "medium" else \
                                styles["Risk-Low"]
                        
                        elements.append(Paragraph(
                            f"[{risk['severity']}] {risk['category']}: {risk['description']}",
                            style
                        ))
            
            # Standard processing for other sections
            else:
                if isinstance(content, dict):
                    for key, value in content.items():
                        if key == "_risks":
                            continue
                            
                        elements.append(Paragraph(key, styles["SubHeader"]))
                        
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, dict):
                                    item_text = ", ".join([f"{k}: {v}" for k, v in item.items()])
                                    elements.append(Paragraph(f"• {item_text}", styles["Content"]))
                                else:
                                    elements.append(Paragraph(f"• {str(item)}", styles["Content"]))
                        elif isinstance(value, dict):
                            for subkey, subval in value.items():
                                if isinstance(subval, list):
                                    elements.append(Paragraph(f"{subkey}:", styles["Content"]))
                                    for item in subval:
                                        elements.append(Paragraph(f"    • {item}", styles["Content"]))
                                else:
                                    elements.append(Paragraph(f"{subkey}: {subval}", styles["Content"]))
                        else:
                            elements.append(Paragraph(f"{value}", styles["Content"]))
                            
                        elements.append(Spacer(1, 0.1 * inch))
                    
                    # Add risk findings
                    if "_risks" in content and content["_risks"]:
                        elements.append(Paragraph("Risk Findings", styles["SubHeader"]))
                        for risk in content["_risks"]:
                            severity = risk.get("severity", "").lower()
                            style = styles["Risk-High"] if severity == "high" else \
                                   styles["Risk-Medium"] if severity == "medium" else \
                                   styles["Risk-Low"]
                            
                            elements.append(Paragraph(
                                f"[{risk['severity']}] {risk['category']}: {risk['description']}",
                                style
                            ))
                
                elif isinstance(content, list):
                    for item in content:
                        elements.append(Paragraph(f"• {str(item)}", styles["Content"]))
                else:
                    elements.append(Paragraph(str(content), styles["Content"]))
                
                elements.append(Spacer(1, 0.2 * inch))

        doc.build(elements)
    except Exception as e:
        print(f"[!] Failed to write PDF: {e}")

def write_html(data, path):
    """Write report in HTML format."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("<html><head><title>DumpSec-Py Report</title>\n")
            f.write("""
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f9f9f9; }
                h1 { color: #333; }
                h2 { cursor: pointer; background: #333; color: #fff; padding: 10px; }
                .content { display: none; padding: 10px; background: #fff; border: 1px solid #ccc; margin-bottom: 20px; }
                .entry { margin-left: 20px; margin-bottom: 6px; }
                .subentry { margin-left: 40px; margin-bottom: 4px; }
                .risk-high { color: red; font-weight: bold; margin-left: 20px; }
                .risk-medium { color: orange; font-weight: bold; margin-left: 20px; }
                .risk-low { color: blue; font-weight: bold; margin-left: 20px; }
                .section { margin-bottom: 30px; }
                table { border-collapse: collapse; margin-left: 40px; margin-bottom: 10px; width: 90%; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 0.9em; }
                th { background-color: #eee; }
                .score-table { width: 50%; margin: 20px auto; }
                .score-table th { background-color: #333; color: white; }
                .high-row { background-color: #ffeeee; }
                .medium-row { background-color: #fff6ee; }
                .low-row { background-color: #eeeeff; }
                .chart { margin: 20px auto; width: 400px; height: 200px; }
            </style>
            <script>
                function toggle(id) {
                    var e = document.getElementById(id);
                    e.style.display = e.style.display === 'none' ? 'block' : 'none';
                }
                
                window.onload = function() {
                    // Expand the first section by default
                    if (document.getElementById('s1')) {
                        document.getElementById('s1').style.display = 'block';
                    }
                }
            </script>
            </head>
            <body>
            <h1>DumpSec-Py Security Audit Report</h1>
            """)
            
            # Process each section
            section_id = 0
            for section, content in data.items():
                if section.startswith("_"):
                    continue  # Skip internal sections
                    
                section_id += 1
                f.write(f"<div class='section'><h2 onclick='toggle(\"s{section_id}\")'>{section}</h2>")
                f.write(f"<div id='s{section_id}' class='content'>")

                # Special handling for Compliance Mapping
                if section == "Compliance Mapping" and isinstance(content, dict):
                    # Format compliance data specially
                    for framework, framework_data in content.items():
                        if framework == "_risks":
                            continue
                            
                        f.write(f"<h3>{framework}</h3>")
                        
                        # Display framework coverage information
                        if isinstance(framework_data, dict) and "coverage" in framework_data:
                            coverage = framework_data["coverage"]
                            f.write("<div class='entry'><strong>Coverage Information:</strong></div>")
                            f.write("<table style='width:60%'>")
                            f.write(f"<tr><td>Total Controls</td><td>{coverage.get('total_controls', 0)}</td></tr>")
                            f.write(f"<tr><td>Controls with Findings</td><td>{coverage.get('controls_with_findings', 0)}</td></tr>")
                            f.write(f"<tr><td class='risk-high'>High Risk Controls</td><td>{coverage.get('high_risk_controls', 0)}</td></tr>")
                            f.write(f"<tr><td class='risk-medium'>Medium Risk Controls</td><td>{coverage.get('medium_risk_controls', 0)}</td></tr>")
                            f.write(f"<tr><td class='risk-low'>Low Risk Controls</td><td>{coverage.get('low_risk_controls', 0)}</td></tr>")
                            f.write("</table><br>")
                        
                        # Display individual controls with findings
                        if isinstance(framework_data, dict) and "controls" in framework_data:
                            controls = framework_data["controls"]
                            f.write("<div class='entry'><strong>Control Findings:</strong></div>")
                            
                            for control_id, control_data in controls.items():
                                risk_class = f"risk-{control_data.get('highest_risk', 'low')}"
                                f.write(f"<div class='{risk_class}'><strong>{control_id}: {control_data.get('name', 'Unknown Control')}</strong></div>")
                                
                                # List findings for this control
                                findings = control_data.get("findings", [])
                                if findings:
                                    f.write("<ul>")
                                    for finding in findings:
                                        finding_severity = finding.get("severity", "").lower()
                                        finding_class = f"risk-{finding_severity}" if finding_severity in ["high", "medium", "low"] else "risk-low"
                                        f.write(f"<li class='{finding_class}'>{finding.get('description', 'No description')}</li>")
                                    f.write("</ul>")
                
                # Special handling for Windows Event Logs section
                elif section == "Windows Event Logs" and isinstance(content, dict) and "Recent Events" in content:
                    recent_events = content.get("Recent Events", [])
                    
                    # Print other content first
                    for key, value in content.items():
                        if key == "Recent Events" or key == "_risks":
                            continue
                            
                        f.write(f"<div class='entry'><strong>{key}:</strong></div>")
                        
                        if isinstance(value, dict):
                            for subkey, subval in value.items():
                                f.write(f"<div class='subentry'><strong>{subkey}:</strong> {subval}</div>")
                        elif isinstance(value, list):
                            for item in value:
                                f.write(f"<div class='subentry'>• {item}</div>")
                        else:
                            f.write(f"<div class='subentry'>{value}</div>")
                    
                    # Format the recent events in a table
                    if recent_events:
                        f.write("<div class='entry'><strong>Recent Events:</strong></div>")
                        f.write("<table style='width:100%'>")
                        
                        # Create table headers using keys from first event
                        if isinstance(recent_events, list) and len(recent_events) > 0:
                            if isinstance(recent_events[0], dict):
                                headers = ["Time", "EventID", "Description"]
                                if "Data" in recent_events[0]:
                                    headers.append("Details")
                                
                                f.write("<tr>")
                                for header in headers:
                                    f.write(f"<th>{header}</th>")
                                f.write("</tr>")
                                
                                # Add event data
                                for event in recent_events:
                                    f.write("<tr>")
                                    f.write(f"<td>{event.get('Time', '')}</td>")
                                    f.write(f"<td>{event.get('EventID', '')}</td>")
                                    f.write(f"<td>{event.get('Description', '')}</td>")
                                    
                                    # Format event data more readably
                                    if "Data" in event:
                                        data_html = "<ul>"
                                        for key, value in event.get("Data", {}).items():
                                            data_html += f"<li><strong>{key}:</strong> {value}</li>"
                                        data_html += "</ul>"
                                        f.write(f"<td>{data_html}</td>")
                                    
                                    f.write("</tr>")
                            else:
                                # Fallback if events aren't dictionaries
                                f.write("<tr><th>Event</th></tr>")
                                for event in recent_events:
                                    f.write(f"<tr><td>{str(event)}</td></tr>")
                        
                        f.write("</table>")
                    
                    # Add risk findings
                    if "_risks" in content and content["_risks"]:
                        f.write("<div class='entry'><strong>Risk Findings:</strong></div>")
                        for risk in content["_risks"]:
                            severity = risk.get("severity", "").lower()
                            css_class = f"risk-{severity}" if severity in ["high", "medium", "low"] else "risk-low"
                            
                            f.write(f"<div class='{css_class}'>[{risk['severity']}] {risk['category']}: {risk['description']}</div>")
                
                # Standard processing for other sections
                else:
                    if isinstance(content, dict):
                        for key, value in content.items():
                            if key == "_risks":
                                continue
                                
                            f.write(f"<div class='entry'><strong>{key}:</strong></div>")

                            # Display list of dicts as a table
                            if isinstance(value, list):
                                if all(isinstance(item, dict) for item in value):
                                    headers = sorted({k for item in value for k in item})
                                    f.write("<table><tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>")
                                    for item in value:
                                        f.write("<tr>")
                                        for h in headers:
                                            f.write(f"<td>{item.get(h, '')}</td>")
                                        f.write("</tr>")
                                    f.write("</table>")
                                elif all(isinstance(item, str) for item in value):
                                    for item in value:
                                        f.write(f"<div class='subentry'>• {item}</div>")
                                else:
                                    for item in value:
                                        f.write(f"<div class='subentry'>• {str(item)}</div>")

                            elif isinstance(value, dict):
                                for subkey, subval in value.items():
                                    f.write(f"<div class='subentry'><strong>{subkey}:</strong></div>")
                                    if isinstance(subval, list):
                                        if subval:
                                            for subitem in subval:
                                                f.write(f"<div class='subentry' style='margin-left: 60px;'>• {subitem}</div>")
                                        else:
                                            f.write(f"<div class='subentry' style='margin-left: 60px;'>(no members)</div>")
                                    elif isinstance(subval, str):
                                        f.write(f"<div class='subentry' style='margin-left: 60px;'>{subval}</div>")
                                    else:
                                        f.write(f"<div class='subentry' style='margin-left: 60px;'>{str(subval)}</div>")

                            elif isinstance(value, str):
                                f.write(f"<div class='subentry'>{value}</div>")
                            else:
                                f.write(f"<div class='subentry'>{str(value)}</div>")

                        if "_risks" in content and content["_risks"]:
                            f.write("<div class='entry'><strong>Risk Findings:</strong></div><ul>")
                            for risk in content["_risks"]:
                                severity = risk.get("severity", "").lower()
                                css_class = f"risk-{severity}" if severity in ["high", "medium", "low"] else "risk-low"
                                f.write(f"<li class='{css_class}'>[{risk['severity']}] {risk['category']}: {risk['description']}</li>")
                            f.write("</ul>")

                    elif isinstance(content, list):
                        for item in content:
                            f.write(f"<div class='entry'>• {item}</div>")
                    else:
                        f.write(f"<div class='entry'>{str(content)}</div>")

                f.write("</div></div>")

            f.write("</body>\n</html>")
    except Exception as e:
        print(f"[!] Failed to write HTML: {e}")

def write_csv(data, path):
    try:
        with open(path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Section", "Key", "Subkey", "Value"])

            for section, content in data.items():
                if section == "_risks":
                    continue

                if isinstance(content, dict):
                    for key, value in content.items():
                        if key == "_risks":
                            continue
                        if isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                if isinstance(subvalue, list):
                                    for item in subvalue:
                                        writer.writerow([section, key, subkey, item])
                                else:
                                    writer.writerow([section, key, subkey, subvalue])
                        elif isinstance(value, list):
                            for item in value:
                                writer.writerow([section, key, "", item])
                        else:
                            writer.writerow([section, key, "", value])
                    # Write risks if present
                    if "_risks" in content and content["_risks"]:
                        for risk in content["_risks"]:
                            risk_line = f"[{risk['severity']}] {risk['category']}: {risk['description']}"
                            writer.writerow([section, "Risk Finding", "", risk_line])
                elif isinstance(content, list):
                    for item in content:
                        writer.writerow([section, "", "", item])
                else:
                    writer.writerow([section, "", "", content])

    except Exception as e:
        print(f"[!] Failed to write CSV: {e}")


