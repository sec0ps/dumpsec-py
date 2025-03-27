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
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.units import inch

        doc = SimpleDocTemplate(
            path,
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, leading=18, spaceAfter=12, spaceBefore=16, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='Entry', fontSize=10.5, leading=14, alignment=TA_LEFT))
        styles.add(ParagraphStyle(name='Risk', fontSize=10.5, leading=14, alignment=TA_LEFT, textColor='red'))

        elements = []

        elements.append(Paragraph("DumpSec-Py Security Audit Report", styles["Title"]))
        elements.append(Spacer(1, 0.3 * inch))

        for section, content in data.items():
            if section == "_risks":
                continue

            elements.append(Paragraph(section, styles["SectionHeader"]))

            if isinstance(content, dict):
                for key, value in content.items():
                    if key == "_risks":
                        continue
                    elements.append(Paragraph(f"{key}:", styles["Entry"]))
                    if isinstance(value, list):
                        for item in value:
                            elements.append(Paragraph(f"  - {item}", styles["Entry"]))
                    elif isinstance(value, dict):
                        for subkey, sublist in value.items():
                            elements.append(Paragraph(f"  {subkey}:", styles["Entry"]))
                            if sublist:
                                for subitem in sublist:
                                    elements.append(Paragraph(f"    - {subitem}", styles["Entry"]))
                            else:
                                elements.append(Paragraph("    (no members)", styles["Entry"]))
                    else:
                        elements.append(Paragraph(f"  {value}", styles["Entry"]))
                if "_risks" in content and content["_risks"]:
                    elements.append(Paragraph("!! Risk Findings:", styles["Risk"]))
                    for risk in content["_risks"]:
                        risk_text = f"[{risk['severity']}] {risk['category']}: {risk['description']}"
                        elements.append(Paragraph(risk_text, styles["Risk"]))
            elif isinstance(content, list):
                for item in content:
                    elements.append(Paragraph(f"  - {item}", styles["Entry"]))
            else:
                elements.append(Paragraph(str(content), styles["Entry"]))

            elements.append(Spacer(1, 0.2 * inch))

        doc.build(elements)

    except Exception as e:
        print(f"[!] Failed to write PDF: {e}")

def write_html(data, path):
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
                .risk { color: red; font-weight: bold; margin-left: 20px; }
                .section { margin-bottom: 30px; }
            </style>
            <script>
                function toggle(id) {
                    var e = document.getElementById(id);
                    e.style.display = e.style.display === 'none' ? 'block' : 'none';
                }
            </script>
            </head><body>
            <h1>DumpSec-Py Security Audit Report</h1>
            """)

            section_id = 0
            for section, content in data.items():
                if section == "_risks":
                    continue
                section_id += 1
                f.write(f"<div class='section'><h2 onclick='toggle(\"s{section_id}\")'>{section}</h2>")
                f.write(f"<div id='s{section_id}' class='content'>")

                if isinstance(content, dict):
                    for key, value in content.items():
                        if key == "_risks":
                            continue
                        f.write(f"<div class='entry'><strong>{key}:</strong></div>")

                        if isinstance(value, list):
                            if all(isinstance(item, str) for item in value):
                                for item in value:
                                    f.write(f"<div class='subentry'>- {item}</div>")
                            elif all(isinstance(item, dict) for item in value):
                                for item in value:
                                    f.write("<div class='subentry'>-</div>")
                                    for k, v in item.items():
                                        f.write(f"<div class='subentry' style='margin-left: 60px;'><strong>{k}:</strong> {v}</div>")
                            else:
                                for item in value:
                                    f.write(f"<div class='subentry'>- {str(item)}</div>")

                        elif isinstance(value, dict):
                            for subkey, subval in value.items():
                                f.write(f"<div class='subentry'><strong>{subkey}:</strong></div>")
                                if isinstance(subval, list):
                                    if subval:
                                        for subitem in subval:
                                            f.write(f"<div class='subentry' style='margin-left: 60px;'>- {subitem}</div>")
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
                            f.write(f"<li class='risk'>[{risk['severity']}] {risk['category']}: {risk['description']}</li>")
                        f.write("</ul>")

                elif isinstance(content, list):
                    for item in content:
                        f.write(f"<div class='entry'>- {item}</div>")
                else:
                    f.write(f"<div class='entry'>{str(content)}</div>")

                f.write("</div></div>")

            f.write("</body></html>")

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


