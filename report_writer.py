import json
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import inch


def write_report(data, output_format, filename):
    if output_format == "txt":
        write_txt(data, filename + ".txt")
    elif output_format == "json":
        write_json(data, filename + ".json")
    elif output_format == "pdf":
        write_pdf(data, filename + ".pdf")
    else:
        print(f"[!] Unsupported format: {output_format}")


def write_txt(data, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            for section, content in data.items():
                f.write(f"=== {section} ===\n")
                if isinstance(content, list):
                    for line in content:
                        f.write(f"{line}\n")
                elif isinstance(content, dict):
                    for key, value in content.items():
                        f.write(f"{key}: {value}\n")
                else:
                    f.write(f"{content}\n")
                f.write("\n")
    except Exception as e:
        print(f"[!] Failed to write TXT: {e}")


def write_json(data, path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[!] Failed to write JSON: {e}")


def write_pdf(data, path):
    try:
        doc = SimpleDocTemplate(path, pagesize=LETTER, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, leading=18, spaceAfter=10, spaceBefore=20, alignment=TA_LEFT, fontName='Helvetica-Bold'))
        styles.add(ParagraphStyle(name='Content', fontSize=10.5, leading=14, alignment=TA_LEFT))

        elements = []

        elements.append(Paragraph("DumpSec-Py Security Audit Report", styles["Title"]))
        elements.append(Spacer(1, 0.25 * inch))

        for section, content in data.items():
            elements.append(Paragraph(section, styles["SectionHeader"]))

            if isinstance(content, list):
                for line in content:
                    elements.append(Paragraph(str(line), styles["Content"]))
            elif isinstance(content, dict):
                for key, value in content.items():
                    elements.append(Paragraph(f"{key}: {value}", styles["Content"]))
            else:
                elements.append(Paragraph(str(content), styles["Content"]))

            elements.append(Spacer(1, 0.2 * inch))

        doc.build(elements)

    except Exception as e:
        print(f"[!] Failed to write PDF: {e}")
