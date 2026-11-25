"""Pure section builders and text extraction for PDF investigation reports."""
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from apps.analysis.templatetags.dates import fmt_datetime


def clean_pdf_text(value: Any) -> str:
    """Convert value to Latin-1 safe plain text, replacing unsupported chars with '?'."""
    return str("" if value is None else value).encode("latin-1", "replace").decode("latin-1")


def esc(value: Any) -> str:
    """Escape XML/markup characters after Latin-1 sanitization for reportlab Paragraphs."""
    return escape(clean_pdf_text(value))


def make_pdf_styles() -> dict[str, ParagraphStyle]:
    """Create built-in Helvetica paragraph styles for PDF reports."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("PdfTitle", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=16, spaceAfter=6),
        "h2": ParagraphStyle("PdfH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("PdfBody", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13, spaceAfter=3),
        "small": ParagraphStyle("PdfSmall", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=11, spaceAfter=2),
    }


def _simple_table(rows: list[list[Any]], widths: list[int], styles: dict[str, ParagraphStyle]) -> Table:
    """Build a plain bordered reportlab table using Paragraph cells."""
    data = [[Paragraph(esc(cell), styles["small"]) for cell in r] for r in rows]
    tbl = Table(data, colWidths=widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef0f3")),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde1e7")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl


def extract_report_text_lines(report: dict[str, Any]) -> list[str]:
    """Extract all plain-text lines from report dict using defanged URL only."""
    a = report["assessment"]
    lines = [
        clean_pdf_text(report["title"]),
        f"Report ID: {report['report_id']}",
        f"Generated: {fmt_datetime(report.get('generated_at'))}",
        f"Submitted: {fmt_datetime(report.get('submitted_at'))}",
        f"Submitted URL (Defanged): {report['submitted_url_defanged']}",
        f"Risk Level: {a['level_label']}",
        f"Coverage: Based on {a['coverage']['completed']} of {a['coverage']['total']} checks completed.",
        clean_pdf_text(a["summary"]),
    ]
    if a.get("show_score"):
        lines.append(f"Score: {a['score']} / 100, higher means more suspicious")
    lines.extend(clean_pdf_text(r) for r in a.get("reasons", []))
    lines.extend(f"{b['group']}: {b['points']}" for b in a.get("points_breakdown", []))
    for k, v in report.get("parsed_components", {}).items():
        lines.append(f"{k}: {v}")
    for lk in report.get("threat_intel", []):
        lines.append(f"{lk['source_name']}: {lk['status']} ({lk.get('source_record_id') or '-'}) {fmt_datetime(lk.get('queried_at'))}")
    for f in report.get("local_findings", []):
        lines.append(f"{f['check_name']} [{f['severity']}]: {f['explanation']}")
    for f in report.get("enrichment_findings", []):
        lines.append(f"{f['check_name']} [{f['severity']}]: {f['explanation']}")
    ml = report.get("ml_prediction")
    if ml:
        lines.append(f"ML: {ml['model_name']} {ml['model_version']} {ml['label']} score={ml['score']} threshold={ml['threshold']}")
    for u in report.get("unavailable_checks", []):
        lines.append(f"Unavailable {u['name']} ({u['category']}): {u['explanation']}")
    lines.append(clean_pdf_text(report["limitations"]))
    lines.extend(clean_pdf_text(s) for s in report.get("suggested_next_steps", []))
    return lines


def build_header_and_assessment(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """Build title, metadata, defanged URL, parsed components, and assessment flowables."""
    a = report["assessment"]
    story: list[Any] = [
        Paragraph(esc(report["title"]), styles["title"]),
        Paragraph(f"Report ID: {esc(report['report_id'])} | Generated: {esc(fmt_datetime(report.get('generated_at')))} | Submitted: {esc(fmt_datetime(report.get('submitted_at')))}", styles["small"]),
        Paragraph(f"<b>Submitted URL (Defanged):</b> {esc(report['submitted_url_defanged'])}", styles["body"]),
        Paragraph("Overall Assessment", styles["h2"]),
        Paragraph(f"<b>Level:</b> {esc(a['level_label'])}", styles["body"]),
    ]
    if a.get("show_score"):
        story.append(Paragraph(f"<b>Risk Score:</b> {esc(a['score'])} / 100, higher means more suspicious", styles["body"]))
    story.append(Paragraph(f"Based on {esc(a['coverage']['completed'])} of {esc(a['coverage']['total'])} checks completed.", styles["body"]))
    story.append(Paragraph(esc(a["summary"]), styles["body"]))
    for r in a.get("reasons", []):
        story.append(Paragraph(f"- {esc(r)}", styles["small"]))
    if a.get("points_breakdown"):
        rows = [["Check Group", "Points"]] + [[b["group"], b["points"]] for b in a["points_breakdown"]]
        story.extend([Spacer(1, 4), _simple_table(rows, [320, 180], styles)])
    parsed = report.get("parsed_components") or {}
    if parsed:
        p_rows = [["Component", "Value"]] + [[k, v if v not in ("", None) else "-"] for k, v in parsed.items()]
        story.extend([Paragraph("Parsed URL Components", styles["h2"]), _simple_table(p_rows, [160, 340], styles)])
    return story


def build_intel_and_ml_sections(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """Build threat intelligence and ML prediction flowables."""
    story: list[Any] = [Paragraph("Threat Intelligence", styles["h2"])]
    intel = report.get("threat_intel") or []
    if intel:
        rows = [["Source", "Status", "Record ID", "Queried At"]] + [
            [lk["source_name"], lk["status"], lk.get("source_record_id") or "-", fmt_datetime(lk.get("queried_at"))]
            for lk in intel
        ]
        story.append(_simple_table(rows, [100, 130, 120, 150], styles))
    else:
        story.append(Paragraph("No threat intelligence lookups recorded.", styles["body"]))
    story.append(Paragraph("ML Prediction", styles["h2"]))
    ml = report.get("ml_prediction")
    if ml:
        story.append(Paragraph(
            f"Model: {esc(ml['model_name'])} ({esc(ml['model_version'])}) | Label: {esc(ml['label'])} | "
            f"Model score: {esc(ml['score'])} | Threshold: {esc(ml['threshold'])}",
            styles["body"],
        ))
    else:
        story.append(Paragraph("Machine learning prediction is not available.", styles["body"]))
    return story


def build_findings_and_footer_sections(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """Build local findings, enrichment (if present), unavailable, limitations, and next steps."""
    story: list[Any] = [Paragraph("Local URL & Obfuscation Findings", styles["h2"])]
    local = report.get("local_findings") or []
    if local:
        story.append(_simple_table([["Check", "Severity", "Explanation"]] + [[f["check_name"], f["severity"], f["explanation"]] for f in local], [130, 70, 300], styles))
    else:
        story.append(Paragraph("No local heuristic findings recorded.", styles["body"]))
    enrich = report.get("enrichment_findings") or []
    if enrich:
        story.append(Paragraph("Enrichment (Brand / DNS / RDAP)", styles["h2"]))
        story.append(_simple_table([["Check", "Severity", "Explanation"]] + [[f["check_name"], f["severity"], f["explanation"]] for f in enrich], [130, 70, 300], styles))
    unavail = report.get("unavailable_checks") or []
    story.append(Paragraph("Unavailable / Not Completed Checks", styles["h2"]))
    if unavail:
        story.append(_simple_table([["Check", "Category", "Detail"]] + [[u["name"], u["category"], u["explanation"]] for u in unavail], [130, 90, 280], styles))
    else:
        story.append(Paragraph("All enabled checks completed.", styles["body"]))
    story.append(Paragraph("Limitations", styles["h2"]))
    story.append(Paragraph(esc(report["limitations"]), styles["body"]))
    story.append(Paragraph("Suggested Next Steps", styles["h2"]))
    story.extend(Paragraph(f"- {esc(step)}", styles["small"]) for step in report.get("suggested_next_steps", []))
    return story
