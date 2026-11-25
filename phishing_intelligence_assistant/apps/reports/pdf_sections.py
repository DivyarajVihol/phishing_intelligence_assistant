"""Pure section builders and text extraction for PDF investigation reports."""
import re
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from apps.analysis.templatetags.dates import fmt_datetime

_INTEL_STATUS_LABELS = {
    "match": "Match found",
    "no_match": "No match found in this source at the time of lookup.",
    "unavailable": "Unavailable",
    "not_configured": "Not configured",
}

_PARSED_LABELS = (
    ("scheme", "Scheme"), ("scheme_assumed", "Scheme assumed"), ("hostname", "Hostname"),
    ("subdomain", "Subdomain"), ("registered_domain", "Registered domain"), ("suffix", "Suffix"),
    ("port", "Port"), ("path", "Path"), ("query", "Query"), ("is_ip_host", "IP host"),
)


def clean_pdf_text(value: Any) -> str:
    """Convert value to Latin-1 safe plain text, replacing unsupported chars with '?'."""
    return str("" if value is None else value).encode("latin-1", "replace").decode("latin-1")


def esc(value: Any) -> str:
    """Escape XML/markup characters after Latin-1 sanitization for reportlab Paragraphs."""
    return escape(clean_pdf_text(value))


def _format_intel_row(lk: dict[str, Any]) -> list[str]:
    """Format a single threat-intel row with website wording."""
    raw_status = lk.get("status", "")
    status_label = _INTEL_STATUS_LABELS.get(raw_status, "Not configured")
    rec_id = str(lk.get("source_record_id") or "").strip()
    if rec_id and raw_status == "no_match":
        rec_display = f"{rec_id} (Reported to this source but not confirmed as phishing)"
    else:
        rec_display = rec_id or "-"
    return [str(lk.get("source_name", "")), status_label, rec_display, fmt_datetime(lk.get("queried_at"))]


def _format_parsed_rows(parsed: dict[str, Any]) -> list[list[str]]:
    """Format parsed URL components with readable labels and Yes/No booleans."""
    rows: list[list[str]] = []
    for key, label in _PARSED_LABELS:
        if key not in parsed:
            continue
        val = parsed[key]
        display = ("Yes" if val else "No") if isinstance(val, bool) else ("-" if val in ("", None) else str(val))
        rows.append([label, display])
    return rows


def _format_enrichment_explanation(finding: dict[str, Any]) -> str:
    """Append approximate years to domain age explanations when >= 1 year."""
    text = str(finding.get("explanation", ""))
    m = re.match(r"^Domain age is (\d+) days\.$", text)
    if m:
        days = int(m.group(1))
        years = days // 365
        if years >= 1:
            return f"Domain age is {days} days (about {years} year{'s' if years != 1 else ''})."
    return text


def make_pdf_styles() -> dict[str, ParagraphStyle]:
    """Create built-in Helvetica paragraph styles for PDF reports."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("PdfTitle", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=16, spaceAfter=6),
        "h2": ParagraphStyle("PdfH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("PdfH3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, spaceBefore=6, spaceAfter=3),
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
    if a.get("points_breakdown"):
        lines.append("Points Breakdown")
        lines.extend(f"{b['group']}: {b['points']}" for b in a["points_breakdown"])
    lines.extend(f"{lbl}: {val}" for lbl, val in _format_parsed_rows(report.get("parsed_components") or {}))
    lines.extend(" | ".join(_format_intel_row(lk)) for lk in report.get("threat_intel", []))
    lines.extend(f"{f['check_name']} [{f['severity']}]: {f['explanation']}" for f in report.get("local_findings", []))
    lines.extend(f"{f['check_name']} [{f['severity']}]: {_format_enrichment_explanation(f)}" for f in report.get("enrichment_findings", []))
    ml = report.get("ml_prediction")
    if ml:
        lines.append(f"ML: {ml['model_name']} {ml['model_version']} {ml['label']} score={ml['score']} threshold={ml['threshold']}")
    lines.extend(f"Unavailable {u['name']} ({u['category']}): {u['explanation']}" for u in report.get("unavailable_checks", []))
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
    story.extend(Paragraph(f"- {esc(r)}", styles["small"]) for r in a.get("reasons", []))
    if a.get("points_breakdown"):
        rows = [["Check Group", "Points"]] + [[b["group"], b["points"]] for b in a["points_breakdown"]]
        story.extend([Paragraph("Points Breakdown", styles["h3"]), _simple_table(rows, [320, 180], styles)])
    p_rows = _format_parsed_rows(report.get("parsed_components") or {})
    if p_rows:
        story.extend([Paragraph("Parsed URL Components", styles["h2"]), _simple_table([["Component", "Value"]] + p_rows, [160, 340], styles)])
    return story


def build_intel_and_ml_sections(report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    """Build threat intelligence and ML prediction flowables."""
    story: list[Any] = [Paragraph("Threat Intelligence", styles["h2"])]
    intel = report.get("threat_intel") or []
    if intel:
        rows = [["Source", "Status", "Record ID", "Queried At"]] + [_format_intel_row(lk) for lk in intel]
        story.append(_simple_table(rows, [85, 165, 120, 130], styles))
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
        story.append(_simple_table([["Check", "Severity", "Explanation"]] + [[f["check_name"], f["severity"], _format_enrichment_explanation(f)] for f in enrich], [130, 70, 300], styles))
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
