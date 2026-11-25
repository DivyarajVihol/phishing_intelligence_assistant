"""PDF report generator using reportlab with Helvetica fonts and Page N of M footer."""
from io import BytesIO
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate

from apps.reports.pdf_sections import (
    build_findings_and_footer_sections,
    build_header_and_assessment,
    build_intel_and_ml_sections,
    clean_pdf_text,
    make_pdf_styles,
)


class _NumberedCanvas(canvas.Canvas):
    """Canvas subclass that renders 'Page N of M' footer in Helvetica."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total_pages: int) -> None:
        self.setFont("Helvetica", 8)
        self.drawRightString(A4[0] - 40, 24, f"Page {self._pageNumber} of {total_pages}")


def generate_pdf_bytes(report: dict[str, Any]) -> bytes:
    """Render canonical report dictionary as plain, link-free PDF bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=45,
        title=clean_pdf_text(report.get("title", "Investigation Report")),
    )
    styles = make_pdf_styles()
    story = (
        build_header_and_assessment(report, styles)
        + build_intel_and_ml_sections(report, styles)
        + build_findings_and_footer_sections(report, styles)
    )
    doc.build(story, canvasmaker=_NumberedCanvas)
    return buf.getvalue()
