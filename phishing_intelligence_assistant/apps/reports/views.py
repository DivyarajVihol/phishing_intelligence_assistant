"""Views for HTML and JSON investigation reports (Phase 15)."""
import json

from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render

from apps.analysis.models import Investigation
from apps.reports.builder import build_report


def report_html(request: HttpRequest, id: int) -> HttpResponse:
    """Render print-friendly HTML investigation report."""
    investigation = get_object_or_404(Investigation, pk=id)
    report = build_report(investigation)
    return render(request, "reports/report.html", {"report": report})


def report_json(request: HttpRequest, id: int) -> HttpResponse:
    """Download investigation report as JSON attachment."""
    investigation = get_object_or_404(Investigation, pk=id)
    report = build_report(investigation)
    payload = json.dumps(report, indent=2)
    response = HttpResponse(payload, content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="report_{investigation.id}.json"'
    return response
