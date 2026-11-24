"""Analysis views (Phases 10 & 11)."""
from typing import Any

from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from apps.analysis.forms import HistoryFilterForm, URLSubmissionForm
from apps.analysis.history import get_history_queryset
from apps.analysis.models import Investigation
from apps.analysis.services import analyse_url, get_investigation_context
from apps.url_analyzer.parser import InvalidURLError

_LEVEL_MAP = {
    "high": ("High risk", "badge--high"),
    "medium": ("Medium risk", "badge--medium"),
    "low_observed": ("Low observed risk", "badge--low"),
    "inconclusive": ("Inconclusive", "badge--inconclusive"),
}


def submit(request: HttpRequest) -> HttpResponse:
    """Handle URL submission form rendering and analysis orchestration."""
    if request.method == "POST":
        form = URLSubmissionForm(request.POST)
        if form.is_valid():
            raw_url = form.cleaned_data["url"]
            try:
                investigation = analyse_url(raw_url)
                return redirect(reverse("result", kwargs={"id": investigation.id}))
            except InvalidURLError as exc:
                form.add_error("url", str(exc))
        return render(request, "analysis/submit.html", {"form": form})

    form = URLSubmissionForm()
    return render(request, "analysis/submit.html", {"form": form})


def result(request: HttpRequest, id: int) -> HttpResponse:
    """Render comprehensive investigation result page."""
    investigation = get_object_or_404(Investigation, pk=id)
    context = get_investigation_context(investigation)
    return render(request, "analysis/result.html", context)


def _format_history_item(inv: Investigation) -> dict[str, Any]:
    """Format single investigation record for history table presentation."""
    label, badge_cls = _LEVEL_MAP.get(
        inv.overall_level, ("Inconclusive", "badge--inconclusive")
    )
    matches = [
        ("PhishTank" if l.source == "phishtank" else "URLhaus")
        for l in inv.threat_lookups.all()
        if l.matched
    ]
    ml = inv.ml_predictions.first()
    ml_str = "Phishing-like" if (ml and ml.predicted_class == "phishing_like") else ("Not phishing-like" if ml else "—")
    is_inconc = inv.overall_level == "inconclusive"
    return {
        "id": inv.id,
        "submitted_at": inv.submitted_at,
        "submitted_url": inv.submitted_url,
        "level_label": label,
        "badge_class": badge_cls,
        "score": None if is_inconc else inv.score,
        "show_score": not is_inconc and inv.score is not None,
        "intel_matches": ", ".join(matches) if matches else "None",
        "ml_result": ml_str,
        "details_url": reverse("result", kwargs={"id": inv.id}),
    }


def history(request: HttpRequest) -> HttpResponse:
    """Render paginated investigation history with search and filter controls."""
    form = HistoryFilterForm(request.GET)
    filters = form.cleaned_data if form.is_valid() else {}
    qs = get_history_queryset(filters).prefetch_related("threat_lookups", "ml_predictions")
    paginator = Paginator(qs, 25)
    page_number = request.GET.get("page", 1)
    page_obj = paginator.get_page(page_number)

    query_params = request.GET.copy()
    query_params.pop("page", None)
    filter_params = query_params.urlencode()

    items = [_format_history_item(inv) for inv in page_obj]
    context = {
        "form": form,
        "page_obj": page_obj,
        "items": items,
        "filter_params": filter_params,
    }
    return render(request, "analysis/history.html", context)
