"""Analysis views (Phase 10)."""
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from apps.analysis.forms import URLSubmissionForm
from apps.analysis.models import Investigation
from apps.analysis.services import analyse_url, get_investigation_context
from apps.url_analyzer.parser import InvalidURLError


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
