"""Analysis views."""
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


def index(request: HttpRequest) -> HttpResponse:
    """Render placeholder home page."""
    return render(request, "base.html")
