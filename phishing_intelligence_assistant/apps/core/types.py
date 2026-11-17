"""Shared dataclasses for phishing intelligence analysis (plain Python, no Django)."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(frozen=True)
class ParsedURL:
    """Structured representation of a parsed URL."""
    original: str
    normalized: str
    scheme: str
    scheme_assumed: bool
    hostname: str
    subdomain: str
    registered_domain: str
    suffix: str
    port: Optional[int]
    userinfo: str
    path: str
    query: str
    fragment: str
    is_ip_host: bool


@dataclass(frozen=True)
class Finding:
    """Individual analytical finding or indicator."""
    check_name: str
    category: str  # "heuristic" | "intel" | "enrichment" | "ml"
    status: str  # "flagged" | "clear" | "unavailable" | "not_run"
    severity: str  # "info" | "low" | "medium" | "high"
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    checked_at: Optional[datetime] = None


@dataclass(frozen=True)
class ThreatLookup:
    """Threat intelligence source lookup result."""
    source: str
    status: str  # "match" | "no_match" | "unavailable" | "not_configured"
    record_id: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)
    queried_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class Prediction:
    """Machine learning model prediction result."""
    model_name: str
    model_version: str
    label: str  # "phishing_like" | "benign"
    score: float
    threshold: float


@dataclass(frozen=True)
class Assessment:
    """Aggregated risk assessment and scoring result."""
    level: str  # "high" | "medium" | "low_observed" | "inconclusive"
    score: Optional[int]
    checks_completed: int
    checks_total: int
    breakdown: list[tuple[str, int]] = field(default_factory=list)
    summary: str = ""
    reasons: list[str] = field(default_factory=list)
