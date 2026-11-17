---
trigger: model_decision
description: Use when writing code that makes network requests, handles API keys or settings, parses user-submitted URLs, or implements threat-intel connectors, DNS/RDAP lookups or the redirect checker.
---

# Security rules (full spec: `docs/05_SECURITY_RULES.md`)

- Submitted URLs are untrusted data. The MVP never opens or fetches them.
- **Nobody may open a submitted URL**: defanged plain text only, no links/buttons/iframes/previews, no `redirect()` to user data (only internal `reverse()` redirects), no `?next=`. Every UI phase tests this (see `docs/05`).
- Every outbound request: explicit timeout from `EXTERNAL_TIMEOUT_SECONDS`, no unbounded retries, no downloading bodies.
- API keys only from `.env` via `config/settings.py`. Never log, print, render, store or commit them.
- Connectors never raise to the caller: timeout, rate limit (HTTP 509/429), invalid key, bad JSON all map to `status="unavailable"`; missing key maps to `not_configured`.
- Redirect checker is off by default and must block loopback, private, link-local, multicast and reserved IPs (IPv4 and IPv6) after DNS resolution and at every hop; max 5 redirects.
- RDAP goes only to `rdap.org`; validate the domain with a strict regex first.
- Tests mock all network access.
