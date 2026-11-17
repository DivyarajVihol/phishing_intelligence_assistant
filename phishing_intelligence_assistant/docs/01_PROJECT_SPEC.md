# 01. Project spec

## What it is
A Django web app where an analyst pastes a suspicious URL and gets an **explainable investigation**: parsed parts, local lexical and obfuscation findings, threat-intelligence lookups (PhishTank, URLhaus), an ML phishing-vs-benign prediction, an overall risk level, and a saved, searchable record with a report.

It is an **investigation assistant**, not a verdict machine. It never claims a URL is safe or proven malicious.

## MVP path (build this first, end to end)
submit URL -> validate -> parse -> local lexical + obfuscation checks -> ML baseline prediction -> PhishTank + URLhaus lookups -> separate evidence + overall explanation -> save investigation.

Dashboard, reports, brand similarity, DNS/RDAP and redirect checking come after the MVP works.

## In scope (v1)
- URL text/structure analysis only. The destination is never opened by the MVP.
- Binary ML classifier (phishing-like vs benign) on URL features.
- PhishTank (phishing) and URLhaus (malware) lookups, kept separate.
- Investigation history with search/filter, dashboard, structured report.
- Later phases: brand similarity, DNS, RDAP domain age, controlled redirect check.

## Out of scope (do NOT build)
User accounts/login, multi-user permissions, browser extension, public API, HTML/screenshot/JavaScript/file inspection, downloading files, automatic blocking or takedown, Character-Level CNN, Celery/Redis/background workers, Docker, cloud deployment.

## Three kinds of evidence (always shown separately)
| Type | Example | Rule |
|---|---|---|
| Direct intelligence match | PhishTank/URLhaus returns a record | Name source, record ID, lookup time, source's category |
| Heuristic warning | `@` in URL, look-alike characters | Say exactly which feature; it is a warning, not proof |
| ML prediction | "phishing-like", score 0.87 | Show model name/version; say it can be wrong |

Plus **unavailable checks** (timeout, rate limit, no key): shown as "Unavailable / not completed". Never shown as "no match" or "safe".

## Risk level and risk score
The result shows **both**: a risk level badge (High risk, Medium risk, Low observed risk, Inconclusive) and a **risk score from 0 to 100, where higher means more suspicious**. Never call it a "safety score".
- Each check adds points when it finds something suspicious. Points are added up (max 100).
- A confirmed PhishTank/URLhaus match forces the score to at least 90 and the level to High, whatever the other points are.
- The result always shows a points breakdown (check -> points) and coverage ("Based on 4 of 6 checks"), so the number is never unexplained.
- If too few checks completed, the level is Inconclusive and no score is shown.
- All weights, caps and band edges live in `risk_engine/rules.py`, are tuned on the validation set (never the test set) and documented. The score is a transparent summary, not a probability.

## Never open the submitted URL (hard rule)
Nobody (user, browser or server) may follow a submitted URL by accident: no clickable link, no "visit site" button, no redirect to it, no auto-open, no preview. It is always shown as **defanged plain text** (`hxxps://example[.]com/path`). Details in `05_SECURITY_RULES.md`.

## Required wording
- Use: "No match found in this source at the time of lookup". Never: "Safe", "Clean", "Verified safe".
- Use: "Suspicious indicators detected". Never: "Confirmed malicious", unless a threat source actually confirms it.
- Model output is "model score", not "probability" (not calibrated).
- Every result and report ends with the limitation notice (text in `06_UI_GUIDELINES.md`).

## Success criteria
- The MVP path works for benign, suspicious and known-bad URLs, and when any external service fails.
- Model metrics are measured on a held-out and a time-based test set and reported honestly. **No accuracy target is promised in advance.**
- False positives and false negatives are reviewed and listed.
