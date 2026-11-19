# AGENTS.md: Open-Source Phishing Intelligence and Investigation Assistant

Django web app: user submits a suspicious URL, gets an explainable investigation (lexical + obfuscation checks, PhishTank/URLhaus lookups, ML prediction, risk level and 0-100 risk score), saved to history, with dashboard and reports. It is an investigation assistant, never a "safe/malicious" oracle.

## Read before any task
`docs/01_PROJECT_SPEC.md`, `docs/02_TECH_STACK.md`, `docs/03_ARCHITECTURE.md`, `docs/07_CODING_RULES.md`, plus the docs the task names (`04` ML/data, `05` security, `06` UI). The current task comes from `docs/08_BUILD_PLAN.md`.

## Hard rules
1. **Stack is locked**: Python 3.12, Django 5.2, SQLite, pandas, scikit-learn, joblib, tldextract, requests, python-dotenv. No new dependency, framework, CDN, chart library or UI library. Ask first.
2. **UI is locked**: Django templates, `static/css/style.css`, `static/js/app.js`, design tokens in `docs/06`. No inline styles. No redesigns.
3. **Touch only the files the task lists.** Never rewrite or reformat working files. Never rename contract functions or dataclass fields in `docs/03`.
4. **Keep code short**: functions <= 30 lines, files <= 200 lines, no speculative features, no abstractions "for later", no TODO stubs, no commented-out code.
5. `core`, `url_analyzer`, `ml_engine`, `risk_engine`, `threat_intel` are plain Python and must not import Django. Views contain no analysis logic.
6. **Training and prediction share one feature path** (`url_analyzer.features` + `ml_engine.predict.build_row`). Never duplicate it.
7. **Evidence stays separated**: intel match, heuristic warning, ML prediction, unavailable check. A failed check is "Unavailable", never "no match" or "safe". Never write "Safe" or "Confirmed malicious" in code, UI or reports.
8. **Score**: higher = more suspicious, called "risk score". All weights live in `risk_engine/rules.py`. A confirmed intel match forces score >= 90. Always show the points breakdown and coverage.
9. **NEVER let anyone open a submitted URL**: show it only as defanged plain text (`defang_url`); no `<a href>`, buttons, redirects, iframes, previews or `urlize`; views never redirect to user data. See `docs/05`.
10. Security: never fetch submitted URLs in the MVP; never log or print secrets; all outbound calls have timeouts; tests never touch the network. URLhaus records are malware intelligence, never phishing labels.
11. If anything is ambiguous or a contract looks wrong, **ask a short question** instead of guessing.
12. On this Windows machine pip.exe is blocked. Always run python -m pip ... and python manage.py ... (the .venv is active). Never call pip directly.
13. pandas 2.3.x works on this machine. Do not upgrade pandas to 3.x, because that version is blocked by an application-control policy.

## Workflow
One phase at a time. Write tests with the code. Run `python manage.py test apps ml`. End with: files changed, test result, anything left undone. Then stop and wait.
