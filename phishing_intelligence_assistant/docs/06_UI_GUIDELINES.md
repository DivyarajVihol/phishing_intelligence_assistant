# 06. UI guidelines (LOCKED, no redesigns)

## Principles
Server-rendered Django templates. Clean, calm, analyst-tool look. One CSS file (`static/css/style.css`), one tiny JS file (`static/js/app.js`, only for small things like a loading state on submit). No inline styles, no CSS/JS frameworks, no CDN, no external fonts, no icon library. Light theme only.

## Pages
| Page | Content |
|---|---|
| Submit `/` | Heading, one URL input (the URL is never shown back as a link), **Analyse** button, third-party lookup notice, link to history |
| Result `/analysis/<id>/` | Submitted URL (defanged plain text, never a link), overall risk badge + summary, then sections below |
| History `/history/` | Search box, filters (date range, risk level, source match, status, model result), table |
| Dashboard `/dashboard/` | Stat cards + tables and CSS bars (see spec metrics) |
| Report `/analysis/<id>/report/` | Print-friendly version of the result page |

## Result page order (always the same)
1. Overall assessment: risk badge, **risk score** (e.g. "58 / 100, higher means more suspicious"), coverage line ("Based on 4 of 6 checks"), plain-language summary, reasons, and a small **points table** (check -> points). Inconclusive shows no score
2. Threat intelligence: one row per source (PhishTank, URLhaus), each with its own state
3. Local URL and obfuscation findings (with severity chip)
4. ML prediction: model name/version, label, model score, threshold
5. Enrichment (brand, DNS, RDAP, redirects): only if those phases exist
6. Unavailable / not completed checks (own section, never merged into "clear")
7. Parsed URL components table
8. Limitation notice

## Design tokens (define once as CSS variables on `:root`)
```
--bg:#f7f8fa; --surface:#ffffff; --text:#1a1d23; --muted:#5b6472; --border:#dde1e7; --accent:#2457d6;
risk high:         text #b42318  bg #fdeceb
risk medium:       text #b54708  bg #fff4e5
risk low observed: text #0f766e  bg #e6f4f1
risk inconclusive: text #475467  bg #eef0f3
font: system-ui stack; monospace stack for URLs/evidence
layout: max-width 960px, centered; spacing scale 4/8/16/24/32 px; radius 8px; 1px borders, no heavy shadows
```
Never convey state by colour alone: every badge also carries its text label.

## Components (reuse, do not invent new ones)
`.card` · `.score` (number + thin bar, colour follows the level) · `.badge` + `.badge--high|medium|low|inconclusive` · `.chip` (severity) · `.finding` (title, explanation, evidence in `<code>`) · `.table` · `.notice` · `.btn` / `.btn--primary`.

## Wording on screen
- Risk labels: "High risk", "Medium risk", "Low observed risk", "Inconclusive". Never "Safe".
- Intel states: "Match found", "No match found in this source at the time of lookup", "Unavailable", "Not configured".
- Limitation notice (verbatim): *"These results are indicators for investigation. They do not independently establish that a website is malicious or safe. A missing threat-feed record does not mean a URL is safe."*

## Submitted URLs are never clickable
Everywhere a submitted URL appears it is defanged plain text in `<code>` (`hxxps://example[.]com/path`). There is no "Open site" or "Visit" button on any page, at any risk level. Only "Copy defanged URL" is allowed. See `05_SECURITY_RULES.md`.

## Accessibility basics
Labels on all inputs, visible focus outline, headings in order, sufficient contrast, usable at phone width (single column below 640 px).
