# 03. Architecture and module contracts

## Folder tree (create only what the current phase needs)
```
phishing_intelligence_assistant/
├── manage.py
├── config/                  settings.py (only place reading .env), urls.py, wsgi.py
├── apps/
│   ├── core/                types.py            shared dataclasses (no Django)
│   ├── url_analyzer/        parser.py  constants.py  features.py  lexical.py  obfuscation.py  defang.py
│   │                        brand.py  domain_checks.py  redirects.py        (last 3: later phases)
│   ├── threat_intel/        phishtank.py  urlhaus.py  service.py
│   ├── ml_engine/           predict.py  (loads artifact, builds model input row)
│   ├── risk_engine/         rules.py  engine.py
│   ├── analysis/            models.py  services.py  views.py  urls.py  forms.py
│   ├── dashboard/           views.py  urls.py                               (Phase 14)
│   └── reports/             views.py  urls.py                               (Phase 15)
├── ml/
│   ├── data/                raw/  processed/   (git-ignored; see 04)
│   ├── training/            prepare_data.py  train.py  evaluate.py
│   └── artifacts/           model-v1.joblib  model-v1.json  evaluation.md
├── templates/               base.html + one folder per app
├── static/                  css/style.css  js/app.js
├── tests/                   (or tests.py inside each app)
├── docs/  .agents/  AGENTS.md  requirements.txt  .env.example  .gitignore  README.md
```
`core`, `url_analyzer`, `ml_engine`, `risk_engine` and `threat_intel` are plain Python packages. Only `analysis`, `dashboard`, `reports` are Django apps with views. Only `analysis` has models.

## Layering rule
`views -> analysis.services -> (url_analyzer | threat_intel | ml_engine | risk_engine) -> core`.
Views never contain analysis logic. Modules never import from `analysis`, views or each other sideways (they only share `core.types`). One failing module must never stop the others.

## Shared types (`apps/core/types.py`, `@dataclass(frozen=True)`)
```python
ParsedURL:   original, normalized, scheme, scheme_assumed, hostname, subdomain,
             registered_domain, suffix, port, userinfo, path, query, fragment, is_ip_host
Finding:     check_name, category ("heuristic"|"intel"|"enrichment"|"ml"),
             status ("flagged"|"clear"|"unavailable"|"not_run"),
             severity ("info"|"low"|"medium"|"high"), explanation, evidence (dict),
             source, checked_at
ThreatLookup: source, status ("match"|"no_match"|"unavailable"|"not_configured"),
             record_id, detail (dict), queried_at, error
Prediction:  model_name, model_version, label ("phishing_like"|"benign"), score, threshold
Assessment:  level ("high"|"medium"|"low_observed"|"inconclusive"), score (int 0-100 | None),
             checks_completed, checks_total, breakdown (list of (check_name, points)),
             summary, reasons (list[str])
```

## Module contracts (signatures are fixed; do not rename)
| Module | Function | Notes |
|---|---|---|
| `url_analyzer.parser` | `parse_url(raw, max_len=2048) -> ParsedURL` | Raises `InvalidURLError`. Only http/https. No scheme -> assume `http://`, set `scheme_assumed`. Hostname lowercased, IDN kept in original and punycode forms. Original string always preserved. If the TLD is not in the public suffix list (`suffix == ""`), fall back to the last two labels as `registered_domain`. |
| `url_analyzer.features` | `FEATURE_NAMES: list[str]`, `extract_features(p) -> dict[str, float]` | **Single source of features** for training and prediction. |
| `url_analyzer.obfuscation` | `check_obfuscation(p) -> list[Finding]` | Percent-encoding, `@` userinfo, repeated separators, non-ASCII/mixed-script/punycode, excess subdomains, brand token in wrong component. |
| `url_analyzer.brand` | `check_brand_similarity(p) -> list[Finding]` | Compares **registered domain only**, edit distance, own implementation. |
| `url_analyzer.domain_checks` | `check_dns(p)`, `check_rdap(p) -> list[Finding]` | Return `unavailable` findings on any failure. |
| `url_analyzer.redirects` | `check_redirects(p) -> list[Finding]` | Obeys `05_SECURITY_RULES.md`. Off by default. |
| `threat_intel.phishtank` / `urlhaus` | `lookup(p, settings) -> ThreatLookup` | Never raises; maps every failure to `unavailable`. |
| `threat_intel.service` | `query_sources(p, settings) -> list[ThreatLookup]` | Adds caching, runs enabled sources, converts to `Finding`s via `to_findings`. |
| `ml_engine.predict` | `predict(p) -> Prediction` | Raises `ModelUnavailable` if artifact missing. Builds the model input row with the same code as training. |
| `url_analyzer.lexical` | `check_lexical(p) -> list[Finding]` | Long URL, many subdomains, IP host, suspicious keywords, `@`; HTTPS as `info` only. Thresholds in `constants.py`. |
| `url_analyzer.defang` | `defang_url(raw) -> str` | `http` -> `hxxp`, dots in the host -> `[.]`. Used for **every** display of a submitted URL. |
| `risk_engine.engine` | `assess(findings) -> Assessment` | Pure function. All numbers in `rules.py`. |
| `analysis.services` | `analyse_url(raw) -> Investigation` | The only orchestrator. Catches per-module errors and records `unavailable` findings. |

## Risk score and level (all numbers live in `risk_engine/rules.py`; tune in Phase 11)
`check_name` is always `<group>.<name>`. Groups: `lexical`, `obfuscation`, `brand`, `intel`, `ml`, `dns`, `rdap`, `redirect`.
Checks only report a **severity**; the engine turns severity into points, so every weight is in one file.

| Group | Points per finding | Group cap |
|---|---|---|
| obfuscation + brand | high 15, medium 8, low 3 | 30 |
| lexical | medium 5, low 2 | 20 |
| ml | 0 below threshold t; above it 30 x (score - t) / (1 - t) | 30 |
| dns + rdap + redirect | high 10, medium 6, low 2 | 20 |
| intel | any `flagged` forces score to at least 90 | n/a |

`info` severity and `clear` findings add 0. Score = sum of capped group points, max 100. Higher = more suspicious.

Level (apply in this order):
1. Any `intel` finding `flagged` -> **High**, score at least 90.
2. Coverage: `checks_total` = findings that are not `not_run`; `checks_completed` = those `flagged` or `clear`. If completed is under half of total -> **Inconclusive**, `score = None`.
3. Score 60 or more -> **High**; 25 to 59 -> **Medium**; 0 to 24 -> **Low observed risk**.
4. If the level would be Low observed risk but an `intel` or `ml` check is `unavailable` -> **Inconclusive** (score still shown).

`breakdown` feeds the points table on screen; `reasons` lists the findings that drove the level. Calibrate weights on the validation set only.

## Database (Django models in `analysis/models.py`)
`Investigation` (id, submitted_url, submitted_at, status, overall_level, summary, model_version) ·
`ParsedURLRecord` (investigation FK, one field per ParsedURL part) ·
`FindingRecord` (investigation FK, check_name, category, status, severity, explanation, evidence JSON, source, checked_at) ·
`ThreatIntelLookupRecord` (investigation FK, source, queried_at, query_status, matched, source_record_id, response_summary JSON) ·
`MLPredictionRecord` (investigation FK, model_name, model_version, predicted_class, score, threshold).
Later: `DomainEnrichmentRecord`, `ReportRecord` (only if needed). Store the original submitted string unchanged.

## Routes
`/` submit · `/analysis/<id>/` result · `/history/` list+search+filters · `/dashboard/` · `/analysis/<id>/report/` (HTML) · `/analysis/<id>/report.json`.
