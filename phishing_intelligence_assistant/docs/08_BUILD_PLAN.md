# 08. Build plan: prompts to paste into Antigravity, in order

How to use: one phase = one Antigravity task. Paste the prompt, review the diff, run `python manage.py test`, commit as `Phase N: ...`, then move on. Phases 0 to 10 complete the MVP.

Every prompt below implicitly starts with:
> Follow `AGENTS.md` and the docs named below. Touch only the listed files. No new dependencies. Run the tests, report files changed and results, then STOP.

---

## Phase 0. Project foundation
**Read:** 02, 03, 07. **Files:** `manage.py`, `config/*`, `apps/core/types.py`, empty app packages per the tree (only those needed through Phase 10), `templates/base.html`, `static/css/style.css`, `static/js/app.js`, `README.md`.
> Create the Django project `config` and the package skeleton from `docs/03_ARCHITECTURE.md` (Django apps only for `analysis`; the rest plain packages with `__init__.py`). In `config/settings.py` load `.env` with python-dotenv and expose every variable listed in `02_TECH_STACK.md` with safe defaults; use SQLite and LocMemCache. Write `apps/core/types.py` with the dataclasses exactly as in `03_ARCHITECTURE.md`. Create `base.html` and a `style.css` containing only the design tokens and the layout/header from `06_UI_GUIDELINES.md`. Add a placeholder `/` page that renders `base.html`. Add one smoke test that `/` returns 200.

**Done when:** `runserver` shows the page; `manage.py test` passes.

## Phase 1. URL validation and parsing
**Read:** 03, 05, 07. **Files:** `apps/url_analyzer/parser.py`, `defang.py`, `apps/url_analyzer/constants.py`, `apps/url_analyzer/tests/test_parser.py`, `test_defang.py`.
> Implement `parse_url(raw, max_len)` and `InvalidURLError` per the contract. Use `urllib.parse` and `tldextract.TLDExtract(suffix_list_urls=())`. No Django imports. Tests: empty, whitespace, too long, `ftp://`, no scheme, port, query, fragment, IP host, unusual subdomains, IDN/punycode, and both known-answer URLs from `07_CODING_RULES.md`.

> Also implement `defang_url(raw) -> str` in `defang.py` (`http` -> `hxxp`, dots in the host -> `[.]`, rest unchanged). Tests: https, http, IP host, userinfo, IDN, no scheme; output never starts with `http`.

**Done when:** all parser and defang tests pass and the original string is never modified.

## Phase 2. Lexical features
**Read:** 03, 04, 07. **Files:** `apps/url_analyzer/features.py`, `lexical.py`, `apps/url_analyzer/constants.py` (suspicious tokens, thresholds), `apps/url_analyzer/tests/test_features.py`, `test_lexical.py`.
> Implement `FEATURE_NAMES` and `extract_features(parsed)` returning a float for every name, in the feature groups listed in `04_ML_DATA_SPEC.md`. Put the suspicious-token list in `constants.py`. No Django imports. Tests: each feature on a hand-checked URL, determinism, no NaN, same keys for every input.
> Also implement `check_lexical(parsed) -> list[Finding]` in `lexical.py` (check_name `lexical.<name>`): long URL, many subdomains, IP host, suspicious keywords, `@`, and HTTPS as `info` only. Each sets a severity and an explanation that says it is a warning, not proof. Thresholds live in `constants.py`. Tests: a clean URL gives no warnings, each rule fires on a matching URL.

## Phase 3. Obfuscation and homograph checks
**Read:** 01, 03, 07. **Files:** `apps/url_analyzer/obfuscation.py`, `apps/url_analyzer/tests/test_obfuscation.py`.
> Implement `check_obfuscation(parsed) -> list[Finding]` covering: percent-encoding, `@` userinfo mismatch, repeated separators, non-ASCII / mixed-script / punycode hostnames (warning only, IDNs can be legitimate), excessive subdomains, and a brand name appearing in a subdomain/path while the registered domain differs. Each finding explains the exact feature and says it is a warning, not proof. Tests include both known-answer URLs and a clean URL that must produce no findings.

## Phase 4. Dataset preparation (needs your manual download first)
**Read:** 04, 07. **Files:** `ml/training/prepare_data.py`, `ml/data/README.md`, `ml/training/tests/test_prepare_data.py`.
> Write a reproducible script that follows "Preparation" in `04_ML_DATA_SPEC.md`: load from `ml/data/raw/`, clean, parse, dedupe, print class balance and per-step row counts, create grouped train/validation/test splits plus a time-based test, and write `ml/data/processed/dataset.csv`. Add a README table for sources. Do not download anything; read local files only. Test the splitting logic on a tiny synthetic frame (no domain in two splits).

**Review:** read the printed counts. Check benign URLs have paths like the phishing ones (structure-leak warning).

## Phase 5. Train and evaluate (human review stop)
**Read:** 04, 07. **Files:** `ml/training/train.py`, `ml/training/evaluate.py`, `ml/artifacts/*`, `apps/ml_engine/predict.py` (only the `build_row` function).
> Implement `build_row(parsed)` in `ml_engine/predict.py` and use it from `train.py`. Train the Logistic Regression + char TF-IDF baseline and the Random Forest on numeric features, evaluate both per `04_ML_DATA_SPEC.md` on validation, test and time-based test, choose the threshold on validation only, save `model-v1.joblib`, `model-v1.json` and `evaluation.md` with error analysis.

**Review:** if scores look near-perfect, ask the AI to investigate leakage before moving on.

## Phase 6. Model inference in the app
**Read:** 03, 04. **Files:** `apps/ml_engine/predict.py`, `apps/ml_engine/tests/test_predict.py`.
> Implement `predict(parsed) -> Prediction` loading the artifact once (module-level cache) and `ModelUnavailable` when the file is missing. Tests: benign-looking and phishing-looking URL return a valid Prediction, missing artifact raises `ModelUnavailable`, and a **parity test** that `build_row` gives the same columns the model was trained with.

## Phase 7. Threat-intelligence connectors
**Read:** 03, 05, 07. **Files:** `apps/threat_intel/phishtank.py`, `urlhaus.py`, `service.py`, `apps/threat_intel/tests/test_connectors.py`.
> Implement PhishTank (POST `https://checkurl.phishtank.com/checkurl/`, `format=json`, descriptive User-Agent) and URLhaus (POST `https://urlhaus-api.abuse.ch/v1/url/`, `Auth-Key` header) lookups per the contract. Add caching and `to_findings` in `service.py`. All failures become `unavailable`; missing key becomes `not_configured`; never use "safe" wording. Tests mock `requests` for: match, no match, timeout, rate limit/509, invalid key, malformed JSON, and a cache hit. No real network calls.

## Phase 8. Risk engine
**Read:** 01, 03. **Files:** `apps/risk_engine/rules.py`, `engine.py`, `apps/risk_engine/tests/test_engine.py`.
> Implement `assess(findings)` exactly per "Risk score and level" in `03_ARCHITECTURE.md`: severity to points by group, group caps, ML points from score vs threshold, the intel override (score at least 90, High), coverage, level bands, and return `Assessment` with `score`, `breakdown`, coverage counts, `summary`, `reasons`. Every weight, cap and band edge is a constant in `rules.py`. Summary text follows the wording rules and never says "safe". Tests: each group's points and cap, ML points below/at/above threshold, intel override beating low points, low coverage gives Inconclusive with no score, unavailable intel gives Inconclusive, and the worked example (brand high 15 + keyword medium 5 + ML 0.87 at threshold 0.62 gives about 40, Medium).

## Phase 9. Orchestrator and persistence
**Read:** 03, 05, 07. **Files:** `apps/analysis/models.py`, `services.py`, migrations, `apps/analysis/tests/test_services.py`.
> Implement the models from `03_ARCHITECTURE.md` and `analyse_url(raw)`: parse, run local checks, ML prediction, threat lookups, assess, save. Each module is wrapped so its failure becomes an `unavailable` finding and the rest continue. Tests mock threat lookups and cover: full success, intel unavailable, model missing, invalid URL (raises, saves nothing).

## Phase 10. Submit and result pages (MVP complete)
**Read:** 06, 05. **Files:** `apps/analysis/forms.py`, `views.py`, `urls.py`, `config/urls.py`, `apps/analysis/templatetags/defang.py`, `templates/analysis/*`, `static/css/style.css`, `static/js/app.js`, `apps/analysis/tests/test_views.py`.
> Build the Submit and Result pages exactly per `06_UI_GUIDELINES.md` (section order, components, wording, limitation notice, third-party lookup notice, the URL always shown through a `defang` template filter wrapping `defang_url`, never a link; risk score, points table and coverage line shown). Views stay thin. Tests: GET/POST, invalid input message, result page shows each evidence section and the "Unavailable" section, the **no-open check** from `05_SECURITY_RULES.md` at every risk level.

**MVP check:** run three URLs by hand (benign, suspicious, known phishing) and with the network off.

## Phase 11. History with search and filters
**Read:** 03, 06. **Files:** `apps/analysis/views.py`, `urls.py`, `templates/analysis/history.html`, tests.
> Add `/history/` with search by URL/domain and filters (date range, risk level, source match, status, model result) per `03_ARCHITECTURE.md`. Paginate 25 per page. URLs in the table are defanged plain text, never links.

## Phase 12. Brand similarity, DNS and RDAP (optional enrichment)
**Read:** 03, 05. **Files:** `apps/url_analyzer/brand.py`, `domain_checks.py`, `constants.py`, tests, `requirements.txt` (adds `dnspython` only), `analysis/services.py` (wiring only).
> Implement edit-distance brand similarity on the registered domain only, using a list of about 30 well-known brand domains (include major Indian banks and payment services) in `constants.py`; show me the list for review. Add DNS (A/AAAA/MX/NS) and RDAP creation date via `rdap.org` per `05_SECURITY_RULES.md`, gated by `ENABLE_DNS_RDAP`. Missing or hidden data is "unavailable", never an error. Mock all network in tests.

## Phase 13. Controlled redirect checker (high risk, review carefully)
**Read:** 05. **Files:** `apps/url_analyzer/redirects.py`, tests, `analysis/services.py` (wiring only).
> Implement `check_redirects` satisfying every rule in "Redirect checker" in `05_SECURITY_RULES.md`. Off by default. Hops are shown defanged and the user is never sent anywhere. Tests must prove blocking of: `127.0.0.1`, `localhost`, `10.x`, `192.168.x`, `169.254.169.254`, IPv6 loopback, a redirect hop to a private IP, and a hostname that resolves to a private IP.

## Phase 14. Dashboard
**Read:** 01, 06. **Files:** `apps/dashboard/*`, `templates/dashboard/*`, `static/css/style.css`, tests.
> Build these metrics (total analyses, risk distribution, PhishTank and URLhaus matches separately, activity over time, top domains/TLDs, check availability, ML prediction distribution) using ORM aggregation, HTML tables and CSS bars. Add a note that charts describe stored investigations, not real-world prevalence. Tests use known records and check the counts.

## Phase 15. Reports
**Read:** 01, 06. **Files:** `apps/reports/*`, `templates/reports/*`, tests.
> HTML report page (print-friendly) and JSON download with every section listed under "Investigation report contents" (title, ID, time, URL and components, assessment, local findings, enrichment if run, PhishTank/URLhaus status with IDs and times, ML model/version/score, unavailable checks, limitations, suggested next steps). URLs are defanged; JSON has `submitted_url_defanged` and `submitted_url_raw` (data only). PDF only if I ask.

## Phase 16. System testing and documentation (you lead, AI assists)
**Files:** `README.md`, `docs/TEST_REPORT.md`, tests.
> Add failure-scenario tests (all intel down, model missing, malformed input). Write the README (setup, env vars, how to train, how to run, known limitations). Draft `TEST_REPORT.md` with tables for benign, suspicious-but-benign, known phishing, URLhaus malware, unseen URLs and service-failure cases; leave results blank for me to fill from manual runs.

---

## If Antigravity goes off track
- It touched files outside the list: `git checkout -- <file>` and re-run the prompt with "Only touch: ..." repeated.
- It added a dependency or framework: revert and point it at `docs/02_TECH_STACK.md`.
- Code is getting long: point it at `docs/07_CODING_RULES.md` size limits and ask for the smallest implementation.
