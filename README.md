# Open-Source Phishing Intelligence and Investigation Assistant

An explainable, defensible investigation assistant for suspicious URLs. The assistant analyzes user-submitted URLs through lexical heuristics, obfuscation checks, threat intelligence feeds (PhishTank, URLhaus), and machine learning predictions to produce an explainable risk score (0–100) and risk level.

> **Important**: This tool is an **investigation assistant**, never a "safe/malicious" oracle. A lack of findings or feed matches does not establish that a URL is benign.

---

## Features

- **Lexical Heuristics** (`apps/url_analyzer/lexical.py`):
  - Excessive URL length (> 75 characters)
  - Excessive subdomain nesting (> 3 subdomain levels)
  - Numerical IP address host
  - Sensitive authentication keywords (e.g. login, signin, verify, account)
  - '@' symbol in the authority section
  - Missing HTTPS encryption (plain HTTP scheme)
- **Obfuscation & Deception Heuristics** (`apps/url_analyzer/obfuscation.py`):
  - Percent-encoded characters in hostname or path
  - Userinfo credentials preceding the destination host (`user@host`)
  - Repeated delimiters ('//' in path or '--' in hostname)
  - Non-ASCII characters or punycode (`xn--`) homograph indicators
  - Deep subdomain nesting
  - Recognized brand names in subdomain or path when the registered domain differs
- **Brand Look-Alike Detection** (`apps/url_analyzer/brand.py`):
  - Detects look-alike registered domains against about 32 brands, including major Indian banks and payment services.
- **Threat Intelligence Integrations**:
  - **PhishTank**: Queries phishing submissions and community verification status.
  - **URLhaus**: Queries active malware distribution intelligence (reported strictly as malware intelligence, never conflated with phishing).
- **DNS & Domain-Age (RDAP) Enrichment** (`apps/url_analyzer/domain_checks.py`):
  - Optional DNS record and domain-age (RDAP) checks (OFF by default; enable with `ENABLE_DNS_RDAP=True` in `.env`).
- **Machine Learning Engine**: Domain-level classifier (model v2) trained on the PhiUSIIL dataset plus PhishTank verified phishing (shared-hosting domains excluded from training), with the decision threshold chosen on validation so about 90% of what it flags is truly phishing.
- **Explainable Risk Engine**:
  - Deterministic 0–100 risk score and categorical tiers (`High risk`, `Medium risk`, `Low observed risk`, `Inconclusive`).
  - Transparent point breakdown by source category and completed check coverage.
  - Confirmed threat feed matches force the score to ≥ 90.
- **Investigation History**: Search and multi-facet filtering (URL/domain search, date range, risk tier, threat feed matches, status, ML classification) with pagination.
- **Metrics Dashboard**: 30-day activity trends, risk distribution, top registered domains and TLDs, check availability, and ML prediction splits.
- **Investigation Reports**: Downloadable PDF reports (`investigation-report-<id>.pdf`, generated via `reportlab` with defanged URLs and no hyperlinks) and machine-readable JSON exports with complete evidence records.

---

## Tech Stack

- **Backend**: Python 3.14.x (developed and tested on Python 3.14.4), Django 5.2 LTS, SQLite, LocMemCache, `reportlab==5.1.1` (PDF).
- **Analysis & ML**: `urllib.parse`, `tldextract`, scikit-learn, pandas 2.3.x, joblib, `dnspython==2.9.2` (DNS).
- **HTTP & Config**: `requests`, `python-dotenv`.
- **Frontend**: Django templates, vanilla CSS (custom design tokens), vanilla JavaScript. No external CDNs or UI libraries.

---

## Windows Setup

1. **Navigate to the project folder**:
   The project directory sits inside the git repository. Ensure you `cd` into the project folder first:
   ```powershell
   cd phishing_intelligence_assistant
   ```

2. **Create and activate a virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```
   > **Windows Policy Note**: Direct invocation of `pip.exe` may be restricted by Windows application-control policies on some machines. Always use `python -m pip`.
   > **Pandas Version**: Pandas must remain on version 2.3.x (do not upgrade to 3.x, which is restricted by policy).

4. **Configure environment variables**:
   ```powershell
   Copy-Item .env.example .env
   ```
   Open `.env` in an editor and configure the variables (see below).

5. **Run database migrations**:
   ```powershell
   python manage.py migrate
   ```

6. **Start the development server**:
   ```powershell
   python manage.py runserver
   ```
   Visit `http://127.0.0.1:8000/` in your browser.

---

## Environment Variables (`.env`)

Configure the following variables in your `.env` file (never commit real secrets or keys):

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DJANGO_SECRET_KEY` | `change-me` | Secret key for Django cryptographic signing |
| `DJANGO_DEBUG` | `True` | Set to `False` in production |
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Comma-separated list of permitted hostnames |
| `ENABLE_PHISHTANK` | `True` | Enable PhishTank threat intelligence lookups |
| `PHISHTANK_APP_KEY` | *(empty)* | Optional application key for PhishTank API |
| `PHISHTANK_USER_AGENT` | `phishtank/assistant` | Descriptive User-Agent header for PhishTank queries |
| `ENABLE_URLHAUS` | `True` | Enable URLhaus malware intelligence lookups |
| `URLHAUS_AUTH_KEY` | *(empty)* | Required Auth-Key for URLhaus API lookups |
| `ENABLE_DNS_RDAP` | `False` | Feature flag for DNS/RDAP enrichment (optional phase) |
| `ENABLE_REDIRECT_CHECK` | `False` | Reserved for the optional redirect checker (Phase 13, not built yet); currently has no effect. |
| `EXTERNAL_TIMEOUT_SECONDS` | `5` | Network timeout in seconds for outbound calls |
| `MAX_URL_LENGTH` | `2048` | Maximum accepted length for submitted URLs |
| `LOOKUP_CACHE_TTL_SECONDS` | `3600` | In-memory lookup cache TTL in seconds |

### Obtaining Threat Intelligence API Keys

- **PhishTank**: Lookups work without an API key provided a descriptive, unique `PHISHTANK_USER_AGENT` is configured. An application key is optional, and new user registration on PhishTank may be temporarily closed.
- **URLhaus**: Register a free account at [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/). After logging in, create a profile first, then generate the `Auth-Key` inside your profile. If this key is omitted, URLhaus lookups will display as "Not configured".

---

## Dataset Preparation & Model Training

Datasets are not stored in git. To train or retrain the machine learning model:

1. **Place the raw datasets**:
   - Obtain the PhiUSIIL Phishing URL Dataset CSV (required) and save it to:
     `ml/data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`
   - Download the PhishTank verified-online feed (`https://data.phishtank.com/data/online-valid.csv`, using a descriptive `User-Agent`; PhishTank may answer HTTP 429 if asked too often) and save it as:
     `ml/data/raw/phishtank_online-valid.csv`
   - If `ml/data/raw/phishtank_online-valid.csv` is missing when preparing data, `prepare_data` skips it and continues using only the PhiUSIIL dataset (with `recent_test` having 0 domains).

2. **Clean and prepare dataset splits**:
   ```powershell
   python -m ml.training.prepare_data
   ```
   This normalizes URLs, removes parse failures, audits domain leakage, removes conflicts, and deterministically partitions rows into train, validation, and test splits at `ml/data/processed/dataset.csv`.

3. **Train, evaluate, and save artifacts**:
   ```powershell
   python -m ml.training.train
   ```
   This trains candidate models, selects the best performer by PR-AUC, tunes the decision threshold on validation data (so about 90% of what it flags is truly phishing), and outputs active v2 artifacts to `ml/artifacts/`:
   - `model-v2.joblib`: Serialized scikit-learn pipeline (trained on PhiUSIIL plus PhishTank verified phishing, with shared-hosting domains excluded).
   - `model-v2.json`: Metadata, threshold, feature names, and performance metrics.
   - `evaluation-v2.md`: Detailed evaluation report including confusion matrix and error analysis.
   - `model-v1.joblib`, `model-v1.json`, `evaluation.md`: Original v1 artifacts kept for history.

---

## Running Tests

Execute the automated test suite across all apps and ML modules:

```powershell
python manage.py test apps ml
```

All network calls are strictly mocked in tests, and tests are forced to run with the network flags off. Automated tests never connect to external servers or feeds.

---

## Project Structure

```
phishing_intelligence_assistant/
├── apps/
│   ├── analysis/       # URL submission, results, history views, models & forms
│   ├── core/           # Shared dataclasses and typing contracts (no Django dependencies)
│   ├── dashboard/      # Metrics aggregation and dashboard view
│   ├── ml_engine/      # ML inference and feature row construction
│   ├── reports/        # Report builder, HTML report view, PDF and JSON exports
│   ├── risk_engine/    # Heuristic scoring rules and risk assessment engine
│   ├── threat_intel/   # PhishTank and URLhaus connectors and caching service
│   └── url_analyzer/   # URL parser, lexical, obfuscation and brand look-alike checks, optional DNS and domain-age checks
├── config/             # Django project settings, URLs, and WSGI configuration
├── docs/               # Architecture, specification, UI guidelines, and test reports
├── ml/
│   ├── artifacts/      # Trained model artifacts and evaluation markdown
│   ├── data/           # Raw and processed training datasets (gitignored)
│   └── training/       # Data preparation, training, and evaluation scripts
├── static/             # Vanilla CSS design tokens and vanilla JavaScript
└── templates/          # Base layout and application templates
```

---

## Security Architecture

- **NEVER-OPEN Rule**: Submitted URLs are never fetched, visited, or converted to clickable `<a href>` links.
- **Defanged Display**: All user-submitted URLs and hostnames are rendered strictly in plain text using `defang_url` (e.g. `hxxps://example[.]com`).
- **Resilient Network Handling**: All outbound requests enforce strict timeouts (`EXTERNAL_TIMEOUT_SECONDS`). Feeds that timeout or error report as "Unavailable", never "no match".
- **Separated Evidence**: Threat intelligence matches, heuristic findings, ML predictions, and unavailable checks are displayed in distinct sections.
- **Secret Isolation**: Credentials and API keys are read only from environment variables, never logged or exposed.
- **Minimal Outbound Data**: When the optional DNS/RDAP checks are enabled, the registered domain (not the full URL) is sent to the DNS resolver and to `rdap.org`; PhishTank and URLhaus always receive the submitted URL, as the Submit page notice says.
- **Offline Testing**: Automated test suites are completely isolated from live network resources.

---

## Known Limitations

- **v2 ML Model Scope**: The active v2 model evaluates lexical features derived exclusively from the registered domain name (mostly an ending signal, and weak on `.com`). At its strict threshold, it catches about 40% of phishing on test data and about 72% of recent PhishTank domains. It cannot identify path-based phishing on shared hosting platforms (e.g. `vercel.app`, `firebaseapp.com`), and serves only as a supporting indicator contributing at most 30 points to the risk score.
- **Popular Domain False Positives**: The v2 model still flags `google.com` at about 0.86 (adding about 12 points), which is why ML adds at most 30 points and never decides the risk level alone.
- **Threat Intelligence Coverage**: Lookups cover only URLs previously identified and listed in PhishTank or URLhaus. A "no match" finding indicates absence from the database, not that a URL is benign. URLhaus represents malware intelligence, not phishing.
- **Optional Modules**: Phase 12 (optional DNS record and RDAP domain-age enrichment) is built but OFF by default (`ENABLE_DNS_RDAP=False`). Phase 13 (controlled HTTP redirect checker) is NOT built yet.
- **Timezone**: All displayed analysis and query timestamps are normalized and rendered in UTC.
- **History Date Filtering**: History date input pickers conform to the host browser's regional date format.

---

## Acknowledgements and Data Sources

- **PhiUSIIL Phishing URL Dataset**: Used as training data for the domain-level machine learning model.
- **PhishTank**: Community-verified phishing feed lookups.
- **URLhaus by abuse.ch**: Malware distribution intelligence.
