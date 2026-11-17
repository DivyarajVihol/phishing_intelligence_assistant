# 02. Tech stack (LOCKED)

## Stack
| Area | Choice |
|---|---|
| Language | Python 3.12 |
| Web framework | Django 5.2 LTS (server-rendered templates) |
| Database | SQLite via Django ORM |
| URL parsing | `urllib.parse` + `tldextract` |
| ML | pandas, NumPy, scikit-learn, joblib |
| HTTP client | `requests` (always with timeouts) |
| Config | `python-dotenv` reading `.env` |
| Cache | Django cache framework, `LocMemCache` |
| Tests | Django test runner: `python manage.py test` |
| Frontend | Django templates, one CSS file, one small JS file. No framework |
| Version control | Git |

`requirements.txt` holds compatible ranges. After the first successful install, pin exact versions (`pip freeze`, keep only these packages and their dependencies).

## Do NOT add (ask first, never assume)
- Frontend: React, Vue, Bootstrap, Tailwind, jQuery, any CDN script or font, any chart library.
- Backend: Django REST Framework, Celery, Redis, PostgreSQL, Docker, async frameworks.
- ML: TensorFlow, PyTorch, XGBoost, LightGBM (Character-Level CNN is out of scope for v1).
- Any new package not in the table. The only pre-approved later additions: `dnspython` (Phase 12), `reportlab` (Phase 15, only if PDF is requested).

## Locked decisions
- Single-user local app. No login in v1.
- `tldextract` must be created with `suffix_list_urls=()` so it uses its bundled suffix list and never fetches over the network at request time.
- Core analysis modules (`url_analyzer`, `ml_engine`, `risk_engine`, `core`) are **plain Python and must not import Django**, so training scripts can reuse them.
- Charts on the dashboard are plain HTML tables and CSS bars.

## Environment variables (`.env.example` lists all)
`DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, `PHISHTANK_APP_KEY`, `PHISHTANK_USER_AGENT`, `URLHAUS_AUTH_KEY`, `ENABLE_PHISHTANK`, `ENABLE_URLHAUS`, `ENABLE_DNS_RDAP`, `ENABLE_REDIRECT_CHECK`, `EXTERNAL_TIMEOUT_SECONDS`, `MAX_URL_LENGTH`, `LOOKUP_CACHE_TTL_SECONDS`.
Read them only in `config/settings.py`. Other code reads `django.conf.settings` (apps) or receives values as arguments (plain-Python modules).

## Commands
- Run: `python manage.py runserver`
- Test: `python manage.py test`
- Migrate: `python manage.py makemigrations && python manage.py migrate`
- Train (Phase 5): `python -m ml.training.train`
