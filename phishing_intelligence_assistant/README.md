# Open-Source Phishing Intelligence and Investigation Assistant

An explainable investigation assistant for suspicious URLs. The app parses URLs, performs lexical and obfuscation checks, executes threat-intelligence lookups (PhishTank, URLhaus), runs ML predictions, and calculates an explainable risk score (0–100) and risk level.

## Tech Stack
- **Backend**: Python 3.12, Django 5.2 LTS, SQLite, LocMemCache
- **URL & ML**: `urllib.parse`, `tldextract`, scikit-learn, pandas, joblib
- **HTTP**: `requests`
- **Frontend**: Django templates, vanilla CSS, vanilla JS

## Setup
1. Create and activate a Python virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
3. Configure environment:
   ```bash
   cp .env.example .env
   ```
4. Run migrations:
   ```bash
   python manage.py migrate
   ```
5. Run the development server:
   ```bash
   python manage.py runserver
   ```

## Running Tests
Run all unit and smoke tests:
```bash
python manage.py test
```

## Security Notice
- Submitted URLs are never fetched or rendered as active links.
- All displays of user-submitted URLs are defanged (`defang_url`).
