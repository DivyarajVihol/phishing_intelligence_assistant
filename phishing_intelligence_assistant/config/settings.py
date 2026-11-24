"""Django settings for phishing_intelligence_assistant project."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / ".env")

# Core Django settings
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-phishing-assistant-default-dev-key-change-in-env",
)
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("true", "1", "yes")

_allowed_hosts_raw = os.environ.get("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost")
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "apps.analysis",
    "apps.dashboard",
    "apps.reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Database: SQLite via Django ORM
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Cache: Django cache framework with LocMemCache
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "phishing-assistant-cache",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Threat intelligence settings (Phase 7+)
ENABLE_PHISHTANK = os.environ.get("ENABLE_PHISHTANK", "True").lower() in ("true", "1", "yes")
PHISHTANK_APP_KEY = os.environ.get("PHISHTANK_APP_KEY", "")
PHISHTANK_USER_AGENT = os.environ.get("PHISHTANK_USER_AGENT", "phishtank/assistant")

ENABLE_URLHAUS = os.environ.get("ENABLE_URLHAUS", "True").lower() in ("true", "1", "yes")
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "")

# Optional enrichment settings (Phases 12 and 13)
ENABLE_DNS_RDAP = os.environ.get("ENABLE_DNS_RDAP", "False").lower() in ("true", "1", "yes")
ENABLE_REDIRECT_CHECK = os.environ.get("ENABLE_REDIRECT_CHECK", "False").lower() in ("true", "1", "yes")

# Limits and timeouts
EXTERNAL_TIMEOUT_SECONDS = int(os.environ.get("EXTERNAL_TIMEOUT_SECONDS", "5"))
MAX_URL_LENGTH = int(os.environ.get("MAX_URL_LENGTH", "2048"))
LOOKUP_CACHE_TTL_SECONDS = int(os.environ.get("LOOKUP_CACHE_TTL_SECONDS", "3600"))

# Display date and datetime formats
DATE_DISPLAY_FORMAT = "d-M-Y"
DATETIME_DISPLAY_FORMAT = "d-M-Y h:i A"

