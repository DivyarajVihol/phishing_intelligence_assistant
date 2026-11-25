"""Constants for URL parsing, validation, and lexical checks."""

DEFAULT_MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
BLOCKED_SCHEMES = (
    "ftp",
    "file",
    "javascript",
    "data",
    "mailto",
    "ssh",
    "telnet",
    "gopher",
)

# Suspicious keyword tokens frequently observed in deceptive URLs
SUSPICIOUS_TOKENS = (
    "account",
    "auth",
    "banking",
    "confirm",
    "credential",
    "ebayisapi",
    "invoice",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "security",
    "signin",
    "submit",
    "support",
    "update",
    "verification",
    "verify",
    "wallet",
    "webscr",
)

# Lexical heuristic thresholds
LEXICAL_MAX_URL_LENGTH = 100
LEXICAL_MAX_SUBDOMAINS = 3

# Well-known brand domains for similarity and impersonation checks
BRAND_DOMAINS = (
    # Indian banks, payment systems, and public services
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "pnbindia.in",
    "bankofbaroda.in",
    "paytm.com",
    "phonepe.com",
    "npci.org.in",
    "irctc.co.in",
    "flipkart.com",
    # Global services, financial, and logistics brands
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "linkedin.com",
    "dropbox.com",
    "adobe.com",
    "chase.com",
    "dhl.com",
    "fedex.com",
    "github.com",
    "yahoo.com",
    "outlook.com",
    "icloud.com",
    "americanexpress.com",
)

# Derived brand tokens reused by obfuscation checks (no duplication)
BRAND_TOKENS = tuple(dict.fromkeys(domain.split(".")[0] for domain in BRAND_DOMAINS))

# Brand similarity length and distance thresholds
BRAND_MIN_LABEL_LEN = 5
BRAND_DIST1_MEDIUM_MIN_LEN = 7
BRAND_DIST2_LOW_MIN_LEN = 8
BRAND_MAX_EDIT_DISTANCE = 2


