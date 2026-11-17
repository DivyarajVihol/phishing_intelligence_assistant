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

