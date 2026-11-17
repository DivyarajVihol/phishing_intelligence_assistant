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
