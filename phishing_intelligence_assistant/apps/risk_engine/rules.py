"""Named constants, weights, group caps, and band thresholds for risk scoring."""

# Group identifiers
GROUP_OBFUSCATION_BRAND = "obfuscation + brand"
GROUP_LEXICAL = "lexical"
GROUP_ML = "ml"
GROUP_DNS_RDAP_REDIRECT = "dns + rdap + redirect"
GROUP_INTEL = "intel"

# Points by severity for Obfuscation + Brand group
OBFUSCATION_BRAND_HIGH_POINTS = 15
OBFUSCATION_BRAND_MEDIUM_POINTS = 8
OBFUSCATION_BRAND_LOW_POINTS = 3
OBFUSCATION_BRAND_INFO_POINTS = 0
OBFUSCATION_BRAND_CAP = 30

# Points by severity for Lexical group
LEXICAL_HIGH_POINTS = 5
LEXICAL_MEDIUM_POINTS = 5
LEXICAL_LOW_POINTS = 2
LEXICAL_INFO_POINTS = 0
LEXICAL_CAP = 20

# Points by severity for DNS + RDAP + Redirect group
DNS_RDAP_REDIRECT_HIGH_POINTS = 10
DNS_RDAP_REDIRECT_MEDIUM_POINTS = 6
DNS_RDAP_REDIRECT_LOW_POINTS = 2
DNS_RDAP_REDIRECT_INFO_POINTS = 0
DNS_RDAP_REDIRECT_CAP = 20

# ML scoring weights and cap
ML_CAP = 30.0
ML_BELOW_THRESHOLD_POINTS = 0.0

# Intel override minimum score
INTEL_OVERRIDE_MIN_SCORE = 90

# Overall score bounds
MIN_SCORE = 0
MAX_SCORE = 100

# Risk level score bands
BAND_LOW_MAX = 24
BAND_MEDIUM_MIN = 25
BAND_MEDIUM_MAX = 59
BAND_HIGH_MIN = 60

# Coverage threshold ratio
MIN_COVERAGE_RATIO = 0.5

# Assessment level identifiers (matching apps.core.types.Assessment.level)
LEVEL_HIGH = "high"
LEVEL_MEDIUM = "medium"
LEVEL_LOW_OBSERVED = "low_observed"
LEVEL_INCONCLUSIVE = "inconclusive"

# UI/Report display wording
WORDING_HIGH_RISK = "High risk"
WORDING_MEDIUM_RISK = "Medium risk"
WORDING_LOW_OBSERVED_RISK = "Low observed risk"
WORDING_INCONCLUSIVE = "Inconclusive"
