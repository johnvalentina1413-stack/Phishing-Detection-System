import re
from urllib.parse import urlparse


# Common words frequently found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "credential",
    "wallet",
    "banking",
    "payment",
    "recover",
    "unlock",
    "suspended",
    "urgent"
]


# URL shortener services
SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "shorturl.at"
]


# TLDs frequently abused in phishing campaigns.
# Their presence alone does NOT mean a website is malicious.
SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq"
]


# Potentially executable file extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".msi",
    ".apk"
]


def analyze_url(url):
    """
    Analyze a URL and return:
    - risk score
    - classification
    - risk level
    - detected phishing indicators
    """

    indicators = []
    score = 0

    # -------------------------------------------------
    # 1. Clean user input
    # -------------------------------------------------

    url = url.strip()

    if not url:
        return {
            "score": 100,
            "classification": "Suspicious",
            "risk_level": "High",
            "indicators": ["No URL was provided"]
        }

    # -------------------------------------------------
    # 2. Check whether the user provided a scheme
    # -------------------------------------------------

    has_scheme = bool(
        re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url
        )
    )

    # If the user enters:
    # www.google.com
    #
    # normalize it to:
    # https://www.google.com
    #
    # This prevents an omitted scheme from being
    # incorrectly treated as HTTP.

    if not has_scheme:
        url = "https://" + url

    # -------------------------------------------------
    # 3. Parse URL
    # -------------------------------------------------

    parsed = urlparse(url)

    hostname = parsed.hostname.lower() if parsed.hostname else ""
    path = parsed.path.lower()
    full_url = url.lower()

    # -------------------------------------------------
    # 4. Validate hostname
    # -------------------------------------------------

    if not hostname:
        return {
            "score": 100,
            "classification": "Suspicious",
            "risk_level": "High",
            "indicators": ["Invalid or malformed URL"]
        }

    # -------------------------------------------------
    # 5. HTTPS check
    # -------------------------------------------------

    # Only penalize HTTP when the user explicitly
    # entered the scheme.
    #
    # Example:
    # www.google.com       -> no HTTPS penalty
    # https://google.com   -> no penalty
    # http://google.com    -> +10

    if has_scheme and parsed.scheme.lower() != "https":
        score += 10
        indicators.append(
            "URL does not use HTTPS"
        )

    # -------------------------------------------------
    # 6. IP address check
    # -------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        score += 25
        indicators.append(
            "URL uses an IP address instead of a domain name"
        )

    # -------------------------------------------------
    # 7. @ symbol check
    # -------------------------------------------------

    if "@" in url:
        score += 25
        indicators.append(
            "URL contains '@' which can hide the real domain"
        )

    # -------------------------------------------------
    # 8. URL length check
    # -------------------------------------------------

    if len(url) > 100:
        score += 10
        indicators.append(
            "Unusually long URL"
        )

    # -------------------------------------------------
    # 9. Suspicious keyword check
    # -------------------------------------------------

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)

    if found_keywords:

        # Maximum 20 points for suspicious keywords
        keyword_score = min(
            len(found_keywords) * 5,
            20
        )

        score += keyword_score

        indicators.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # -------------------------------------------------
    # 10. URL shortener check
    # -------------------------------------------------

    if hostname in SHORTENER_DOMAINS:
        score += 20

        indicators.append(
            "URL uses a URL shortening service"
        )

    # -------------------------------------------------
    # 11. Suspicious TLD check
    # -------------------------------------------------

    if any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):
        score += 15

        indicators.append(
            "Domain uses a frequently abused TLD"
        )

    # -------------------------------------------------
    # 12. Excessive subdomain check
    # -------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 5:
        score += 15

        indicators.append(
            "Domain contains an unusually large number "
            "of subdomains"
        )

    # -------------------------------------------------
    # 13. Multiple hyphens check
    # -------------------------------------------------

    if hostname.count("-") >= 3:
        score += 10

        indicators.append(
            "Domain contains multiple hyphens"
        )

    # -------------------------------------------------
    # 14. Suspicious '..' path pattern
    # -------------------------------------------------

    if ".." in path:
        score += 10

        indicators.append(
            "URL path contains suspicious '..' pattern"
        )

    # -------------------------------------------------
    # 15. Suspicious file extension check
    # -------------------------------------------------

    if any(
        path.endswith(extension)
        for extension in SUSPICIOUS_EXTENSIONS
    ):
        score += 20

        indicators.append(
            "URL points to a potentially executable file"
        )

    # -------------------------------------------------
    # 16. Punycode / IDN domain check
    # -------------------------------------------------

    if "xn--" in hostname:
        score += 15

        indicators.append(
            "Domain uses Punycode, which can be used "
            "in lookalike or homograph attacks"
        )

    # -------------------------------------------------
    # 17. Excessive dots in hostname
    # -------------------------------------------------

    if hostname.count(".") >= 4:
        score += 10

        indicators.append(
            "Domain contains an unusually high number "
            "of dot-separated sections"
        )

    # -------------------------------------------------
    # 18. Final score
    # -------------------------------------------------

    score = min(score, 100)

    # -------------------------------------------------
    # 19. Classification
    # -------------------------------------------------

    if score >= 60:

        classification = "Suspicious"
        risk_level = "High"

    elif score >= 30:

        classification = "Suspicious"
        risk_level = "Medium"

    else:

        classification = "Likely Safe"
        risk_level = "Low"

    # -------------------------------------------------
    # 20. Indicator message
    # -------------------------------------------------

    if not indicators:

        indicators.append(
            "No major phishing indicators detected"
        )

    elif score < 30:

        indicators.append(
            "Only minor security indicators detected; "
            "no strong phishing indicators found"
        )

    # -------------------------------------------------
    # 21. Return analysis result
    # -------------------------------------------------

    return {
        "score": score,
        "classification": classification,
        "risk_level": risk_level,
        "indicators": indicators
    }