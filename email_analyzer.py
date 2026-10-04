import re
from urllib.parse import urlparse


# Words commonly associated with phishing and social engineering
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "verification",
    "confirm",
    "password",
    "login",
    "account",
    "suspended",
    "blocked",
    "security alert",
    "click here",
    "update your account",
    "reset your password",
    "payment",
    "bank",
    "credit card",
    "debit card",
    "otp",
    "one time password",
    "winner",
    "prize",
    "claim",
    "refund"
]


def extract_urls(text):
    """
    Extract URLs from email text.
    """
    pattern = r"https?://[^\s<>\"]+"
    return re.findall(pattern, text)


def analyze_email(email_text):
    """
    Analyze email content and return a phishing risk score.
    """

    indicators = []
    score = 0

    text = email_text.strip()
    lower_text = text.lower()

    if not text:
        return {
            "score": 0,
            "classification": "Unknown",
            "risk_level": "Unknown",
            "indicators": ["No email content provided"]
        }

    # -------------------------------------------------
    # 1. Check suspicious keywords
    # -------------------------------------------------
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_text:
            found_keywords.append(keyword)

    if found_keywords:
        keyword_score = min(len(found_keywords) * 5, 30)
        score += keyword_score

        indicators.append(
            "Suspicious language detected: "
            + ", ".join(found_keywords)
        )

    # -------------------------------------------------
    # 2. Check urgency
    # -------------------------------------------------
    urgency_words = [
        "urgent",
        "immediately",
        "within 24 hours",
        "act now",
        "last chance",
        "account will be closed",
        "account will be suspended"
    ]

    found_urgency = [
        word for word in urgency_words
        if word in lower_text
    ]

    if found_urgency:
        score += 15
        indicators.append(
            "Urgency or pressure tactics detected"
        )

    # -------------------------------------------------
    # 3. Check requests for sensitive information
    # -------------------------------------------------
    sensitive_requests = [
        "enter your password",
        "provide your password",
        "send your password",
        "enter your otp",
        "share your otp",
        "credit card number",
        "debit card number",
        "bank account number",
        "cvv",
        "security code"
    ]

    found_sensitive_requests = [
        phrase for phrase in sensitive_requests
        if phrase in lower_text
    ]

    if found_sensitive_requests:
        score += 25
        indicators.append(
            "Email requests sensitive personal or financial information"
        )

    # -------------------------------------------------
    # 4. Extract URLs
    # -------------------------------------------------
    urls = extract_urls(text)

    if urls:
        indicators.append(
            f"Email contains {len(urls)} link(s)"
        )

        # Analyze basic URL characteristics
        for url in urls:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            if parsed.scheme != "https":
                score += 10
                indicators.append(
                    "Email contains a link that does not use HTTPS"
                )

            if "@" in url:
                score += 15
                indicators.append(
                    "Email contains a URL with '@'"
                )

            if len(url) > 100:
                score += 10
                indicators.append(
                    "Email contains an unusually long URL"
                )

            if hostname and re.match(
                r"^(?:\d{1,3}\.){3}\d{1,3}$",
                hostname
            ):
                score += 20
                indicators.append(
                    "Email contains a link using an IP address"
                )

    # -------------------------------------------------
    # 5. Check for fake verification/account language
    # -------------------------------------------------
    verification_phrases = [
        "verify your account",
        "confirm your identity",
        "verify your identity",
        "update your account",
        "restore your account",
        "unlock your account"
    ]

    if any(phrase in lower_text for phrase in verification_phrases):
        score += 15
        indicators.append(
            "Account verification or recovery request detected"
        )

    # -------------------------------------------------
    # Keep score between 0 and 100
    # -------------------------------------------------
    score = min(score, 100)

    # -------------------------------------------------
    # Classification
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

    if not indicators:
        indicators.append(
            "No major phishing indicators detected"
        )

    return {
        "score": score,
        "classification": classification,
        "risk_level": risk_level,
        "indicators": indicators
    }