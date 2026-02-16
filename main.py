import re
from urllib.parse import urlparse

KNOWN_BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft",
    "apple", "netflix", "instagram", "linkedin", "twitter",
    "spotify", "github", "adobe", "bank", "hdfc", "icici", "sbi"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "alert", "reset"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".work", ".gq", ".tk", ".ml"
]

def phishing_score(url):
    score = 0
    reasons = []

    url = url.lower()
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    if re.search(r"\d{1,3}(\.\d{1,3}){3}", url):
        score += 25
        reasons.append("IP address used")

    if "@" in url:
        score += 25
        reasons.append("@ symbol present")

    if "xn--" in domain:
        score += 25
        reasons.append("Punycode detected")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("Suspicious domain extension")

    if any(word in url for word in SUSPICIOUS_WORDS):
        score += 10
        reasons.append("Suspicious keywords")

    if score >= 60:
        verdict = "Phishing"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return score, verdict, reasons


url = input("Enter URL: ")
score, verdict, reasons = phishing_score(url)

print("\nScore:", score)
print("Verdict:", verdict)
print("Reasons:", reasons)

