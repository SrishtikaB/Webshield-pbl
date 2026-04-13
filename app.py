from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)



KNOWN_BRANDS = [
    "google","facebook","amazon","paypal","microsoft",
    "apple","netflix","instagram","linkedin","twitter",
    "spotify","github","adobe","bank","hdfc","icici","sbi"
]

SUSPICIOUS_WORDS = [
    "login","verify","secure","update","account",
    "bank","confirm","password","signin","alert","reset"
]

SUSPICIOUS_TLDS = [
    ".xyz",".top",".gq",".tk",".ml"
]



def analyze_url(url):
    score = 0
    reasons = []

    url = url.lower().strip()
    parsed = urlparse(url)

    domain = parsed.netloc if parsed.netloc else parsed.path

    
    length = len(url)
    dots = url.count(".")
    hyphens = domain.count("-")
    has_https = url.startswith("https")
    has_ip = bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url))

    

    # 1. IP Address
    if has_ip:
        score += 25
        reasons.append("Uses IP address instead of domain")

    # 2. @ Symbol
    if "@" in url:
        score += 25
        reasons.append("Contains @ symbol")

    # 3. Punycode
    if "xn--" in domain:
        score += 25
        reasons.append("Uses encoded domain (punycode)")

    # 4. Suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append("Suspicious domain extension")

    # 5. Brand + phishing keyword
    for brand in KNOWN_BRANDS:
        if brand in domain:
            for word in SUSPICIOUS_WORDS:
                if word in url:
                    score += 20
                    reasons.append("Brand impersonation attempt")
                    break

    # 6. Suspicious keywords
    if any(word in url for word in SUSPICIOUS_WORDS):
        score += 10
        reasons.append("Suspicious keywords detected")

    # 7. Too many dots
    if dots > 4:
        score += 8
        reasons.append("Too many subdomains")

    # 8. Long domain
    if len(domain) > 25:
        score += 8
        reasons.append("Long domain name")

    # 9. Hyphen usage
    if hyphens > 0:
        score += 8
        reasons.append("Hyphen used in domain")

    # 10. No HTTPS
    if not has_https:
        score += 10
        reasons.append("Not using HTTPS")
  
  

    if score >= 60:
        verdict = "Fake"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    # Risk percentage
    risk = min(score, 100)

    

    return {
        "url": url,
        "domain": domain,
        "length": length,
        "dots": dots,
        "hyphens": hyphens,
        "https": has_https,
        "score": score,
        "risk": risk,
        "result": verdict,
        "reasons": reasons
    }



@app.route("/check", methods=["POST"])
def check():
    data = request.json
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)

    return jsonify(result)


if __name__ == "__main__":
    app.run()
