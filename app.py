import math
import re
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft",
    "apple", "netflix", "instagram", "linkedin", "twitter",
    "spotify", "github", "adobe", "bank", "hdfc", "icici", "sbi",
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "password", "signin", "alert", "reset",
]

LOGIN_PATH_WORDS = ["login", "signin", "account", "verify", "auth", "wp-login"]

SUSPICIOUS_TLDS = [".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".ga", ".work", ".click"]
TRUSTED_TLDS = [".gov", ".edu", ".org"]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly",
]

STANDARD_PORTS = {"80", "443"}

VERDICT_THRESHOLDS = {"fake": 40, "suspicious": 15}
THREAT_LEVEL_THRESHOLDS = {"High": 40, "Medium": 15}


# ---------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------
def shannon_entropy(text):
    if not text:
        return 0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------
# Build context
# ---------------------------------------------------------------------
class Context:
    pass


def build_context(raw_url):
    url = raw_url.lower().strip()
    parse_failed = False
    try:
        candidate = url if "://" in url else "http://" + url
        parsed = urlparse(candidate)
        if not parsed.netloc:
            parse_failed = True
    except Exception:
        parsed = None
        parse_failed = True

    ctx = Context()
    ctx.url = url
    ctx.parsed = parsed
    ctx.domain = (parsed.netloc if parsed and parsed.netloc else (parsed.path if parsed else "")) or ""
    ctx.parse_failed = parse_failed
    ctx.length = len(url)
    ctx.dots = url.count(".")
    ctx.hyphens = ctx.domain.count("-")
    ctx.has_https = url.startswith("https")
    ctx.has_ip = bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url))
    return ctx


def is_likely_valid_url(ctx):
    if ctx.parse_failed:
        return False
    if not ctx.domain:
        return False
    if ctx.has_ip:
        return True
    if "." not in ctx.domain:
        return False

    labels = ctx.domain.split(".")
    tld = labels[-1]
    if not re.fullmatch(r"[a-zA-Z]{2,24}", tld):
        return False

    valid_label = re.compile(r"^[a-zA-Z0-9-]{1,63}$")
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-") or not valid_label.match(label):
            return False
    return True


# ---------------------------------------------------------------------
# Rules -> each returns (points, reason) or None
# ---------------------------------------------------------------------
def rule_ip(ctx):
    return (25, "Uses IP address instead of domain") if ctx.has_ip else None


def rule_https(ctx):
    return (10, "Website is not using HTTPS") if not ctx.has_https else None


def rule_at_symbol(ctx):
    return (25, "'@' symbol hides actual destination") if "@" in ctx.url else None


def rule_punycode(ctx):
    return (25, "Possible Unicode homograph attack") if "xn--" in ctx.domain else None


def rule_suspicious_tld(ctx):
    if any(ctx.domain.endswith(t) for t in SUSPICIOUS_TLDS):
        return (15, "Uses suspicious domain extension")
    return None


def rule_long_url(ctx):
    return (8, "Very long URL detected") if ctx.length > 75 else None


def rule_long_domain(ctx):
    return (8, "Long domain name detected") if len(ctx.domain) > 25 else None


def rule_many_dots(ctx):
    return (8, "Excessive subdomains detected") if ctx.dots > 4 else None


def rule_hyphens(ctx):
    return (8, "Domain contains multiple hyphens") if ctx.hyphens > 1 else None


def rule_shortener(ctx):
    if any(s in ctx.domain for s in URL_SHORTENERS):
        return (15, "Uses URL shortening service")
    return None


def rule_login_path(ctx):
    path = (ctx.parsed.path if ctx.parsed else "").lower()
    if any(w in path for w in LOGIN_PATH_WORDS):
        return (10, "Contains login/account related path")
    return None


def rule_suspicious_words(ctx):
    if any(w in ctx.url for w in SUSPICIOUS_WORDS):
        return (10, "Phishing keywords detected")
    return None


def rule_brand_impersonation(ctx):
    labels = ctx.domain.split(".")
    for brand in KNOWN_BRANDS:
        for label in labels:
            if brand in label and label != brand:
                if any(w in ctx.url for w in SUSPICIOUS_WORDS):
                    return (20, "Possible brand impersonation")
    return None


def rule_digit_heavy(ctx):
    digit_count = sum(c.isdigit() for c in ctx.domain)
    return (6, "Excessive numeric characters") if digit_count >= 4 else None


def rule_special_chars(ctx):
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789:/?.=&-_~%#@")
    special_count = sum(1 for c in ctx.url if c not in allowed)
    return (6, "Excessive special symbols") if special_count > 3 else None


def rule_encoded_chars(ctx):
    return (8, "Encoded URL characters found") if re.search(r"%[0-9a-fA-F]{2}", ctx.url) else None


def rule_double_slash_path(ctx):
    path = ctx.parsed.path if ctx.parsed else ""
    return (6, "Suspicious URL structure") if "//" in path else None


def rule_query_params(ctx):
    query = ctx.parsed.query if ctx.parsed else ""
    if query and len(query.split("&")) > 3:
        return (6, "Excessive query parameters")
    return None


def rule_uncommon_port(ctx):
    port = ctx.parsed.port if ctx.parsed else None
    if port and str(port) not in STANDARD_PORTS:
        return (8, "Uses uncommon network port")
    return None


def rule_multi_keywords(ctx):
    count = sum(1 for w in SUSPICIOUS_WORDS if w in ctx.url)
    return (10, "Multiple phishing keywords detected") if count >= 2 else None


def rule_domain_starts_digit(ctx):
    return (5, "Domain starts with numeric value") if ctx.domain and ctx.domain[0].isdigit() else None


def rule_domain_ends_digit(ctx):
    labels = ctx.domain.split(".")
    main_label = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    return (5, "Domain ends with numeric value") if main_label and main_label[-1].isdigit() else None


def rule_consecutive_hyphens(ctx):
    return (6, "Consecutive hyphens detected") if "--" in ctx.domain else None


def rule_random_domain(ctx):
    main_label = ctx.domain.split(".")[0] if ctx.domain else ""
    if len(main_label) >= 8 and shannon_entropy(main_label) > 3.6:
        return (10, "Domain appears randomly generated")
    return None


RISK_RULES = [
    rule_ip, rule_https, rule_at_symbol, rule_punycode, rule_suspicious_tld,
    rule_long_url, rule_long_domain, rule_many_dots, rule_hyphens, rule_shortener,
    rule_login_path, rule_suspicious_words, rule_brand_impersonation, rule_digit_heavy,
    rule_special_chars, rule_encoded_chars, rule_double_slash_path, rule_query_params,
    rule_uncommon_port, rule_multi_keywords, rule_domain_starts_digit,
    rule_domain_ends_digit, rule_consecutive_hyphens, rule_random_domain,
]


def trust_gov(ctx):
    return (-15, "Trusted .gov Domain") if ctx.domain.endswith(".gov") else None


def trust_edu(ctx):
    return (-10, "Trusted .edu Domain") if ctx.domain.endswith(".edu") else None


def trust_clean_structure(ctx):
    if ctx.hyphens == 0 and ctx.dots <= 2 and not ctx.has_ip and len(ctx.domain) <= 20:
        return (-3, "Clean Domain Structure")
    return None


def trust_https_trusted_tld(ctx):
    if ctx.has_https and any(ctx.domain.endswith(t) for t in TRUSTED_TLDS):
        return (-10, "HTTPS + Trusted TLD Bonus")
    return None


TRUST_RULES = [trust_gov, trust_edu, trust_clean_structure, trust_https_trusted_tld]

# rules 0-9 = Structure, 10-19 = Content, 20-24 = Domain Intel
RISK_CATEGORIES = [
    {"name": "Structure", "start": 0, "end": 10},
    {"name": "Content", "start": 10, "end": 20},
    {"name": "Domain Intel", "start": 20, "end": 25},
]


def category_for_index(i):
    for c in RISK_CATEGORIES:
        if c["start"] <= i < c["end"]:
            return c["name"]
    return "Other"


# ---------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------
def determine_verdict(score):
    if score >= VERDICT_THRESHOLDS["fake"]:
        return "Fake"
    if score >= VERDICT_THRESHOLDS["suspicious"]:
        return "Suspicious"
    return "Safe"


def determine_threat_level(score):
    if score >= THREAT_LEVEL_THRESHOLDS["High"]:
        return "High"
    if score >= THREAT_LEVEL_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def determine_recommendation(verdict):
    if verdict == "Fake":
        return "Avoid visiting this website. Never enter passwords or banking details."
    if verdict == "Suspicious":
        return "Proceed with caution. Verify the sender or source before entering any information."
    return "This URL looks safe, but always stay alert for unexpected requests for personal data."


def determine_confidence(reasons_count, positive_count):
    base = 55
    signal_bonus = (reasons_count * 6) + (positive_count * 4)
    return min(99, base + signal_bonus)


def analyze_url(raw_url):
    ctx = build_context(raw_url)
    score = 0
    reasons = []
    positive_checks = []
    category_totals = {c["name"]: c["end"] - c["start"] for c in RISK_CATEGORIES}
    category_hits = {c["name"]: 0 for c in RISK_CATEGORIES}

    for i, rule in enumerate(RISK_RULES):
        result = rule(ctx)
        if result:
            points, reason = result
            score += points
            category = category_for_index(i)
            reasons.append({"text": reason, "points": points, "category": category})
            category_hits[category] = category_hits.get(category, 0) + 1

    for rule in TRUST_RULES:
        result = rule(ctx)
        if result:
            points, reason = result
            score += points
            positive_checks.append(reason)

    if ctx.has_https and "HTTPS Enabled" not in positive_checks:
        positive_checks.insert(0, "HTTPS Enabled")
    if ctx.hyphens == 0 and "Standard Domain Structure" not in positive_checks:
        positive_checks.append("Standard Domain Structure")

    score = max(0, score)
    risk = min(score, 100)
    verdict = determine_verdict(score)
    threat_level = determine_threat_level(score)
    confidence = determine_confidence(len(reasons), len(positive_checks))
    recommendation = determine_recommendation(verdict)

    total_rules = len(RISK_RULES) + len(TRUST_RULES)
    top_risk = max(reasons, key=lambda r: r["points"]) if reasons else None

    categories = [
        {"name": c["name"], "total": category_totals[c["name"]], "hits": category_hits[c["name"]]}
        for c in RISK_CATEGORIES
    ]
    categories.append({"name": "Trust", "total": len(TRUST_RULES), "hits": len(positive_checks)})

    return {
        "url": ctx.url,
        "domain": ctx.domain,
        "length": ctx.length,
        "dots": ctx.dots,
        "hyphens": ctx.hyphens,
        "https": ctx.has_https,
        "score": score,
        "risk": risk,
        "result": verdict,
        "threat_level": threat_level,
        "confidence": confidence,
        "positive_checks": positive_checks,
        "reasons": reasons,
        "recommendation": recommendation,
        "categories": categories,
        "stats": {
            "totalRules": total_rules,
            "flagsTriggered": len(reasons),
            "trustSignals": len(positive_checks),
            "topRisk": f"{top_risk['text']} (+{top_risk['points']})" if top_risk else "None",
        },
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.json or {}
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    ctx = build_context(url)
    if not is_likely_valid_url(ctx):
        return jsonify({"error": "invalid_url"}), 400

    result = analyze_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run()
