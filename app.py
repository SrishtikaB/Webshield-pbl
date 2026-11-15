from ml.predict import predict_url
from pathlib import Path
import ipaddress
import math
import os
import re
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------
# Google Safe Browsing API
# ---------------------------------------------------------------------
# Get a free key here: https://developers.google.com/safe-browsing/v4/get-started
# Then set it as an environment variable named GOOGLE_SAFE_BROWSING_API_KEY
# (locally in a .env / terminal export, and on Render under Environment).
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(raw_url):
    """
    Calls Google's Safe Browsing API to check if this URL is a known
    malware/phishing/unwanted-software site. Returns (is_threat, threat_types)
    or (False, []) if the key is missing, the request fails, or nothing is found.
    This never crashes the app -- if the API is down, we just skip this check
    and fall back to the rule-based score alone.
    """
    if not SAFE_BROWSING_API_KEY:
        return False, []

    payload = {
        "client": {"clientId": "webshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": raw_url}],
        },
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=4,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType", "THREAT") for m in matches})
            return True, threat_types
        return False, []
    except requests.RequestException:
        # API down, network issue, timeout, bad key, etc. -- fail safe, don't block the scan.
        return False, []


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

HIGH_CONFIDENCE_MALICIOUS_RULES = {
    "Uses IP address instead of domain",
    "'@' symbol hides actual destination",
    "Possible Unicode homograph attack",
    "Possible brand impersonation",
    "Uses suspicious domain extension",
    "Uses URL shortening service",
}

QUERY_OR_LENGTH_REASONS = {
    "Very long URL detected",
    "Excessive query parameters",
    "Excessive special symbols",
    "Encoded URL characters found",
}


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


def is_ip_address(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


TWO_PART_TLD_SUBDOMAINS = {
    "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go", "gen", "firm", "ind",
}


def extract_domain_parts(domain):
    """
    Splits a domain into (subdomains_list, registered_domain_label, suffix).
    Handles both standard single-part (.com) and two-part (.co.uk) TLDs.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return [], domain, ""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in TWO_PART_TLD_SUBDOMAINS:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    return labels[:-2], labels[-2], labels[-1]


LOOKALIKE_MAPS = [
    {"0": "o", "1": "l", "3": "e", "5": "s", "8": "b"},
    {"0": "o", "1": "i", "3": "e", "5": "s", "8": "b"},
]


def levenshtein_distance(s1, s2):
    """Computes the standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def is_brand_typosquat(domain_label, brand):
    """
    Checks if domain_label is a typosquat / lookalike of a known brand.
    Conservative comparison to prevent false positives:
    - Never flags the exact brand name.
    - Excludes brands shorter than 4 characters.
    - Checks visual substitutions (e.g. 1->l, 0->o).
    - Checks Levenshtein edit distance == 1 for brands with length >= 5.
    """
    if not domain_label or domain_label == brand or len(brand) < 4:
        return False
    # Visual substitution lookalikes (e.g., paypa1 -> paypal, g00gle -> google)
    for lmap in LOOKALIKE_MAPS:
        normalized = "".join(lmap.get(c, c) for c in domain_label)
        if normalized == brand:
            return True
    # Levenshtein distance of 1 for brands of length >= 5
    if len(brand) >= 5 and abs(len(domain_label) - len(brand)) <= 1:
        if levenshtein_distance(domain_label, brand) == 1:
            return True
    return False


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
        if parsed.netloc.endswith(":"):
            parse_failed = True
        _ = parsed.port
        if not parsed.netloc or not parsed.hostname:
            parse_failed = True
    except Exception:
        parsed = None
        parse_failed = True

    ctx = Context()
    ctx.url = url
    ctx.parsed = parsed
    hostname = parsed.hostname if parsed else None
    ctx.domain = (hostname if hostname else (parsed.path if parsed and not parse_failed else "")) or ""
    ctx.parse_failed = parse_failed
    ctx.length = len(url)
    ctx.dots = url.count(".")
    ctx.hyphens = ctx.domain.count("-")
    ctx.has_https = url.startswith("https")
    ctx.has_ip = is_ip_address(ctx.domain)
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
    netloc = (ctx.parsed.netloc if ctx.parsed else "") or ""
    return (25, "'@' symbol hides actual destination") if "@" in netloc else None


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
    domain = (ctx.domain or "").lower()
    if any(domain == s or domain.endswith("." + s) for s in URL_SHORTENERS):
        return (15, "Uses URL shortening service")
    return None


def rule_login_path(ctx):
    path = (ctx.parsed.path if ctx.parsed else "").lower()
    if any(w in path for w in LOGIN_PATH_WORDS):
        return (10, "Contains login/account related path")
    return None


def rule_suspicious_words(ctx):
    # Inspect the hostname and path, not query values such as search terms.
    # A legitimate search for "phishing" should not trigger this rule by itself.
    hostname = (ctx.domain or "").lower()
    path = (ctx.parsed.path if ctx.parsed else "").lower()
    relevant_text = f"{hostname} {path}"
    if any(w in relevant_text for w in SUSPICIOUS_WORDS):
        return (10, "Phishing-related keywords detected in domain or path")
    return None


def rule_brand_impersonation(ctx):
    subdomains, reg_domain, _ = extract_domain_parts(ctx.domain)
    for brand in KNOWN_BRANDS:
        for sub in subdomains:
            if (brand in sub or is_brand_typosquat(sub, brand)) and reg_domain != brand:
                return (20, "Possible brand impersonation")
        if brand in reg_domain and reg_domain != brand:
            # Only use the hostname/path for corroborating signals; query text is user-controlled.
            path = (ctx.parsed.path if ctx.parsed else "").lower()
            if any(w in path for w in SUSPICIOUS_WORDS):
                return (20, "Possible brand impersonation")
        if is_brand_typosquat(reg_domain, brand):
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
    # Do not count arbitrary query-string values (e.g. Google search terms).
    hostname = (ctx.domain or "").lower()
    path = (ctx.parsed.path if ctx.parsed else "").lower()
    relevant_text = f"{hostname} {path}"
    count = sum(1 for w in SUSPICIOUS_WORDS if w in relevant_text)
    return (10, "Multiple phishing-related keywords in domain or path") if count >= 2 else None


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

# rules 0-9 = Structure, 10-19 = Content, 20-23 = Domain Intel
RISK_CATEGORIES = [
    {"name": "Structure", "start": 0, "end": 10},
    {"name": "Content", "start": 10, "end": 20},
    {"name": "Domain Intel", "start": 20, "end": 24},
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

    # --- Google Safe Browsing check (real-world threat intelligence) ---
    is_threat, threat_types = check_safe_browsing(raw_url)
    safe_browsing_hit = is_threat
    if is_threat:
        readable_types = ", ".join(t.replace("_", " ").title() for t in threat_types)
        score += 60
        reasons.append({
            "text": f"Flagged by Google Safe Browsing ({readable_types})",
            "points": 60,
            "category": "Threat Intel",
        })

    if ctx.has_https and "HTTPS Enabled" not in positive_checks:
        positive_checks.insert(0, "HTTPS Enabled")
    if ctx.hyphens == 0 and "Standard Domain Structure" not in positive_checks:
        positive_checks.append("Standard Domain Structure")

    score = max(0, score)
    risk = min(score, 100)
    verdict = determine_verdict(score)
    threat_level = determine_threat_level(score)
    recommendation = determine_recommendation(verdict)

    # Machine Learning prediction
    try:
        ml_result = predict_url(
            raw_url,
            Path(__file__).resolve().parent / "ml" / "artifacts",
        )
    except Exception as e:
        ml_result = {
            "prediction": "unavailable",
            "error": str(e),
        }

    # Combine rule-based and ML predictions using principled hybrid logic
    ml_prediction = ml_result.get("prediction", "unavailable")
    probabilities = ml_result.get("probabilities") or {}
    p_phish = probabilities.get("phishing")
    rule_risk = risk
    rule_threat_level = threat_level

    # Domain trust analysis
    _, reg_domain, _ = extract_domain_parts(ctx.domain)
    is_trusted_institution = bool(
        ctx.domain.endswith(".gov") or ctx.domain.endswith(".edu") or
        any(t in ctx.domain for t in (".gov.", ".edu.", ".ac."))
    )
    major_brands = set(KNOWN_BRANDS) - {"bank"}
    is_genuine_brand = (
        reg_domain in major_brands and
        not any(r["text"] == "Possible brand impersonation" for r in reasons) and
        not any(ctx.domain.endswith(t) for t in SUSPICIOUS_TLDS)
    )
    is_trusted_domain = (is_trusted_institution or is_genuine_brand or "HTTPS + Trusted TLD Bonus" in positive_checks)

    has_strong_rule = any(
        r["text"] in HIGH_CONFIDENCE_MALICIOUS_RULES or r.get("points", 0) >= 15
        for r in reasons
    )
    has_substantive_threat = any(
        r["text"] not in QUERY_OR_LENGTH_REASONS for r in reasons
    )

    if safe_browsing_hit:
        # Definitive external threat intelligence confirming active malware/phishing
        hybrid_risk = max(score, 60)
    elif verdict == "Fake":
        # Substantive rule-based evidence (score >= 40)
        if ml_prediction == "phishing" and p_phish is not None:
            hybrid_risk = min(100, max(rule_risk, int(round(rule_risk * 0.7 + p_phish * 100 * 0.3))))
        else:
            hybrid_risk = rule_risk
    elif verdict == "Suspicious":
        if has_strong_rule:
            # High-confidence attack indicator (e.g. brand impersonation or IP address)
            if ml_prediction == "phishing" and p_phish is not None:
                if rule_risk >= 30 and p_phish >= 0.8:
                    hybrid_risk = min(100, max(40, int(round(rule_risk * 0.6 + p_phish * 100 * 0.4))))
                else:
                    hybrid_risk = min(39, max(rule_risk, int(round(rule_risk * 0.7 + p_phish * 100 * 0.3))))
            else:
                hybrid_risk = rule_risk
        else:
            if ml_prediction == "phishing":
                p_val = p_phish if p_phish is not None else 0.5
                hybrid_risk = min(39, max(rule_risk, int(round(rule_risk * 0.7 + p_val * 100 * 0.3))))
            else:
                if is_trusted_domain and not has_substantive_threat:
                    hybrid_risk = min(rule_risk, 14)
                else:
                    hybrid_risk = rule_risk
    else:  # verdict == "Safe" (score < 15)
        if ml_prediction == "phishing" and (p_phish is None or p_phish > 0.5):
            # ML predicts phishing, but rule detector finds low/zero threat
            if is_trusted_domain:
                # On trusted brand/institutional domains, query parameters and lengths
                # do not create false positives unless substantive threats exist in path/content
                if not has_substantive_threat:
                    hybrid_risk = min(rule_risk, 14)
                else:
                    if p_phish is not None:
                        hybrid_risk = max(15, min(35, int(round(15 + p_phish * 15 + rule_risk * 0.5))))
                    else:
                        hybrid_risk = max(15, min(30, 15 + rule_risk))
            else:
                # On unknown/unvetted domains
                if len(reasons) == 0:
                    # Clean domain with zero threat indicators; ML path_length artifact
                    hybrid_risk = rule_risk
                else:
                    # Specific threat indicator present on unvetted domain; cautious verdict
                    if p_phish is not None:
                        hybrid_risk = max(15, min(35, int(round(15 + p_phish * 15 + rule_risk * 0.5))))
                    else:
                        hybrid_risk = max(15, min(30, 15 + rule_risk))
        else:
            # Rule and ML agree on Safe/legitimate (or ML unavailable)
            hybrid_risk = rule_risk

    hybrid_risk = max(0, min(100, hybrid_risk))
    hybrid_verdict = determine_verdict(hybrid_risk)
    hybrid_threat_level = determine_threat_level(hybrid_risk)
    hybrid_recommendation = determine_recommendation(hybrid_verdict)

    total_rules = len(RISK_RULES) + len(TRUST_RULES)
    top_risk = max(reasons, key=lambda r: r["points"]) if reasons else None

    categories = [
        {"name": c["name"], "total": category_totals[c["name"]], "hits": category_hits[c["name"]]}
        for c in RISK_CATEGORIES
    ]
    categories.append({"name": "Trust", "total": len(TRUST_RULES), "hits": len(positive_checks)})
    categories.append({"name": "Threat Intel", "total": 1, "hits": 1 if safe_browsing_hit else 0})

    return {
        "url": ctx.url,
        "domain": ctx.domain,
        "length": ctx.length,
        "dots": ctx.dots,
        "hyphens": ctx.hyphens,
        "https": ctx.has_https,
        "score": score,
        # Existing frontend fields follow the hybrid verdict so the badge,
        # gauge, and threat level do not contradict one another.
        "risk": hybrid_risk,
        "result": verdict,
        "ml_prediction": ml_result,
        "hybrid_verdict": hybrid_verdict,
        "hybrid_recommendation": hybrid_recommendation,
        "threat_level": hybrid_threat_level,
        # Explicit rule-based metrics retained for diagnostics/backward use.
        "rule_risk": rule_risk,
        "rule_threat_level": rule_threat_level,
        "hybrid_risk": hybrid_risk,
        "hybrid_threat_level": hybrid_threat_level,
        "positive_checks": positive_checks,
        "reasons": reasons,
        "recommendation": hybrid_recommendation,
        "categories": categories,
        "safe_browsing": {
            "checked": bool(SAFE_BROWSING_API_KEY),
            "flagged": safe_browsing_hit,
            "threat_types": threat_types,
        },
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
