"""Convert a URL string into numerical features. No network I/O."""

from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import parse_qs, urlparse

FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_digits",
    "num_hyphens",
    "num_subdomains",
    "https",
    "ip_hostname",
    "has_at",
    "query_param_count",
    "punycode",
    "suspicious_keyword_count",
    "hostname_entropy",
)

# Lexical phishing cues counted as substrings of the lowercase URL.
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "signin",
    "verify",
    "secure",
    "update",
    "account",
    "confirm",
    "password",
    "banking",
    "wallet",
    "urgent",
    "suspend",
    "unlock",
    "limited",
    "alert",
    "reset",
)

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _empty_features(url: str) -> dict[str, float]:
    text = url or ""
    return {
        "url_length": float(len(text)),
        "hostname_length": 0.0,
        "path_length": 0.0,
        "num_dots": float(text.count(".")),
        "num_digits": float(sum(ch.isdigit() for ch in text)),
        "num_hyphens": float(text.count("-")),
        "num_subdomains": 0.0,
        "https": 0.0,
        "ip_hostname": 0.0,
        "has_at": 1.0 if "@" in text else 0.0,
        "query_param_count": 0.0,
        "punycode": 1.0 if "xn--" in text.lower() else 0.0,
        "suspicious_keyword_count": float(_keyword_count(text)),
        "hostname_entropy": 0.0,
    }


def _keyword_count(text: str) -> int:
    lowered = (text or "").lower()
    return sum(1 for word in SUSPICIOUS_KEYWORDS if word in lowered)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_ip_hostname(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return bool(_IPV4_RE.match(candidate))


def _subdomain_count(host: str, is_ip: bool) -> int:
    if not host or is_ip:
        return 0
    labels = [part for part in host.split(".") if part]
    # hostname = [subdomains...] + registered name + tld
    return max(0, len(labels) - 2)


def _parse(raw_url: str):
    text = (raw_url or "").strip()
    if not text:
        return None, ""
    candidate = text if "://" in text else "http://" + text
    try:
        parsed = urlparse(candidate)
    except Exception:
        return None, text
    return parsed, text


def extract_url_features(raw_url: str | None) -> dict[str, float]:
    """Return a dict of numerical features for ``raw_url``.

    Malformed or empty inputs never raise: string-level counts are still
    produced and hostname-dependent values are set to 0.
    """
    if raw_url is None:
        return _empty_features("")

    parsed, text = _parse(raw_url)
    if parsed is None:
        return _empty_features(text)

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        features = _empty_features(text)
        path = parsed.path or ""
        query = parsed.query or ""
        features["path_length"] = float(len(path))
        if query:
            features["query_param_count"] = float(len(parse_qs(query, keep_blank_values=True)))
        if (parsed.scheme or "").lower() == "https":
            features["https"] = 1.0
        return features

    is_ip = _is_ip_hostname(hostname)
    query = parsed.query or ""
    path = parsed.path or ""

    return {
        "url_length": float(len(text)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "num_dots": float(text.count(".")),
        "num_digits": float(sum(ch.isdigit() for ch in text)),
        "num_hyphens": float(text.count("-")),
        "num_subdomains": float(_subdomain_count(hostname, is_ip)),
        "https": 1.0 if (parsed.scheme or "").lower() == "https" else 0.0,
        "ip_hostname": 1.0 if is_ip else 0.0,
        "has_at": 1.0 if "@" in text else 0.0,
        "query_param_count": float(len(parse_qs(query, keep_blank_values=True))),
        "punycode": 1.0 if "xn--" in hostname else 0.0,
        "suspicious_keyword_count": float(_keyword_count(text)),
        "hostname_entropy": float(_shannon_entropy(hostname)),
    }


def feature_vector(raw_url: str | None) -> list[float]:
    """Return feature values in ``FEATURE_NAMES`` order."""
    features = extract_url_features(raw_url)
    return [features[name] for name in FEATURE_NAMES]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract numerical features from a URL (offline).")
    parser.add_argument("url", help="URL string to analyse; it is not fetched")
    args = parser.parse_args(argv)
    print(json.dumps(extract_url_features(args.url), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
