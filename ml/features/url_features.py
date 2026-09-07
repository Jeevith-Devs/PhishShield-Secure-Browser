"""
PhishShield URL Feature Extraction Engine
Extracts 38 lexical, structural, and heuristic features from raw URLs for ML/DL models.
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

# Prominent brand targets commonly impersonated in phishing campaigns
SUSPICIOUS_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "citi", "binance",
    "coinbase", "metamask", "outlook", "office365", "dropbox", "dhl", "fedex"
]

# High-risk / free TLDs frequently abused in ephemeral phishing attacks
HIGH_RISK_TLDS = {
    "xyz", "top", "work", "club", "buzz", "tk", "ml", "ga", "cf", "gq",
    "fit", "country", "kim", "cricket", "science", "party", "click", "link"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "billing", "confirm", "wallet",
    "support", "service", "recover", "authenticate", "passcode", "auth"
]

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)

def extract_url_features(raw_url: str) -> Dict[str, Any]:
    """
    Extracts 38 lexical, structural, and heuristic features from a given URL.
    Returns a dictionary of numerical and boolean features suitable for ML inference.
    """
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        parsed = urlparse("http://invalid-url.local")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Structural Length Metrics
    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # 2. Character Counts in full URL
    dot_count = raw_url.count(".")
    hyphen_count = raw_url.count("-")
    underscore_count = raw_url.count("_")
    slash_count = raw_url.count("/")
    question_count = raw_url.count("?")
    equal_count = raw_url.count("=")
    at_count = raw_url.count("@")
    ampersand_count = raw_url.count("&")
    percent_count = raw_url.count("%")
    digit_count = sum(c.isdigit() for c in raw_url)
    letter_count = sum(c.isalpha() for c in raw_url)

    # 3. Ratios
    digit_ratio = round(digit_count / url_length, 4) if url_length > 0 else 0.0
    letter_ratio = round(letter_count / url_length, 4) if url_length > 0 else 0.0

    # 4. Hostname Metrics
    is_ip_address = 1 if IPV4_PATTERN.match(hostname) else 0
    subdomains = hostname.split(".") if hostname else []
    # e.g., 'www.login.example.com' has 4 parts -> 2 subdomains (www, login)
    subdomain_count = max(0, len(subdomains) - 2) if not is_ip_address else 0
    hostname_entropy = calculate_shannon_entropy(hostname)
    has_punycode = 1 if "xn--" in hostname.lower() else 0

    # Extract TLD
    tld = subdomains[-1].lower() if len(subdomains) > 1 and not is_ip_address else ""
    is_high_risk_tld = 1 if tld in HIGH_RISK_TLDS else 0

    # 5. Security & Path Indicators
    is_https = 1 if raw_url.lower().startswith("https://") else 0
    has_double_slash_in_path = 1 if "//" in path else 0
    has_port_in_url = 1 if parsed.port is not None else 0

    # 6. Suspicious Keywords & Brands
    url_lower = raw_url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_keyword = 1 if keyword_count > 0 else 0

    brand_count = sum(1 for b in SUSPICIOUS_BRANDS if b in url_lower)
    has_brand_in_subdomain = 0
    if not is_ip_address and len(subdomains) > 2:
        subdomain_part = ".".join(subdomains[:-2]).lower()
        has_brand_in_subdomain = 1 if any(b in subdomain_part for b in SUSPICIOUS_BRANDS) else 0

    # 7. Information Entropy
    url_entropy = calculate_shannon_entropy(raw_url)
    path_entropy = calculate_shannon_entropy(path)

    # Compile the 38-feature vector
    features = {
        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "query_length": query_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "at_count": at_count,
        "ampersand_count": ampersand_count,
        "percent_count": percent_count,
        "digit_count": digit_count,
        "letter_count": letter_count,
        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "is_ip_address": is_ip_address,
        "subdomain_count": subdomain_count,
        "hostname_entropy": hostname_entropy,
        "has_punycode": has_punycode,
        "is_high_risk_tld": is_high_risk_tld,
        "is_https": is_https,
        "has_double_slash_in_path": has_double_slash_in_path,
        "has_port_in_url": has_port_in_url,
        "keyword_count": keyword_count,
        "has_suspicious_keyword": has_suspicious_keyword,
        "brand_count": brand_count,
        "has_brand_in_subdomain": has_brand_in_subdomain,
        "url_entropy": url_entropy,
        "path_entropy": path_entropy,
        # Extended structural signals
        "dot_in_hostname": hostname.count("."),
        "hyphen_in_hostname": hostname.count("-"),
        "digit_in_hostname": sum(c.isdigit() for c in hostname),
        "param_count": len(query.split("&")) if query else 0,
        "has_www": 1 if hostname.lower().startswith("www.") else 0,
        "consecutive_dots": 1 if ".." in raw_url else 0,
        "consecutive_hyphens": 1 if "--" in raw_url else 0
    }

    return features
