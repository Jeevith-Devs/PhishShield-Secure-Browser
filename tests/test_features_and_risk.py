"""
Unit tests for PhishShield Feature Extraction and Risk Scoring Engines.
"""

import sys
import os

# Set root path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.features.url_features import extract_url_features
from backend.app.risk.engine import RiskEngine, ThreatLevel, AdaptiveAction

def test_benign_url():
    url = "https://www.google.com/search?q=cybersecurity"
    features = extract_url_features(url)
    assert features["url_length"] > 0
    assert features["is_ip_address"] == 0
    assert features["has_brand_in_subdomain"] == 0
    assert features["is_high_risk_tld"] == 0

    engine = RiskEngine()
    result = engine.evaluate(url=url, ml_probability=0.01, features=features)
    assert result.composite_risk_score <= 30.0
    assert result.threat_level == ThreatLevel.LOW
    assert result.adaptive_action == AdaptiveAction.ALLOW
    print(f"[PASS] Benign URL '{url}' -> Score: {result.composite_risk_score}, Action: {result.adaptive_action.value}")

def test_phishing_ip_url():
    url = "http://192.168.1.50/paypal-update/login.php"
    features = extract_url_features(url)
    assert features["is_ip_address"] == 1
    assert features["has_suspicious_keyword"] == 1

    engine = RiskEngine()
    result = engine.evaluate(
        url=url,
        ml_probability=0.95,
        domain_risk_score=90.0,
        infrastructure_risk_score=85.0,
        features=features
    )
    assert result.composite_risk_score >= 61.0
    assert result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    assert result.adaptive_action in [AdaptiveAction.CONTROLLED, AdaptiveAction.ISOLATE]
    print(f"[PASS] Phishing IP URL '{url}' -> Score: {result.composite_risk_score}, Action: {result.adaptive_action.value}")

def test_brand_spoofing_url():
    url = "http://paypal.verify-account.security-update.xyz/login"
    features = extract_url_features(url)
    assert features["has_brand_in_subdomain"] == 1
    assert features["is_high_risk_tld"] == 1
    assert features["subdomain_count"] >= 2

    engine = RiskEngine()
    result = engine.evaluate(
        url=url,
        ml_probability=0.88,
        domain_risk_score=75.0,
        features=features
    )
    assert result.composite_risk_score >= 31.0
    print(f"[PASS] Brand Spoofing URL '{url}' -> Score: {result.composite_risk_score}, Level: {result.threat_level.value}")

if __name__ == "__main__":
    print("Running PhishShield Core Unit Verification...")
    test_benign_url()
    test_phishing_ip_url()
    test_brand_spoofing_url()
    print("All unit tests successfully passed!")
