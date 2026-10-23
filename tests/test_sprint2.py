"""
PhishShield — Backend Test Suite (Sprint 2 MVP)
Tests for Feature Extractor, Risk Engine, Scan API, Sandbox, and Analyst.
Run: pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from ml.features.url_features import extract_url_features, calculate_shannon_entropy
from backend.app.risk.engine import RiskEngine, ThreatLevel, AdaptiveAction
from backend.app.main import app

client = TestClient(app)


# ─── Feature Extractor Tests ─────────────────────────────────────────────────

class TestURLFeatureExtractor:

    def test_basic_url_returns_dict(self):
        feats = extract_url_features("https://google.com")
        assert isinstance(feats, dict)
        assert len(feats) == 38

    def test_feature_keys_present(self):
        feats = extract_url_features("https://example.com/path?q=1")
        required_keys = [
            "url_length", "is_ip_address", "subdomain_count", "url_entropy",
            "is_https", "has_suspicious_keyword", "has_brand_in_subdomain",
            "is_high_risk_tld", "has_punycode",
        ]
        for key in required_keys:
            assert key in feats, f"Missing key: {key}"

    def test_https_detection(self):
        assert extract_url_features("https://example.com")["is_https"] == 1
        assert extract_url_features("http://example.com")["is_https"] == 0

    def test_ip_address_detection(self):
        assert extract_url_features("http://192.168.1.1/login")["is_ip_address"] == 1
        assert extract_url_features("https://google.com")["is_ip_address"] == 0

    def test_high_risk_tld_detection(self):
        assert extract_url_features("http://phishing.xyz/verify")["is_high_risk_tld"] == 1
        assert extract_url_features("https://google.com")["is_high_risk_tld"] == 0

    def test_brand_in_subdomain(self):
        feats = extract_url_features("http://paypal.login.attacker.com/verify")
        assert feats["has_brand_in_subdomain"] == 1

    def test_punycode_detection(self):
        assert extract_url_features("http://xn--pypal-4ve.com/login")["has_punycode"] == 1
        assert extract_url_features("https://paypal.com")["has_punycode"] == 0

    def test_suspicious_keyword(self):
        feats = extract_url_features("http://secure-banking-login.com/verify")
        assert feats["has_suspicious_keyword"] == 1
        assert feats["keyword_count"] >= 2

    def test_entropy_calculation(self):
        entropy = calculate_shannon_entropy("aaaa")
        assert entropy == 0.0
        entropy2 = calculate_shannon_entropy("abcd")
        assert entropy2 > 0.0

    def test_subdomain_count(self):
        feats = extract_url_features("http://one.two.three.example.com/")
        assert feats["subdomain_count"] >= 2

    def test_at_sign_detection(self):
        feats = extract_url_features("http://user@evil.com/login")
        assert feats["at_count"] == 1


# ─── Risk Engine Tests ────────────────────────────────────────────────────────

class TestRiskEngine:

    def setup_method(self):
        self.engine = RiskEngine()

    def test_low_risk_verdict(self):
        result = self.engine.evaluate(url="https://google.com", ml_probability=0.05)
        assert result.threat_level == ThreatLevel.LOW
        assert result.adaptive_action == AdaptiveAction.ALLOW
        assert result.composite_risk_score <= 30.0

    def test_medium_risk_verdict(self):
        # composite = ml_prob * 0.40 weight; need > 30 → ml_prob > 0.75
        result = self.engine.evaluate(url="http://example.xyz", ml_probability=0.85)
        assert result.threat_level == ThreatLevel.MEDIUM
        assert result.adaptive_action == AdaptiveAction.WARN

    def test_high_risk_verdict(self):
        # composite = 0.99*40 + 100*20 + 100*15 = 39.6+20+15 = 74.6 → HIGH
        result = self.engine.evaluate(
            url="http://paypal-login.xyz", ml_probability=0.99,
            domain_risk_score=100.0, infrastructure_risk_score=100.0,
        )
        assert result.threat_level == ThreatLevel.HIGH
        assert result.adaptive_action == AdaptiveAction.CONTROLLED

    def test_critical_risk_verdict(self):
        # Need composite > 80; use all dimensions
        result = self.engine.evaluate(
            url="http://192.168.1.1/wallet", ml_probability=0.99,
            domain_risk_score=100.0, infrastructure_risk_score=100.0,
            behavior_risk_score=100.0, threat_intel_score=100.0,
        )
        assert result.threat_level == ThreatLevel.CRITICAL
        assert result.adaptive_action == AdaptiveAction.ISOLATE

    def test_score_range(self):
        for prob in [0.0, 0.25, 0.5, 0.75, 1.0]:
            result = self.engine.evaluate("http://test.com", ml_probability=prob)
            assert 0.0 <= result.composite_risk_score <= 100.0

    def test_feature_reasons_populated(self):
        features = {"is_ip_address": 1, "has_brand_in_subdomain": 1, "is_high_risk_tld": 1}
        result = self.engine.evaluate("http://192.168.1.1", ml_probability=0.9, features=features)
        assert len(result.reasons) > 0

    def test_breakdown_keys(self):
        result = self.engine.evaluate("http://test.com", ml_probability=0.3)
        assert "ml_model_contribution" in result.score_breakdown
        assert "domain_contribution" in result.score_breakdown


# ─── API Integration Tests ────────────────────────────────────────────────────

class TestScanAPI:

    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_scan_url_returns_verdict(self):
        resp = client.post("/api/v1/scan/url", json={"url": "https://google.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_score" in data
        assert "threat_level" in data
        assert "adaptive_action" in data
        assert "scan_id" in data
        assert data["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_scan_phishing_url(self):
        resp = client.post("/api/v1/scan/url", json={"url": "http://paypal-login-verify.xyz/account"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] > 20  # Should be elevated

    def test_scan_empty_url_rejected(self):
        resp = client.post("/api/v1/scan/url", json={"url": ""})
        assert resp.status_code == 422

    def test_batch_scan(self):
        resp = client.post("/api/v1/scan/batch", json={
            "urls": ["https://google.com", "http://phishing.xyz/login", "http://192.168.1.1/wallet"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3

    def test_batch_too_many_urls(self):
        resp = client.post("/api/v1/scan/batch", json={"urls": ["http://test.com"] * 51})
        assert resp.status_code == 422

    def test_scan_history(self):
        # First run a scan to populate history
        client.post("/api/v1/scan/url", json={"url": "https://example.com"})
        resp = client.get("/api/v1/scan/history")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_scan_stats(self):
        resp = client.get("/api/v1/scan/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data


class TestSandboxAPI:

    def test_launch_high_risk_sandbox(self):
        resp = client.post("/api/v1/sandbox/launch", json={
            "url": "http://paypal-verify.xyz/login",
            "threat_level": "HIGH",
            "inject_synthetic_data": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert data["status"] == "active"
        assert data["synthetic_data"] is not None

    def test_launch_low_risk_rejected(self):
        resp = client.post("/api/v1/sandbox/launch", json={
            "url": "https://google.com",
            "threat_level": "LOW",
        })
        assert resp.status_code == 422

    def test_list_sessions(self):
        resp = client.get("/api/v1/sandbox/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data

    def test_terminate_session(self):
        # Launch first
        launch_resp = client.post("/api/v1/sandbox/launch", json={
            "url": "http://evil.top/login",
            "threat_level": "CRITICAL",
        })
        session_id = launch_resp.json()["session_id"]
        # Terminate
        term_resp = client.post(f"/api/v1/sandbox/sessions/{session_id}/terminate")
        assert term_resp.status_code == 200
        assert term_resp.json()["status"] == "terminated"


class TestIntelAPI:

    def test_domain_intel(self):
        resp = client.get("/api/v1/intel/domain/google.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "google.com"
        assert "urlhaus" in data
        assert "composite_reputation_score" in data

    def test_recent_feed(self):
        resp = client.get("/api/v1/intel/feeds/recent?limit=3")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) <= 3
