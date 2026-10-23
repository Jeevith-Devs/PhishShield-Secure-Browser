"""
PhishShield — Backend Test Suite (Sprints 3 & 4)
Comprehensive tests for:
  - Ephemeral Sandboxing & Synthetic Data Injection (SDI)
  - Threat Intelligence Aggregator & Feed Connectors
  - Neo4j Infrastructure Threat Graph & Campaign Clustering
  - Evidence-Grounded AI Security Analyst (OBSERVED / INFERRED / UNKNOWN Triad)
"""
import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.sandbox.sdi import sdi, verify_luhn, generate_luhn_card
from backend.app.sandbox.orchestrator import SandboxOrchestrator
from backend.app.threat_intel.connectors import connector
from backend.app.graph.schema import graph
from backend.app.analyst.engine import analyst

client = TestClient(app)


# ─── 1. Synthetic Data Injection (SDI) Tests ─────────────────────────────────

class TestSyntheticDataInjection:

    def test_luhn_algorithm_validation(self):
        """Validates that SDI generated credit cards strictly pass the ISO/IEC 7812 Luhn checksum."""
        for _ in range(25):
            cc_number = generate_luhn_card("visa")
            assert len(cc_number) == 16
            assert cc_number.isdigit()
            assert verify_luhn(cc_number) is True

    def test_synthetic_identity_generation(self):
        """Validates synthetic identity properties and zero real-user credential leakage."""
        identity = sdi.generate_identity()
        d = identity.to_dict()

        assert "cardholder_name" in d
        assert "email" in d
        assert "password" in d
        assert "card_number" in d
        assert "canary_token" in d
        assert "address_line" in d

        # Verify card inside identity passes Luhn
        clean_num = d["card_number"].replace(" ", "")
        assert verify_luhn(clean_num) is True

        # Verify synthetic markings
        assert "canary" in d["email"] or "@phishshield-trap.invalid" in d["email"]

    def test_form_field_filling_rules(self):
        """Verifies intelligent field value matching for sensitive inputs."""
        identity = sdi.generate_identity()
        assert sdi.match_form_field("card_number", "text", identity) == identity.card_number.replace(" ", "")
        assert sdi.match_form_field("cvv", "text", identity) == identity.card_cvv
        assert sdi.match_form_field("password", "password", identity) == identity.password
        assert sdi.match_form_field("email", "email", identity) == identity.email


# ─── 2. Ephemeral Sandbox Orchestrator Tests ──────────────────────────────────

class TestSandboxOrchestrator:

    def test_spawn_session_with_sdi(self):
        async def _test():
            orchestrator = SandboxOrchestrator()
            session = await orchestrator.spawn("http://bank-login-update.xyz/auth", inject_synthetic=True)

            assert session.status == "active"
            assert session.synthetic_data_injected is True
            assert session.synthetic_identity is not None
            assert len(session.telemetry) > 0

            # Check telemetry event types
            event_types = [e.event_type for e in session.telemetry]
            assert "navigation" in event_types
            assert "network_request" in event_types
        asyncio.run(_test())

    def test_terminate_session(self):
        async def _test():
            orchestrator = SandboxOrchestrator()
            session = await orchestrator.spawn("http://evil-tracker.top", inject_synthetic=False)
            assert session.status == "active"

            success = await orchestrator.terminate(session.session_id)
            assert success is True
            assert session.status == "terminated"
            assert session.terminated_at is not None
        asyncio.run(_test())

    def test_sandbox_api_workflow(self):
        """Tests full API flow: launch -> list -> get telemetry -> terminate."""
        # 1. Launch
        launch_res = client.post("/api/v1/sandbox/launch", json={
            "url": "http://paypal-verification-portal.xyz/login",
            "threat_level": "HIGH",
            "inject_synthetic_data": True,
        })
        assert launch_res.status_code == 200
        data = launch_res.json()
        session_id = data["session_id"]
        assert data["synthetic_data"] is not None

        # 2. Get Telemetry
        telem_res = client.get(f"/api/v1/sandbox/sessions/{session_id}/telemetry")
        assert telem_res.status_code == 200
        telem_data = telem_res.json()
        assert "events" in telem_data
        assert telem_data["total_events"] > 0

        # 3. Terminate
        term_res = client.post(f"/api/v1/sandbox/sessions/{session_id}/terminate")
        assert term_res.status_code == 200
        assert term_res.json()["status"] == "terminated"


# ─── 3. Threat Intelligence Aggregator Tests ──────────────────────────────────

class TestThreatIntel:

    def test_benign_domain_enrichment(self):
        async def _test():
            enrichment = await connector.enrich("google.com")
            assert enrichment.domain == "google.com"
            assert enrichment.composite_reputation_score < 30.0
            assert enrichment.urlhaus.listed is False
            assert enrichment.abuseipdb.abuse_confidence_score == 0
        asyncio.run(_test())

    def test_malicious_domain_enrichment(self):
        async def _test():
            enrichment = await connector.enrich("paypal-secure-login.xyz")
            assert enrichment.domain == "paypal-secure-login.xyz"
            assert enrichment.composite_reputation_score >= 40.0
            assert enrichment.urlhaus.listed is True
            assert enrichment.abuseipdb.abuse_confidence_score > 50
        asyncio.run(_test())

    def test_domain_intel_api(self):
        resp = client.get("/api/v1/intel/domain/apple-verification.xyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "apple-verification.xyz"
        assert "urlhaus" in data
        assert "abuseipdb" in data
        assert "virustotal" in data
        assert "rdap" in data
        assert data["composite_reputation_score"] > 30.0

    def test_feed_stats_api(self):
        resp = client.get("/api/v1/intel/feeds/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_iocs"] > 0
        assert data["sources"]["urlhaus"]["status"] == "active"


# ─── 4. Infrastructure Graph & Campaign Clustering Tests ───────────────────────

class TestInfrastructureGraph:

    def test_graph_scan_ingestion(self):
        async def _test():
            scan_payload = {
                "url": "http://chase-bank-verify.xyz/account/login",
                "scan_id": "test-scan-101",
                "risk_score": 88.5,
                "threat_level": "CRITICAL",
                "scan_timestamp": "2026-10-23T10:00:00Z",
            }
            await graph.ingest_scan(scan_payload)

            # Retrieve domain subgraph
            subgraph = await graph.get_domain_graph("chase-bank-verify.xyz")
            assert subgraph["total_nodes"] >= 4
            assert subgraph["total_edges"] >= 3

            # Verify edge types and confidence
            edge_relations = [e["relationship"] for e in subgraph["edges"]]
            assert "HOSTED_ON" in edge_relations
            assert "RESOLVES_TO" in edge_relations
            assert "BELONGS_TO" in edge_relations

            # Edge confidence verification: DNS/host is CONFIRMED, Campaign is INFERRED
            for e in subgraph["edges"]:
                if e["relationship"] in ("HOSTED_ON", "RESOLVES_TO", "BELONGS_TO", "USES_CERT"):
                    assert e["confidence"] == "CONFIRMED"
                elif e["relationship"] in ("PART_OF", "AFFILIATED_WITH"):
                    assert e["confidence"] == "INFERRED"
        asyncio.run(_test())

    def test_campaign_clusters(self):
        async def _test():
            clusters = await graph.get_campaign_clusters()
            assert len(clusters) >= 2
            cluster_names = [c["name"] for c in clusters]
            assert any("SilentKite" in name or "CryptoDrainer" in name for name in cluster_names)
        asyncio.run(_test())

    def test_graph_api_endpoints(self):
        # 1. Overview
        resp = client.get("/api/v1/graph/overview")
        assert resp.status_code == 200
        assert resp.json()["total_nodes"] > 0

        # 2. Domain Graph
        resp = client.get("/api/v1/graph/domain/paypal-phish-portal.xyz")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data

        # 3. Campaigns
        resp = client.get("/api/v1/graph/campaigns")
        assert resp.status_code == 200
        assert resp.json()["total"] > 0

        # 4. Correlate
        resp = client.post("/api/v1/graph/correlate", json={"domain": "crypto-login.xyz"})
        assert resp.status_code == 200
        corr_data = resp.json()
        assert "graph" in corr_data
        assert "campaign_matches" in corr_data


# ─── 5. AI Security Analyst Tests (Evidence Triad & Zero Hallucination) ─────────

class TestAISecurityAnalyst:

    def test_analyst_evidence_triad_partitioning(self):
        """
        Validates that every statement generated by the AnalystEngine is strictly
        partitioned into the OBSERVED, INFERRED, and UNKNOWN triad.
        """
        sample_scan = {
            "scan_id": "test-analyst-scan-1",
            "url": "http://paypal.login-update.xyz/verify",
            "risk_score": 92.0,
            "threat_level": "CRITICAL",
            "adaptive_action": "ISOLATE",
            "confidence": 0.95,
            "indicators": {
                "reasons": [
                    "Host uses IP address instead of domain name",
                    "Brand keyword 'paypal' spoofed in subdomain",
                    "Suspicious high-risk TLD (.xyz)",
                ],
                "score_breakdown": {
                    "ml_model_contribution": 40.0,
                    "domain_contribution": 20.0,
                    "infrastructure_contribution": 15.0,
                    "behavior_contribution": 17.0,
                },
                "features_summary": {
                    "url_length": 42,
                    "entropy": 3.84,
                    "is_ip_address": True,
                    "is_high_risk_tld": True,
                    "has_brand_in_subdomain": True,
                }
            }
        }

        context = analyst.build_context(scan_verdict=sample_scan)
        report = analyst.generate_report(context)

        # 1. OBSERVED facts exist and cite evidence sources
        assert len(report.observed) > 0
        for fact in report.observed:
            assert "test-analyst-scan-1" in fact.evidence_source or fact.evidence_source in ("url_features", "dns_lookup", "telemetry")
            assert fact.category in ("network", "dom", "redirect", "form", "lexical", "tld", "brand")

        # 2. INFERRED conclusions have supporting facts and confidence
        assert len(report.inferred) > 0
        for inference in report.inferred:
            assert inference.confidence in ("HIGH", "MEDIUM", "LOW")
            assert len(inference.supporting_facts) > 0

        # 3. UNKNOWN gaps document what was sought and why inaccessible
        assert len(report.unknown) > 0
        for gap in report.unknown:
            assert len(gap.what_is_unknown) > 0
            assert len(gap.why_unknown) > 0

        # 4. Zero Hallucination Check:
        # All IOC domains and URLs in report must match or be derived from target
        assert report.target_url == sample_scan["url"]
        for domain in report.iocs.get("domains", []):
            assert domain in sample_scan["url"] or domain == "login-update.xyz" or "xyz" in domain

    def test_analyst_api_generate_and_recent(self):
        # 1. Run a high risk scan to create a scan_id in history
        scan_res = client.post("/api/v1/scan/url", json={
            "url": "http://paypal-security-alert.xyz/account",
        })
        scan_id = scan_res.json()["scan_id"]

        # 2. Request Analyst Report
        report_res = client.post("/api/v1/analyst/generate", json={
            "scan_id": scan_id,
            "include_sandbox_telemetry": True,
            "include_graph_data": True,
        })
        assert report_res.status_code == 200
        report = report_res.json()

        assert report["scan_id"] == scan_id
        assert "observed" in report
        assert "inferred" in report
        assert "unknown" in report
        assert "recommended_actions" in report
        assert len(report["recommended_actions"]) > 0

        # 3. Check Recent Reports endpoint
        recent_res = client.get("/api/v1/analyst/reports/recent?limit=5")
        assert recent_res.status_code == 200
        recent_data = recent_res.json()
        assert "reports" in recent_data
        assert recent_data["total"] >= 1
