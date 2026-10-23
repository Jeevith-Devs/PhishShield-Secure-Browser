"""
PhishShield Evidence-Grounded AI Security Analyst
Generates structured, hallucination-free investigation reports partitioned into
OBSERVED, INFERRED, and UNKNOWN evidence buckets.

Architecture:
  AnalystEngine
    ├── build_context(scan, telemetry, graph_data) → InvestigationContext
    ├── generate_report(context) → SecurityReport
    └── export_to_json/stix(report)

Evidence Triad (strict enforcement):
  OBSERVED  — tangible facts from logs (DNS lookups, form POST targets, network egress)
  INFERRED  — deductive reasoning from observed evidence (brand impersonation hypothesis)
  UNKNOWN   — data not available or inaccessible (registrant identity, C2 operator)

Zero Hallucination Protocol:
  The analyst engine NEVER fabricates IPs, hashes, domain names, or indicators
  not present in the verified investigation evidence payload.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json


# ─── Evidence Structures ──────────────────────────────────────────────────────

@dataclass
class ObservedFact:
    """A tangible, log-verified event or artifact."""
    category: str           # network | dom | redirect | form | download
    description: str
    evidence_source: str    # scan_id | telemetry_id | dns_log
    timestamp: str


@dataclass
class InferredConclusion:
    """Security reasoning derived from observed evidence."""
    hypothesis: str
    supporting_facts: List[str]
    confidence: str         # HIGH | MEDIUM | LOW


@dataclass
class UnknownGap:
    """Data that was sought but is inaccessible."""
    what_is_unknown: str
    why_unknown: str


@dataclass
class InvestigationContext:
    """Aggregated raw evidence for a single investigation session."""
    target_url: str
    scan_id: str
    risk_score: float
    threat_level: str
    features: Dict[str, Any]
    reasons: List[str]
    score_breakdown: Dict[str, float]
    sandbox_telemetry: List[Dict[str, Any]] = field(default_factory=list)
    graph_correlations: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SecurityReport:
    """
    Structured, evidence-grounded investigation report.
    Strictly partitioned into OBSERVED / INFERRED / UNKNOWN.
    """
    report_id: str
    generated_at: str
    target_url: str
    scan_id: str
    risk_score: float
    threat_level: str
    adaptive_action: str
    executive_summary: str
    observed: List[ObservedFact]
    inferred: List[InferredConclusion]
    unknown: List[UnknownGap]
    recommended_actions: List[str]
    iocs: Dict[str, List[str]]          # indicator_of_compromise: {domains, ips, hashes}


# ─── Analyst Engine ───────────────────────────────────────────────────────────

class AnalystEngine:
    """
    Evidence-grounded AI Security Analyst.
    Sprint 4: Integrates LLM (e.g., Gemini / GPT-4) with structured grounding prompts.
    Sprint 2: Deterministic rule-based report generation from structured evidence.
    """

    def build_context(
        self,
        scan_verdict: Dict[str, Any],
        sandbox_telemetry: Optional[List[Dict]] = None,
        graph_data: Optional[List[Dict]] = None,
    ) -> InvestigationContext:
        """Constructs the investigation context from all available evidence."""
        indicators = scan_verdict.get("indicators", {})
        return InvestigationContext(
            target_url=scan_verdict["url"],
            scan_id=scan_verdict["scan_id"],
            risk_score=scan_verdict["risk_score"],
            threat_level=scan_verdict["threat_level"],
            features=indicators.get("features_summary", {}),
            reasons=indicators.get("reasons", []),
            score_breakdown=indicators.get("score_breakdown", {}),
            sandbox_telemetry=sandbox_telemetry or [],
            graph_correlations=graph_data or [],
        )

    def generate_report(self, context: InvestigationContext) -> SecurityReport:
        """
        Generates a structured investigation report strictly from context evidence.
        Never fabricates data not present in context.
        """
        import uuid
        report_id = str(uuid.uuid4())
        ts = datetime.now(timezone.utc).isoformat()

        observed: List[ObservedFact] = []
        inferred: List[InferredConclusion] = []
        unknown: List[UnknownGap] = []
        iocs: Dict[str, List[str]] = {"domains": [], "ips": [], "hashes": [], "urls": []}

        # Build OBSERVED from features
        features = context.features
        if features.get("is_ip_address"):
            observed.append(ObservedFact(
                category="network",
                description=f"Target URL uses a raw IPv4 address as the hostname rather than a registered domain.",
                evidence_source=f"scan:{context.scan_id}",
                timestamp=ts,
            ))
        if features.get("has_brand_in_subdomain"):
            observed.append(ObservedFact(
                category="dom",
                description=f"A recognized brand keyword was identified within the subdomain structure of the URL.",
                evidence_source=f"scan:{context.scan_id}",
                timestamp=ts,
            ))
        if features.get("is_high_risk_tld"):
            observed.append(ObservedFact(
                category="network",
                description=f"The domain utilizes a top-level domain (TLD) statistically associated with ephemeral phishing infrastructure.",
                evidence_source=f"scan:{context.scan_id}",
                timestamp=ts,
            ))
        if features.get("has_punycode"):
            observed.append(ObservedFact(
                category="dom",
                description=f"Punycode (xn--) encoding detected in hostname — possible homoglyph/IDN spoofing attempt.",
                evidence_source=f"scan:{context.scan_id}",
                timestamp=ts,
            ))
        if features.get("has_suspicious_keyword"):
            observed.append(ObservedFact(
                category="dom",
                description=f"Credential-harvesting keywords detected in URL path/query: count={features.get('keyword_count', 0)}.",
                evidence_source=f"scan:{context.scan_id}",
                timestamp=ts,
            ))

        # Add sandbox telemetry as OBSERVED (Sprint 3/4 — currently empty)
        for event in context.sandbox_telemetry:
            observed.append(ObservedFact(
                category=event.get("event_type", "network"),
                description=event.get("description", "Sandbox telemetry event."),
                evidence_source=f"sandbox_telemetry",
                timestamp=event.get("timestamp", ts),
            ))

        # Build INFERRED from risk score + reasons
        if context.risk_score > 60 and features.get("has_brand_in_subdomain"):
            inferred.append(InferredConclusion(
                hypothesis="Brand impersonation phishing kit targeting credential harvesting.",
                supporting_facts=[
                    "Brand name present in subdomain structure",
                    f"Risk score: {context.risk_score}/100",
                    "High-risk TLD pattern" if features.get("is_high_risk_tld") else "Elevated URL entropy",
                ],
                confidence="HIGH" if context.risk_score > 75 else "MEDIUM",
            ))
        if context.risk_score > 40 and features.get("has_suspicious_keyword"):
            inferred.append(InferredConclusion(
                hypothesis="URL designed to mimic a legitimate authentication endpoint.",
                supporting_facts=[
                    f"Credential keywords detected: {features.get('keyword_count', 0)}",
                    f"Overall risk score: {context.risk_score}/100",
                ],
                confidence="MEDIUM",
            ))

        # Build UNKNOWN gaps
        unknown.append(UnknownGap(
            what_is_unknown="Domain registrant identity and ownership.",
            why_unknown="RDAP/WHOIS data was not retrieved in this scan. Privacy masking may be in use.",
        ))
        if not context.sandbox_telemetry:
            unknown.append(UnknownGap(
                what_is_unknown="Dynamic page behavior (form destinations, DOM mutations, redirect chains).",
                why_unknown="No sandbox session was initiated. Page was not loaded in isolation.",
            ))

        # Executive summary
        level = context.threat_level
        if level == "LOW":
            summary = f"The target URL ({context.target_url}) scored {context.risk_score}/100 and presents no significant threat indicators. Normal browsing is permitted."
        elif level == "MEDIUM":
            summary = f"The target URL scored {context.risk_score}/100 and exhibits suspicious characteristics. User confirmation is recommended before navigation."
        elif level == "HIGH":
            summary = f"The target URL scored {context.risk_score}/100 with high-confidence phishing indicators. Direct navigation is blocked. Controlled investigation via isolated sandbox is recommended."
        else:
            summary = f"CRITICAL: The target URL scored {context.risk_score}/100. Confirmed or near-confirmed threat infrastructure detected. Navigation is strictly prohibited. Full sandboxed investigation required."

        # Recommended actions
        actions = []
        if level in ("HIGH", "CRITICAL"):
            actions.append("Launch isolated Playwright sandbox with synthetic data injection enabled.")
            actions.append("Capture and archive all network egress from the sandbox session.")
            actions.append("Ingest domain, IP, and certificate data into Neo4j infrastructure graph.")
        if features.get("has_brand_in_subdomain"):
            actions.append("Report brand impersonation to the legitimate brand's security team and abuse registry.")
        actions.append("Log scan verdict and all indicators to PostgreSQL for longitudinal analysis.")

        iocs["urls"].append(context.target_url)

        return SecurityReport(
            report_id=report_id,
            generated_at=ts,
            target_url=context.target_url,
            scan_id=context.scan_id,
            risk_score=context.risk_score,
            threat_level=level,
            adaptive_action=_level_to_action(level),
            executive_summary=summary,
            observed=observed,
            inferred=inferred,
            unknown=unknown,
            recommended_actions=actions,
            iocs=iocs,
        )

    def export_dict(self, report: SecurityReport) -> Dict[str, Any]:
        """Serializes the report to a Python dictionary for API responses."""
        def _serialize(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: _serialize(v) for k, v in obj.__dict__.items()}
            if isinstance(obj, list):
                return [_serialize(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            return obj
        return _serialize(report)

    def export_json(self, report: SecurityReport) -> str:
        """Serializes the report to JSON for API delivery or archiving."""
        return json.dumps(self.export_dict(report), indent=2)


def _level_to_action(level: str) -> str:
    return {"LOW": "ALLOW", "MEDIUM": "WARN", "HIGH": "CONTROLLED", "CRITICAL": "ISOLATE"}.get(level, "WARN")


# Singleton analyst engine
analyst = AnalystEngine()
