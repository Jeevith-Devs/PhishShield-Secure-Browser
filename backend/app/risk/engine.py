"""
PhishShield Multidimensional Risk Scoring & Adaptive Decision Engine
Fuses ML/DL inferences, domain reputation, infrastructure signals,
behavioral telemetry, and threat intelligence into an actionable risk posture.
"""

from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AdaptiveAction(str, Enum):
    ALLOW = "ALLOW"             # Direct navigation allowed
    WARN = "WARN"               # Pre-navigation warning gate displayed
    CONTROLLED = "CONTROLLED"   # Ephemeral sandbox container with synthetic data injection
    ISOLATE = "ISOLATE"         # Deep headless sandbox; direct client interaction blocked

@dataclass
class RiskWeights:
    ml_prediction: float = 0.40
    domain_reputation: float = 0.20
    infrastructure: float = 0.15
    dynamic_behavior: float = 0.15
    threat_intel: float = 0.10

@dataclass
class RiskEvaluationResult:
    url: str
    composite_risk_score: float  # 0.0 to 100.0
    threat_level: ThreatLevel
    adaptive_action: AdaptiveAction
    confidence: float
    score_breakdown: Dict[str, float]
    reasons: list[str]

class RiskEngine:
    """
    Computes composite risk and arbitrates the adaptive browsing posture.
    """
    def __init__(self, weights: RiskWeights = RiskWeights()):
        self.weights = weights

    def evaluate(
        self,
        url: str,
        ml_probability: float,                  # 0.0 to 1.0
        domain_risk_score: float = 0.0,         # 0.0 to 100.0
        infrastructure_risk_score: float = 0.0, # 0.0 to 100.0
        behavior_risk_score: float = 0.0,       # 0.0 to 100.0
        threat_intel_score: float = 0.0,        # 0.0 to 100.0
        features: Dict[str, Any] = None
    ) -> RiskEvaluationResult:
        """
        Calculates normalized composite score (0-100) and maps to adaptive action.
        """
        # Convert ml_probability (0-1) to 0-100 scale
        ml_score = max(0.0, min(100.0, ml_probability * 100.0))
        dom_score = max(0.0, min(100.0, domain_risk_score))
        inf_score = max(0.0, min(100.0, infrastructure_risk_score))
        beh_score = max(0.0, min(100.0, behavior_risk_score))
        ti_score = max(0.0, min(100.0, threat_intel_score))

        composite = (
            (ml_score * self.weights.ml_prediction) +
            (dom_score * self.weights.domain_reputation) +
            (inf_score * self.weights.infrastructure) +
            (beh_score * self.weights.dynamic_behavior) +
            (ti_score * self.weights.threat_intel)
        )

        composite = round(min(100.0, max(0.0, composite)), 2)

        # Classify threat level & adaptive posture
        reasons = []
        if composite <= 30.0:
            level = ThreatLevel.LOW
            action = AdaptiveAction.ALLOW
            confidence = 0.95 - (composite / 100.0 * 0.1)
        elif composite <= 60.0:
            level = ThreatLevel.MEDIUM
            action = AdaptiveAction.WARN
            confidence = 0.85
            reasons.append("Elevated risk detected; user confirmation recommended before navigation.")
        elif composite <= 80.0:
            level = ThreatLevel.HIGH
            action = AdaptiveAction.CONTROLLED
            confidence = 0.90
            reasons.append("High probability of credential harvesting or brand impersonation.")
            reasons.append("Routing to isolated container with synthetic credentials enabled.")
        else:
            level = ThreatLevel.CRITICAL
            action = AdaptiveAction.ISOLATE
            confidence = 0.96
            reasons.append("Confirmed or critical threat infrastructure detected.")
            reasons.append("Direct navigation strictly blocked; routing to isolated sandbox.")

        if features:
            if features.get("is_ip_address"):
                reasons.append("Host utilizes direct IP address instead of registered domain.")
            if features.get("has_brand_in_subdomain"):
                reasons.append("Brand name detected in subdomain structure.")
            if features.get("is_high_risk_tld"):
                reasons.append("Domain utilizes top-level domain frequently associated with abuse.")
            if features.get("has_punycode"):
                reasons.append("Punycode / homoglyph characters detected in hostname.")

        breakdown = {
            "ml_model_contribution": round(ml_score * self.weights.ml_prediction, 2),
            "domain_contribution": round(dom_score * self.weights.domain_reputation, 2),
            "infrastructure_contribution": round(inf_score * self.weights.infrastructure, 2),
            "behavior_contribution": round(beh_score * self.weights.dynamic_behavior, 2),
            "threat_intel_contribution": round(ti_score * self.weights.threat_intel, 2),
        }

        return RiskEvaluationResult(
            url=url,
            composite_risk_score=composite,
            threat_level=level,
            adaptive_action=action,
            confidence=round(confidence, 2),
            score_breakdown=breakdown,
            reasons=reasons
        )
