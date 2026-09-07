"""
PhishShield Security Backend API Gateway
Defensive Intelligence, Detection, Risk Adaptation, and Sandboxed Investigation
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Dict, Any, Optional

app = FastAPI(
    title="PhishShield Security Intelligence API",
    description="Backend API for Deep Learning Cyber Threat Detection, Risk Adaptation, and Ephemeral Sandboxing",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    client_type: Optional[str] = "extension" # "browser" | "extension"

class RiskVerdict(BaseModel):
    url: str
    risk_score: float # 0 to 100
    threat_level: str # LOW | MEDIUM | HIGH | CRITICAL
    adaptive_action: str # ALLOW | WARN | CONTROLLED | ISOLATE
    confidence: float
    indicators: Dict[str, Any]

@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "service": "PhishShield Security Intelligence API",
        "version": "1.0.0",
        "tagline": "DETECT. ADAPT. ISOLATE. EXPLAIN."
    }

import sys
import os

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ml.features.url_features import extract_url_features
from backend.app.risk.engine import RiskEngine

risk_engine = RiskEngine()

@app.post("/api/v1/scan/url", response_model=RiskVerdict, tags=["Detection & Risk"])
async def scan_url(request: ScanRequest):
    """
    Initial URL analysis endpoint:
    Performs fast lexical extraction, heuristic/ML risk scoring, and calculates the multidimensional risk posture.
    """
    features = extract_url_features(request.url)

    # Heuristic probability baseline before full offline ML weight loading
    risk_signals = 0.0
    if features["is_ip_address"]:
        risk_signals += 0.35
    if features["has_brand_in_subdomain"]:
        risk_signals += 0.40
    if features["is_high_risk_tld"]:
        risk_signals += 0.25
    if features["has_suspicious_keyword"]:
        risk_signals += 0.15 * min(3, features["keyword_count"])
    if features["has_punycode"]:
        risk_signals += 0.30
    if features["subdomain_count"] > 3:
        risk_signals += 0.20

    heuristic_ml_prob = min(0.99, max(0.02, risk_signals))

    evaluation = risk_engine.evaluate(
        url=request.url,
        ml_probability=heuristic_ml_prob,
        features=features
    )

    return RiskVerdict(
        url=evaluation.url,
        risk_score=evaluation.composite_risk_score,
        threat_level=evaluation.threat_level.value,
        adaptive_action=evaluation.adaptive_action.value,
        confidence=evaluation.confidence,
        indicators={
            "score_breakdown": evaluation.score_breakdown,
            "reasons": evaluation.reasons,
            "features_summary": {
                "url_length": features["url_length"],
                "entropy": features["url_entropy"],
                "subdomain_count": features["subdomain_count"],
                "is_ip_address": bool(features["is_ip_address"]),
                "is_high_risk_tld": bool(features["is_high_risk_tld"]),
                "has_brand_in_subdomain": bool(features["has_brand_in_subdomain"]),
            }
        }
    )

