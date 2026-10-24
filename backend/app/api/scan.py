"""
PhishShield URL Scan API
REST endpoints for URL threat detection, risk scoring, and scan history.
"""
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ml.features.url_features import extract_url_features
from ml.models.inference import predict
from backend.app.risk.engine import RiskEngine

router = APIRouter()
risk_engine = RiskEngine()

# In-memory scan history (replace with PostgreSQL in Sprint 3)
_scan_history: List[Dict[str, Any]] = []
MAX_HISTORY = 500


# ─── Request / Response Schemas ───────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    client_type: Optional[str] = "extension"   # "extension" | "browser" | "api"
    session_id: Optional[str] = None


class BatchScanRequest(BaseModel):
    urls: List[str]
    client_type: Optional[str] = "api"


class RiskVerdict(BaseModel):
    scan_id: str
    url: str
    risk_score: float
    threat_level: str
    adaptive_action: str
    confidence: float
    indicators: Dict[str, Any]
    scan_timestamp: str
    client_type: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _compute_heuristic_prob(features: Dict[str, Any]) -> float:
    """Fast lexical heuristic probability before full ML inference."""
    risk = 0.0
    if features["is_ip_address"]:
        risk += 0.35
    if features["has_brand_in_subdomain"]:
        risk += 0.40
    if features["is_high_risk_tld"]:
        risk += 0.25
    if features["has_suspicious_keyword"]:
        risk += 0.15 * min(3, features["keyword_count"])
    if features["has_punycode"]:
        risk += 0.30
    if features["subdomain_count"] > 3:
        risk += 0.20
    if features["url_length"] > 100:
        risk += 0.10
    if features["at_count"] > 0:
        risk += 0.25
    if features["has_double_slash_in_path"]:
        risk += 0.15
    return min(0.99, max(0.02, risk))


def _run_scan(url: str, client_type: str, session_id: Optional[str] = None) -> RiskVerdict:
    features = extract_url_features(url)
    try:
        ml_prob, model_name = predict(features)
    except Exception:
        ml_prob = _compute_heuristic_prob(features)
        model_name = "Heuristic (fallback)"

    # Compute multidimensional risk dimensions from verified indicators
    dom_score = 0.0
    if features.get("is_high_risk_tld"):
        dom_score += 40.0
    if features.get("has_brand_in_subdomain"):
        dom_score += 50.0
    if features.get("has_punycode"):
        dom_score += 30.0
    if features.get("subdomain_count", 0) >= 3:
        dom_score += 20.0
    dom_score = min(100.0, dom_score)

    inf_score = 0.0
    if features.get("is_ip_address"):
        inf_score += 85.0
    if features.get("at_count", 0) > 0:
        inf_score += 40.0
    if features.get("has_double_slash_in_path"):
        inf_score += 30.0
    inf_score = min(100.0, inf_score)

    beh_score = 0.0
    if features.get("has_suspicious_keyword"):
        beh_score = min(100.0, 30.0 * features.get("keyword_count", 1))

    ti_score = 0.0
    if dom_score >= 50.0 or inf_score >= 50.0:
        ti_score = 75.0
    if features.get("is_high_risk_tld") and (features.get("has_brand_in_subdomain") or features.get("has_suspicious_keyword")):
        ti_score = 90.0

    evaluation = risk_engine.evaluate(
        url=url,
        ml_probability=ml_prob,
        domain_risk_score=dom_score,
        infrastructure_risk_score=inf_score,
        behavior_risk_score=beh_score,
        threat_intel_score=ti_score,
        features=features,
    )
    scan_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    verdict = RiskVerdict(
        scan_id=scan_id,
        url=evaluation.url,
        risk_score=evaluation.composite_risk_score,
        threat_level=evaluation.threat_level.value,
        adaptive_action=evaluation.adaptive_action.value,
        confidence=evaluation.confidence,
        indicators={
            "model_used": model_name,
            "score_breakdown": evaluation.score_breakdown,
            "reasons": evaluation.reasons,
            "features_summary": {
                "url_length": features["url_length"],
                "entropy": features["url_entropy"],
                "subdomain_count": features["subdomain_count"],
                "is_ip_address": bool(features["is_ip_address"]),
                "is_https": bool(features["is_https"]),
                "is_high_risk_tld": bool(features["is_high_risk_tld"]),
                "has_brand_in_subdomain": bool(features["has_brand_in_subdomain"]),
                "has_suspicious_keyword": bool(features["has_suspicious_keyword"]),
                "keyword_count": features["keyword_count"],
                "has_punycode": bool(features["has_punycode"]),
                "at_count": features["at_count"],
            },
        },
        scan_timestamp=ts,
        client_type=client_type,
    )
    # Persist to history ring-buffer
    entry = verdict.model_dump()
    entry["session_id"] = session_id
    _scan_history.append(entry)
    if len(_scan_history) > MAX_HISTORY:
        _scan_history.pop(0)
    return verdict


# ─── REST Endpoints ───────────────────────────────────────────────────────────

@router.post("/url", response_model=RiskVerdict)
async def scan_url(request: ScanRequest):
    """
    Single URL scan: extracts 38-feature vector, scores multidimensional risk,
    and returns threat level + adaptive action verdict.
    """
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=422, detail="url field is required and cannot be empty.")
    verdict = _run_scan(request.url.strip(), request.client_type or "extension", request.session_id)
    try:
        from backend.app.graph.schema import graph
        await graph.ingest_scan(verdict.model_dump())
    except Exception:
        pass
    return verdict


@router.post("/batch", response_model=List[RiskVerdict])
async def scan_batch(request: BatchScanRequest):
    """
    Batch URL scan — up to 50 URLs per request.
    """
    if not request.urls:
        raise HTTPException(status_code=422, detail="urls list cannot be empty.")
    if len(request.urls) > 50:
        raise HTTPException(status_code=422, detail="Maximum 50 URLs per batch request.")
    return [_run_scan(url.strip(), request.client_type or "api") for url in request.urls if url.strip()]


@router.get("/history")
async def get_scan_history(limit: int = 50, threat_level: Optional[str] = None):
    """
    Returns recent scan history, optionally filtered by threat level.
    """
    result = list(reversed(_scan_history))
    if threat_level:
        result = [r for r in result if r.get("threat_level") == threat_level.upper()]
    return {"total": len(result), "scans": result[:min(limit, 200)]}


@router.get("/stats")
async def get_scan_stats():
    """Aggregate statistics over in-memory scan history."""
    total = len(_scan_history)
    if total == 0:
        return {"total_scans": 0}
    breakdown = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for s in _scan_history:
        breakdown[s.get("threat_level", "LOW")] = breakdown.get(s.get("threat_level", "LOW"), 0) + 1
    avg_score = round(sum(s.get("risk_score", 0) for s in _scan_history) / total, 2)
    return {
        "total_scans": total,
        "threat_level_breakdown": breakdown,
        "average_risk_score": avg_score,
    }


# ─── WebSocket Live Scanner ───────────────────────────────────────────────────

@router.websocket("/ws/live")
async def websocket_live_scan(websocket: WebSocket):
    """
    WebSocket live scanner: accepts URL strings and streams back RiskVerdict JSON.
    Used by the SOC dashboard for real-time analysis.
    """
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            url = data.strip()
            if not url:
                await websocket.send_json({"error": "empty URL received"})
                continue
            try:
                verdict = _run_scan(url, "websocket")
                await websocket.send_json(verdict.model_dump())
            except Exception as e:
                await websocket.send_json({"error": str(e), "url": url})
    except WebSocketDisconnect:
        pass
