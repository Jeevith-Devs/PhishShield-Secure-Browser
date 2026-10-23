"""
PhishShield System Health & Status Endpoints
"""
import time
from fastapi import APIRouter

router = APIRouter()

START_TIME = time.time()


@router.get("/health")
async def health_check():
    """Deep health check including uptime."""
    uptime_seconds = round(time.time() - START_TIME, 1)
    return {
        "status": "healthy",
        "service": "PhishShield Security Intelligence API",
        "version": "1.0.0",
        "tagline": "DETECT. ADAPT. ISOLATE. EXPLAIN.",
        "uptime_seconds": uptime_seconds,
        "components": {
            "feature_engine": "operational",
            "risk_engine": "operational",
            "threat_intel": "stub_mode",
            "sandbox": "stub_mode",
            "graph_db": "stub_mode",
        },
    }


@router.get("/version")
async def version():
    return {"version": "1.0.0", "sprint": "2", "phase": "MVP"}
