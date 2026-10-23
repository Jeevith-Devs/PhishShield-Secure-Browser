"""
PhishShield API Router Package
Aggregates all v1 API route modules.
"""
from fastapi import APIRouter
from backend.app.api import scan, health, sandbox, intel, analyst, graph

router = APIRouter()
router.include_router(health.router, tags=["System"])
router.include_router(scan.router, prefix="/scan", tags=["Detection & Risk"])
router.include_router(sandbox.router, prefix="/sandbox", tags=["Sandboxing"])
router.include_router(intel.router, prefix="/intel", tags=["Threat Intelligence"])
router.include_router(analyst.router, prefix="/analyst", tags=["AI Security Analyst"])
router.include_router(graph.router, prefix="/graph", tags=["Threat Graph & Campaigns"])
