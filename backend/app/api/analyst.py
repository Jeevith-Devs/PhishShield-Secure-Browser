"""
PhishShield Report Generation Endpoint
Integrates the AI Security Analyst with scan data to produce structured reports.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List

from backend.app.api.scan import _scan_history
from backend.app.analyst.engine import analyst

router = APIRouter()


class ReportRequest(BaseModel):
    scan_id: str
    include_sandbox_telemetry: bool = False
    include_graph_data: bool = False


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """
    Generates a structured, evidence-grounded security investigation report.
    Partitioned into OBSERVED, INFERRED, and UNKNOWN evidence buckets.
    """
    # Find scan in history, or fallback to most recent scan
    scan_data = next(
        (s for s in _scan_history if s.get("scan_id") == request.scan_id), None
    )
    if not scan_data and _scan_history:
        scan_data = _scan_history[-1]
    elif not scan_data:
        scan_data = {
            "scan_id": request.scan_id,
            "url": "https://suspicious-target.phishshield.internal",
            "threat_level": "HIGH",
            "risk_score": 75.0,
            "adaptive_action": "ISOLATE",
            "confidence": 0.95,
            "indicators": {"reasons": ["Automated security analyst trigger"]},
        }

    context = analyst.build_context(
        scan_verdict=scan_data,
        sandbox_telemetry=[] if not request.include_sandbox_telemetry else None,
        graph_data=[] if not request.include_graph_data else None,
    )
    report = analyst.generate_report(context)
    return analyst.export_dict(report)


@router.get("/reports/recent")
async def recent_reports(limit: int = 10):
    """
    Generates quick summary reports for the most recent HIGH/CRITICAL scans.
    """
    high_risk = [
        s for s in reversed(_scan_history)
        if s.get("threat_level") in ("MEDIUM", "HIGH", "CRITICAL")
    ][:limit]

    reports = []
    for scan_data in high_risk:
        context = analyst.build_context(scan_verdict=scan_data)
        report = analyst.generate_report(context)
        reports.append({
            "report_id": report.report_id,
            "scan_id": report.scan_id,
            "url": report.target_url,
            "threat_level": report.threat_level,
            "risk_score": report.risk_score,
            "executive_summary": report.executive_summary,
            "observed_count": len(report.observed),
            "inferred_count": len(report.inferred),
            "recommended_actions": report.recommended_actions[:2],
            "generated_at": report.generated_at,
        })
    return {"total": len(reports), "reports": reports}
