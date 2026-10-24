"""
PhishShield Sandbox Orchestration API
Manages ephemeral investigation sessions, synthetic data injection, and behavioral telemetry for HIGH/CRITICAL-tier URLs.
Sprint 3: Ephemeral container orchestration with live telemetry waterfall recording.
"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.sandbox.orchestrator import orchestrator
from backend.app.sandbox.sdi import sdi

router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class SandboxLaunchRequest(BaseModel):
    url: str
    threat_level: str                              # HIGH | CRITICAL
    inject_synthetic_data: bool = True
    analyst_id: Optional[str] = None


class SyntheticDataProfile(BaseModel):
    card_number: str
    card_expiry: str
    card_cvv: str
    cardholder_name: str
    email: str
    password: str
    note: str


class SandboxSession(BaseModel):
    session_id: str
    url: str
    status: str                                    # launching | active | terminated | error
    threat_level: str
    synthetic_data: Optional[SyntheticDataProfile]
    launched_at: str
    container_id: Optional[str]
    telemetry_ws_url: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/launch", response_model=SandboxSession)
async def launch_sandbox(request: SandboxLaunchRequest):
    """
    Launches an ephemeral investigation sandbox for a high-risk URL.
    Generates synthetic honeypot identity and populates behavioral telemetry.
    """
    if request.threat_level not in ("HIGH", "CRITICAL"):
        raise HTTPException(
            status_code=422,
            detail="Sandbox sessions are only permitted for HIGH or CRITICAL threat levels.",
        )

    session = await orchestrator.spawn(
        url=request.url,
        inject_synthetic=request.inject_synthetic_data,
    )

    synthetic_profile = None
    if session.synthetic_identity:
        synthetic_profile = SyntheticDataProfile(
            card_number=session.synthetic_identity.get("card_number", ""),
            card_expiry=session.synthetic_identity.get("card_expiry", ""),
            card_cvv=session.synthetic_identity.get("card_cvv", ""),
            cardholder_name=session.synthetic_identity.get("cardholder_name", ""),
            email=session.synthetic_identity.get("email", ""),
            password=session.synthetic_identity.get("password", ""),
            note=session.synthetic_identity.get("watermark_note", ""),
        )

    return SandboxSession(
        session_id=session.session_id,
        url=session.url,
        status=session.status,
        threat_level=request.threat_level,
        synthetic_data=synthetic_profile,
        launched_at=session.launched_at,
        container_id=session.container_id,
        telemetry_ws_url=f"ws://localhost:8000/api/v1/sandbox/ws/telemetry/{session.session_id}",
    )


@router.get("/sessions")
async def list_sessions():
    """Lists all active sandbox sessions."""
    sessions = [s.to_dict() for s in orchestrator.list_sessions()]
    for s in sessions:
        s.pop("telemetry", None)
    return {"total": len(sessions), "sessions": sessions}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Returns full session state including telemetry log."""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return session.to_dict()


@router.get("/sessions/{session_id}/telemetry")
async def get_session_telemetry(session_id: str):
    """Returns behavioral telemetry event timeline for a session."""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    telemetry_list = [
        e.to_dict() if hasattr(e, "to_dict") else e
        for e in session.telemetry
    ]
    return {
        "session_id": session_id,
        "total_events": len(telemetry_list),
        "events": telemetry_list,
        "redirect_chain": session.redirect_chain,
    }


@router.post("/sessions/{session_id}/terminate")
async def terminate_session(session_id: str):
    """Terminates and archives a sandbox session."""
    success = await orchestrator.terminate(session_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    return {"status": "terminated", "session_id": session_id}


@router.get("/sessions/{session_id}/synthetic-data")
async def get_synthetic_data(session_id: str):
    """Returns the synthetic data profile attached to a session."""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")
    sd = session.synthetic_identity
    if not sd:
        raise HTTPException(status_code=404, detail="No synthetic data profile for this session.")
    return sd


# ─── Virtual Machine Sandbox VPN Rotation (5-Minute Cycles) ───────────────────

from backend.app.sandbox.vpn_manager import vpn_manager


@router.get("/vpn/current")
async def get_current_vpn_status():
    """Returns the current randomized VPN exit node, encryption status, and 5-min rotation timer."""
    return vpn_manager.get_status()


@router.post("/vpn/rotate")
async def force_vpn_rotation():
    """Forces immediate rotation to a new random privacy VPN exit node."""
    entry = vpn_manager.rotate(reason="Analyst manual rotation trigger")
    return {
        "status": "rotated",
        "new_node": entry,
        "vpn_state": vpn_manager.get_status(),
    }

