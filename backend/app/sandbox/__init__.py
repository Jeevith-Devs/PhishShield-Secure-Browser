"""
PhishShield Sandbox Module
Playwright + Docker orchestration for ephemeral investigation sessions.
"""
from backend.app.sandbox.orchestrator import SandboxOrchestrator, ContainerSession, TelemetryEvent, orchestrator
from backend.app.sandbox.sdi import SDIEngine, SyntheticIdentity, sdi

__all__ = [
    "SandboxOrchestrator",
    "ContainerSession",
    "TelemetryEvent",
    "orchestrator",
    "SDIEngine",
    "SyntheticIdentity",
    "sdi",
]
