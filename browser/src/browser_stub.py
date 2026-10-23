"""
PhishShield Browser Module
Hardened Chromium/Electron secure browser implementation.
Sprint 2: Architecture stubs and README.
Sprint Enterprise: Full Electron build with custom isolation controls.
"""

BROWSER_FEATURES = [
    "Memory-only cache (no disk persistence)",
    "Zero cookie persistence across isolated domains",
    "Disabled WebRTC local IP enumeration",
    "Mandatory egress routing through PhishShield security proxy",
    "Integrated risk indicator overlay",
    "Native navigation barrier dialogs",
    "Timeline rendering of sandbox telemetry",
]
