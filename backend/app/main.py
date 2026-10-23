"""
PhishShield Security Backend — Refactored API Gateway
Sprint 2 MVP: modular routers, CORS, lifespan, OpenAPI configuration.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    print("[PhishShield] Security Intelligence API starting up …")
    yield
    print("[PhishShield] API shutting down.")


app = FastAPI(
    title="PhishShield Security Intelligence API",
    description=(
        "Backend API for Deep Learning Cyber Threat Detection, "
        "Multidimensional Risk Adaptation, Synthetic Data Injection, "
        "and Ephemeral Sandboxed Investigation."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from backend.app.api.health import router as health_router
from backend.app.api.scan import router as scan_router
from backend.app.api.sandbox import router as sandbox_router
from backend.app.api.intel import router as intel_router
from backend.app.api.analyst import router as analyst_router
from backend.app.api.graph import router as graph_router

app.include_router(health_router, tags=["System"])
app.include_router(scan_router, prefix="/api/v1/scan", tags=["Detection & Risk"])
app.include_router(sandbox_router, prefix="/api/v1/sandbox", tags=["Sandboxing"])
app.include_router(intel_router, prefix="/api/v1/intel", tags=["Threat Intelligence"])
app.include_router(analyst_router, prefix="/api/v1/analyst", tags=["AI Security Analyst"])
app.include_router(graph_router, prefix="/api/v1/graph", tags=["Threat Graph & Campaigns"])


@app.get("/", tags=["System"])
async def root():
    return {
        "service": "PhishShield Security Intelligence API",
        "tagline": "DETECT. ADAPT. ISOLATE. EXPLAIN.",
        "docs": "/docs",
        "health": "/health",
    }
