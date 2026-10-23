"""
PhishShield Infrastructure Graph API
Endpoints for Neo4j threat graph exploration, infrastructure correlation, and campaign clustering.
"""
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.graph.schema import graph

router = APIRouter()


class CorrelateRequest(BaseModel):
    url: Optional[str] = None
    domain: Optional[str] = None


@router.get("/overview")
async def graph_overview():
    """
    Returns high-level graph statistics: total nodes, edges, node types, and active campaigns.
    """
    return await graph.get_graph_overview()


@router.get("/domain/{domain}")
async def get_domain_graph(domain: str):
    """
    Returns the infrastructure graph nodes and edges centered on the target domain.
    Includes resolved IPs, ASNs, SSL Certificates, and Campaign links.
    """
    if not domain or domain.strip() == "":
        raise HTTPException(status_code=422, detail="Domain cannot be empty.")
    
    clean_domain = domain.lower().strip()
    if "/" in clean_domain:
        clean_domain = clean_domain.split("/")[0]
    return await graph.get_domain_graph(clean_domain)


@router.get("/campaigns")
async def get_campaigns():
    """
    Returns detected threat campaign clusters based on shared infrastructure and hosting patterns.
    """
    clusters = await graph.get_campaign_clusters()
    return {"total": len(clusters), "campaigns": clusters}


@router.get("/related/{domain}")
async def get_related_domains(domain: str):
    """
    Returns domains co-hosted on identical IP/ASN infrastructure.
    """
    clean_domain = domain.lower().strip()
    related = await graph.find_related_domains(clean_domain)
    return {"domain": clean_domain, "total_related": len(related), "related": related}


@router.post("/correlate")
async def correlate_target(request: CorrelateRequest):
    """
    Accepts a URL or domain and returns full multi-hop graph correlations and campaign indicators.
    """
    target_domain = request.domain
    if not target_domain and request.url:
        parsed = urlparse(request.url if request.url.startswith("http") else f"http://{request.url}")
        target_domain = parsed.hostname or request.url
    
    if not target_domain:
        raise HTTPException(status_code=422, detail="Either domain or url must be provided.")
    
    graph_data = await graph.get_domain_graph(target_domain)
    related = await graph.find_related_domains(target_domain)
    campaigns = await graph.get_campaign_clusters()

    return {
        "target_domain": target_domain,
        "graph": graph_data,
        "shared_infrastructure": related,
        "campaign_matches": [
            c for c in campaigns
            if target_domain in c.get("domains", []) or any(e.get("relationship") == "PART_OF" for e in graph_data.get("edges", []))
        ],
    }
