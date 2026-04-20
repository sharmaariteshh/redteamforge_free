"""
RedTeamForge — REST API Layer
Exposes scan data for the dashboard and external consumers.
"""

from fastapi import APIRouter, Query
from db import list_scans, get_scan, get_stats

api_router = APIRouter(prefix="/api", tags=["API"])


@api_router.get("/scans")
async def api_list_scans(
    repo: str | None = Query(None, description="Filter by repo name"),
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List scans with optional filtering."""
    scans = await list_scans(repo=repo, status=status, limit=limit, offset=offset)
    return {"scans": scans, "count": len(scans)}


@api_router.get("/scans/{scan_id}")
async def api_get_scan(scan_id: str):
    """Get detailed scan with vulnerabilities and simulations."""
    scan = await get_scan(scan_id)
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@api_router.get("/stats")
async def api_get_stats():
    """Aggregate statistics across all scans."""
    return await get_stats()
