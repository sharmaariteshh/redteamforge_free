"""
RedTeamForge — FastAPI Application
Webhook endpoint, REST API, Dashboard, rate limiting, and validation.
"""

import os
from dotenv import load_dotenv

# Load .env before any config imports
load_dotenv()

from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from agents.orchestrator import run_pipeline
from github_client import verify_signature
from api import api_router
from db import list_scans, get_scan, get_stats
from logger import get_logger
import markdown2

log = get_logger("main")

# ── Rate Limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="RedTeamForge",
    description="Autonomous AI Red-Team Security Engine for CI/CD pipelines",
    version="3.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files & Templates ─────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

# ── Include API router ───────────────────────────────────────
app.include_router(api_router)


# ── Pydantic Models ──────────────────────────────────────────

class ScanRequest(BaseModel):
    repo: str
    branch: str = ""

class TestPRRequest(BaseModel):
    owner: str
    repo: str
    pr_number: int


# ── Health Check ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "RedTeamForge",
        "version": "3.0.0",
        "status": "running",
        "docs": "/docs",
        "dashboard": "/dashboard",
    }


# ── GitHub Webhook Endpoint ──────────────────────────────────

@app.post("/github/webhook")
@limiter.limit("30/minute")
async def github_webhook(request: Request, bg: BackgroundTasks):
    """
    Receives GitHub webhook events.
    Processes 'pull_request' events with action 'opened' or 'synchronize'.
    """
    # Verify signature
    body = await request.body()
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(body, sig):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = await request.json()
    event = request.headers.get("X-GitHub-Event", "")

    # Only process PR events
    if event != "pull_request":
        return {"status": "ignored", "event": event}

    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "action": action}

    pr = payload.get("pull_request", {})
    pr_number = pr.get("number", "?")
    repo_name = payload.get("repository", {}).get("full_name", "?")

    log.info(f"Webhook: PR #{pr_number} on {repo_name} ({action})")

    # Run pipeline in background
    bg.add_task(run_pipeline, payload)

    return {
        "status": "processing",
        "pr": pr_number,
        "repo": repo_name,
    }


# ── Manual Scan Endpoint ─────────────────────────────────────

@app.post("/scan")
async def scan(data: ScanRequest, bg: BackgroundTasks):
    """
    Manual scan endpoint.
    Body: {"repo": "https://github.com/user/repo.git", "branch": "main"}
    """
    bg.add_task(run_pipeline, data.model_dump())
    return {"status": "started", "repo": data.repo}


# ── Test Endpoint (simulate webhook locally) ─────────────────

@app.post("/test/pr")
async def test_pr(data: TestPRRequest):
    """
    Synchronous test endpoint — runs the full pipeline and returns the report.
    Body: {"owner": "user", "repo": "repo", "pr_number": 1}
    """
    from github_client import fetch_pr_info

    pr_info = await fetch_pr_info(data.owner, data.repo, data.pr_number)

    # Build a synthetic webhook payload
    payload = {
        "action": "opened",
        "pull_request": pr_info,
        "repository": pr_info["base"]["repo"],
    }

    report = await run_pipeline(payload)
    return {"status": "done", "report": report}


# ── Dashboard Routes ─────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    repo: str | None = None,
    status: str | None = None,
):
    """Main dashboard page — scan history and statistics."""
    scans = await list_scans(repo=repo, status=status, limit=50)
    stats = await get_stats()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "scans": scans,
            "stats": stats,
            "filter_repo": repo or "",
            "filter_status": status or "",
        },
    )


@app.get("/dashboard/scan/{scan_id}", response_class=HTMLResponse)
async def dashboard_scan_detail(request: Request, scan_id: str):
    """Scan detail page — full report with vulnerabilities and simulations."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Convert markdown report to HTML
    report_html = ""
    if scan.get("report"):
        report_html = markdown2.markdown(
            scan["report"],
            extras=["tables", "fenced-code-blocks", "header-ids", "break-on-newline"],
        )

    return templates.TemplateResponse(
        request=request,
        name="scan_detail.html",
        context={
            "scan": scan,
            "report_html": report_html,
        },
    )


# ── Run with: uvicorn main:app --reload ──────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
