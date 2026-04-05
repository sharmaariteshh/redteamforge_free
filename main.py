"""
RedTeamForge — FastAPI Application
Webhook endpoint for GitHub PR events + manual scan endpoint.
"""

import os
from dotenv import load_dotenv

# Load .env before any config imports
load_dotenv()

from fastapi import FastAPI, BackgroundTasks, Request, HTTPException
from fastapi.responses import JSONResponse
from agents.orchestrator import run_pipeline
from github_client import verify_signature

app = FastAPI(
    title="RedTeamForge",
    description="Autonomous AI Red-Team Security Engine for CI/CD pipelines",
    version="2.0.0",
)


# ── Health Check ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "RedTeamForge",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
    }


# ── GitHub Webhook Endpoint ──────────────────────────────────

@app.post("/github/webhook")
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

    print(f"🔔 Webhook: PR #{pr_number} on {repo_name} ({action})")

    # Run pipeline in background
    bg.add_task(run_pipeline, payload)

    return {
        "status": "processing",
        "pr": pr_number,
        "repo": repo_name,
    }


# ── Manual Scan Endpoint ─────────────────────────────────────

@app.post("/scan")
async def scan(data: dict, bg: BackgroundTasks):
    """
    Manual scan endpoint.
    Body: {"repo": "https://github.com/user/repo.git", "branch": "main"}
    """
    bg.add_task(run_pipeline, data)
    return {"status": "started", "repo": data.get("repo", "?")}


# ── Test Endpoint (simulate webhook locally) ─────────────────

@app.post("/test/pr")
async def test_pr(data: dict):
    """
    Synchronous test endpoint — runs the full pipeline and returns the report.
    Body: {"owner": "user", "repo": "repo", "pr_number": 1}
    """
    from github_client import fetch_pr_info

    owner = data["owner"]
    repo = data["repo"]
    pr_number = data["pr_number"]

    pr_info = await fetch_pr_info(owner, repo, pr_number)

    # Build a synthetic webhook payload
    payload = {
        "action": "opened",
        "pull_request": pr_info,
        "repository": pr_info["base"]["repo"],
    }

    report = await run_pipeline(payload)
    return {"status": "done", "report": report}


# ── Run with: uvicorn main:app --reload ──────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
