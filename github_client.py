"""
RedTeamForge — GitHub API Client
Handles diff fetching, comment posting, and webhook signature verification.
"""

import hashlib
import hmac
import httpx
from config import GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, GITHUB_API_BASE


def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify the GitHub webhook HMAC-SHA256 signature."""
    if not GITHUB_WEBHOOK_SECRET:
        return True  # no secret configured — allow (dev mode)
    if not signature_header:
        return False
    expected = (
        "sha256="
        + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode(), payload_body, hashlib.sha256
        ).hexdigest()
    )
    return hmac.compare_digest(expected, signature_header)


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RedTeamForge/1.0",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


async def fetch_pr_diff(owner: str, repo: str, pr_number: int) -> str:
    """Fetch the unified diff of a pull request."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {**_headers(), "Accept": "application/vnd.github.v3.diff"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.text


async def fetch_pr_files(owner: str, repo: str, pr_number: int) -> list[dict]:
    """Return list of changed files with metadata (filename, status, patch)."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}/files"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=_headers())
        resp.raise_for_status()
        return resp.json()


async def fetch_file_content(owner: str, repo: str, path: str, ref: str) -> str:
    """Download raw file content at a specific ref (branch/SHA)."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=_headers())
        resp.raise_for_status()
        return resp.text


async def post_comment(owner: str, repo: str, pr_number: int, body: str) -> dict:
    """Post a comment on a pull request."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{pr_number}/comments"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers=_headers(), json={"body": body})
        resp.raise_for_status()
        return resp.json()


async def fetch_pr_info(owner: str, repo: str, pr_number: int) -> dict:
    """Get PR metadata (head SHA, branch, etc.)."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=_headers())
        resp.raise_for_status()
        return resp.json()
