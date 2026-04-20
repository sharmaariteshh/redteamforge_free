"""
RedTeamForge — Ingest Agent
Handles PR-aware repository ingestion: clones the repo and checks out the PR head.
"""

import os
import asyncio
import shutil
import stat
from logger import get_logger

log = get_logger("ingest_agent")

def remove_readonly(func, path, _):
    """Handle read-only files when deleting git repos on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


async def ingest(data: dict, scan_id: str) -> str:
    """
    Clone repository and check out the PR head commit into a scan-isolated directory.

    data can be:
      - A webhook payload with 'pull_request' key
      - A manual scan payload with 'repo' key
    """
    pr = data.get("pull_request")

    if pr:
        # ── PR webhook mode ──────────────────────────────────
        repo_url = pr["head"]["repo"]["clone_url"]
        branch = pr["head"]["ref"]
    else:
        # ── Manual / legacy mode ─────────────────────────────
        repo_url = data.get("repo", "")
        branch = data.get("branch", "")

    if not repo_url:
        raise ValueError("No repository URL provided")

    repo_path = os.path.join("data", f"repo_{scan_id}")

    # Clean previous clone if it somehow exists
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path, onerror=remove_readonly)

    os.makedirs(repo_path, exist_ok=True)

    log.info(f"Cloning {repo_url} (branch: {branch or 'default'}) into {repo_path}")

    # Shallow clone for speed using synchronous subprocess within an async thread
    import subprocess
    if branch:
        cmd = ["git", "clone", "--depth", "1", "--branch", branch, repo_url, repo_path]
    else:
        # Defaults to HEAD (master/main/etc.)
        cmd = ["git", "clone", "--depth", "1", repo_url, repo_path]
    
    def _run_clone():
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    proc = await asyncio.to_thread(_run_clone)

    if proc.returncode != 0:
        log.error(f"git clone failed: {proc.stderr}")
        raise RuntimeError(f"git clone failed: {proc.stderr}")

    return repo_path