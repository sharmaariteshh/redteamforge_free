"""
RedTeamForge — Ingest Agent
Handles PR-aware repository ingestion: clones the repo and checks out the PR head.
"""

import os
import asyncio
import shutil
from config import REPO_DIR


async def ingest(data: dict) -> str:
    """
    Clone repository and check out the PR head commit.

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
        branch = data.get("branch", "main")

    if not repo_url:
        raise ValueError("No repository URL provided")

    # Clean previous clone
    if os.path.exists(REPO_DIR):
        shutil.rmtree(REPO_DIR, ignore_errors=True)

    os.makedirs(REPO_DIR, exist_ok=True)

    # Shallow clone for speed
    cmd = f'git clone --depth 1 --branch {branch} "{repo_url}" "{REPO_DIR}"'
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode()}")

    return REPO_DIR