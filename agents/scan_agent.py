"""
RedTeamForge — Scan Agent
Runs Semgrep asynchronously on changed files only for faster scans.
"""

import asyncio
import json
from config import MAX_CONCURRENT_SCANS

_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


async def static_scan(repo_path: str, changed_files: list[str] | None = None) -> str:
    """
    Run Semgrep on the repository.
    If changed_files is provided, scan only those files for speed.
    Returns raw Semgrep JSON output as a string.
    """
    if changed_files:
        # Build list of full paths that exist
        import os
        targets = []
        for f in changed_files:
            full = os.path.join(repo_path, f)
            if os.path.isfile(full):
                targets.append(full)
        if not targets:
            return "No scannable files in diff."
        target_str = " ".join(f'"{t}"' for t in targets)
    else:
        target_str = f'"{repo_path}"'

    cmd = f"semgrep --config=auto --json {target_str}"

    async with _semaphore:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

    raw = stdout.decode(errors="replace")

    # Try to extract just the findings summary for LLM context size
    try:
        data = json.loads(raw)
        results = data.get("results", [])
        if not results:
            return "Semgrep: No findings."

        lines = []
        for r in results:
            lines.append(
                f"[{r.get('check_id', 'unknown')}] "
                f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')} — "
                f"{r.get('extra', {}).get('message', 'no message')}"
            )
        return "\n".join(lines)
    except (json.JSONDecodeError, KeyError):
        # Fallback: return raw (truncated)
        return raw[:4000] if raw else f"Semgrep error: {stderr.decode(errors='replace')[:2000]}"
