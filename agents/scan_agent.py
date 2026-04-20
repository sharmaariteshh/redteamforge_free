"""
RedTeamForge — Scan Agent
Runs Semgrep asynchronously on changed files only for faster scans.
"""

import asyncio
import json
import os
import subprocess
import sys
from config import MAX_CONCURRENT_SCANS
from logger import get_logger

log = get_logger("scan_agent")

_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


async def static_scan(repo_path: str, changed_files: list[str] | None = None) -> str:
    """
    Run Semgrep on the repository.
    If changed_files is provided, scan only those files for speed.
    Returns parsed findings as a string.
    """
    if changed_files:
        targets = []
        for f in changed_files:
            full = os.path.join(repo_path, f)
            if os.path.isfile(full):
                targets.append(full)
        if not targets:
            log.info("No scannable files in diff")
            return "No scannable files in diff."
        target_str = " ".join(f'"{t}"' for t in targets)
    else:
        target_str = f'"{repo_path}"'

    # Force Windows console to UTF-8 before running Semgrep
    cmd = f"chcp 65001 >nul 2>&1 && semgrep --config=auto --json {target_str}"
    log.info(f"Running Semgrep on {len(changed_files) if changed_files else 'all'} files")

    async with _semaphore:
        # Build env with UTF-8 forced everywhere
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONLEGACYWINDOWSSTDIO"] = "0"

        def _run_semgrep():
            return subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=120,
            )

        try:
            proc = await asyncio.to_thread(_run_semgrep)
        except subprocess.TimeoutExpired:
            log.warning("Semgrep timed out after 120s")
            return "Semgrep: Scan timed out."

        stdout, stderr = proc.stdout, proc.stderr

    raw = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")

    # Check for charmap / encoding errors in stderr
    if "charmap" in err or "codec can't encode" in err:
        log.warning(f"Semgrep encoding issue, retrying with --no-git-ignore")
        # Retry without git-aware features which can trigger encoding bugs
        cmd_retry = f"chcp 65001 >nul 2>&1 && semgrep --config=auto --json --no-git-ignore {target_str}"
        try:
            proc2 = await asyncio.to_thread(
                lambda: subprocess.run(
                    cmd_retry, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env=env, timeout=120,
                )
            )
            raw = proc2.stdout.decode("utf-8", errors="replace")
            err2 = proc2.stderr.decode("utf-8", errors="replace")
            if "charmap" in err2 or "codec can't encode" in err2:
                log.warning("Semgrep encoding issue persists — skipping static scan")
                return "Semgrep: Skipped due to Windows encoding incompatibility. Other scanners (fuzz + LLM detection) still ran."
        except subprocess.TimeoutExpired:
            return "Semgrep: Scan timed out on retry."

    # Parse results
    try:
        data = json.loads(raw)
        results = data.get("results", [])
        if not results:
            log.info("Semgrep: No findings")
            return "Semgrep: No findings."

        lines = []
        for r in results:
            lines.append(
                f"[{r.get('check_id', 'unknown')}] "
                f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')} — "
                f"{r.get('extra', {}).get('message', 'no message')}"
            )
        log.info(f"Semgrep: {len(results)} findings")
        return "\n".join(lines)
    except (json.JSONDecodeError, KeyError):
        # If raw output is empty or not JSON, provide clean error
        if not raw.strip():
            if "charmap" in err or "codec" in err:
                return "Semgrep: Skipped due to Windows encoding incompatibility. Other scanners (fuzz + LLM detection) still ran."
            return f"Semgrep returned no output. stderr: {err[:500]}"
        return raw[:4000]
