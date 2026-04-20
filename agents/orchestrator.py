"""
RedTeamForge — Orchestrator
Coordinates the full PR analysis pipeline:
  Ingest → Diff Parse → Parallel (Scan + Fuzz + LLM Detect) → Attack Engine → LLM Analysis → Report → Comment
Now with scan_id tracking, DB persistence, GitHub status checks, and structured logging.
"""

import asyncio
import json
import traceback

from agents.ingest_agent import ingest
from agents.scan_agent import static_scan
from agents.fuzz_agent import fuzz
from agents.llm_agent import analyze
from agents.report_agent import generate_report, compute_risk_score

from diff_parser import parse_pr_files_response, changed_paths
from llm_detector import scan_files, LLMDetection
from attack_engine import simulate_attacks
from github_client import fetch_pr_files, fetch_file_content, post_comment, set_commit_status
from db import (
    get_cached, set_cached, generate_scan_id,
    create_scan, update_scan, save_vulnerabilities, save_simulations,
)
from config import PIPELINE_TIMEOUT_SECS
from logger import get_logger, set_scan_id

log = get_logger("orchestrator")


async def run_pipeline(data: dict) -> str:
    """
    Full analysis pipeline. Returns the markdown report string.
    Also posts the report as a GitHub PR comment if webhook data is present.
    """
    scan_id = generate_scan_id()
    set_scan_id(scan_id)

    pr = data.get("pull_request")
    owner = ""
    repo_name = ""
    pr_number = 0
    pr_url = ""
    head_sha = ""
    full_name = ""

    if pr:
        full_name = pr["base"]["repo"]["full_name"]
        owner, repo_name = full_name.split("/")
        pr_number = pr["number"]
        pr_url = pr["html_url"]
        head_sha = pr["head"]["sha"]

    try:
        log.info(f"Pipeline started — PR #{pr_number} on {full_name or 'manual'}")

        # ── Create scan record ────────────────────────────
        await create_scan(
            scan_id=scan_id,
            repo=full_name or data.get("repo", "unknown"),
            pr_number=pr_number or None,
            pr_url=pr_url,
            head_sha=head_sha,
        )
        await update_scan(scan_id, status="running")

        # ── Set GitHub status: pending ────────────────────
        if pr and owner and head_sha:
            try:
                await set_commit_status(
                    owner, repo_name, head_sha,
                    "pending", "RedTeamForge is scanning this PR..."
                )
            except Exception as e:
                log.warning(f"Could not set pending status: {e}")

        # ── Check cache ───────────────────────────────────
        if pr and head_sha:
            cached = await get_cached(full_name, head_sha)
            if cached:
                log.info("Cache hit — returning cached report")
                await update_scan(scan_id, status="completed", report=cached.get("report", ""))
                return cached.get("report", "")

        # ── Step 1: Ingest (clone repo) ───────────────────
        repo_path = await ingest(data, scan_id)
        log.info(f"Ingest complete (path: {repo_path})")

        # ── Step 2: Get changed files ─────────────────────
        changed = []
        file_paths = []
        if pr and owner:
            pr_files_json = await fetch_pr_files(owner, repo_name, pr_number)
            changed = parse_pr_files_response(pr_files_json)
            file_paths = changed_paths(changed, extensions={".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".yaml", ".yml", ".json"})
            log.info(f"Changed files: {len(file_paths)}")
        else:
            log.info("Full repo scan (no PR context)")

        # ── Step 3: Fetch file contents for LLM detection ─
        file_contents: dict[str, str] = {}
        if pr and owner and file_paths:
            head_ref = pr["head"]["ref"]
            fetch_tasks = [
                _fetch_safe(owner, repo_name, p, head_ref)
                for p in file_paths[:30]
            ]
            results = await asyncio.gather(*fetch_tasks)
            for path, content in zip(file_paths[:30], results):
                if content is not None:
                    file_contents[path] = content
        else:
            import os
            for root, dirs, files in os.walk(repo_path):
                for fname in files:
                    if any(fname.endswith(ext) for ext in (".py", ".js", ".ts", ".go", ".java")):
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, repo_path)
                        try:
                            with open(fpath, "r", errors="replace") as f:
                                file_contents[rel] = f.read()
                        except Exception:
                            pass

        # ── Step 4: Parallel — Scan + Fuzz + LLM Detect ───
        scan_task = static_scan(repo_path, file_paths or None)
        fuzz_task = fuzz(repo_path, file_contents)
        llm_detect_task = asyncio.to_thread(scan_files, file_contents)

        scan_results, fuzz_results, llm_detections = await asyncio.wait_for(
            asyncio.gather(scan_task, fuzz_task, llm_detect_task),
            timeout=PIPELINE_TIMEOUT_SECS,
        )
        log.info("Scan + Fuzz + LLM detection complete")

        # ── Step 5: Attack simulation ─────────────────────
        attacks = simulate_attacks(scan_results, fuzz_results)
        log.info(f"Attack simulations: {len(attacks)}")

        # ── Step 6: LLM expert analysis ──────────────────
        llm_det_text = ""
        if llm_detections:
            llm_det_text = "\n".join(
                f"- {d.file}:{d.line} — {d.pattern} ({d.category})"
                for d in llm_detections
            )

        llm_analysis = await analyze(scan_results, fuzz_results, llm_det_text)
        log.info("LLM analysis complete")

        # ── Step 7: Generate report ───────────────────────
        risk_score = compute_risk_score(scan_results, attacks, llm_detections)

        report = generate_report(
            scan_results=scan_results,
            fuzz_results=fuzz_results,
            llm_analysis=llm_analysis,
            attacks=attacks,
            llm_detections=llm_detections,
            pr_url=pr_url,
        )
        log.info(f"Report generated — risk score: {risk_score}/100")

        # ── Step 8: Persist to database ───────────────────
        await update_scan(scan_id, status="completed", risk_score=risk_score, report=report)

        # Save vulnerabilities from scan results + LLM detections
        vuln_records = _extract_vulns(scan_results, llm_detections)
        await save_vulnerabilities(scan_id, vuln_records)

        # Save attack simulations
        await save_simulations(scan_id, attacks)

        # ── Step 9: Post comment to GitHub ────────────────
        if pr and owner and pr_number:
            try:
                await post_comment(owner, repo_name, pr_number, report)
                log.info(f"Comment posted to PR #{pr_number}")
            except Exception as e:
                log.error(f"Failed to post comment: {e}")

        # ── Step 10: Set GitHub status ────────────────────
        if pr and owner and head_sha:
            try:
                state = "success" if risk_score < 50 else "failure"
                desc = f"Risk score: {risk_score}/100 — {'Pass' if risk_score < 50 else 'Action required'}"
                await set_commit_status(owner, repo_name, head_sha, state, desc)
            except Exception as e:
                log.warning(f"Could not set final status: {e}")

        # ── Cache results ─────────────────────────────────
        if pr and head_sha:
            await set_cached(full_name, head_sha, {"report": report})

        # ── Save report locally ───────────────────────────
        with open("report.md", "w", encoding="utf-8") as f:
            f.write(report)

        return report

    except asyncio.TimeoutError:
        msg = f"Pipeline timed out after {PIPELINE_TIMEOUT_SECS}s"
        log.error(msg)
        await update_scan(scan_id, status="failed", error_message=msg)
        if pr and owner and head_sha:
            try:
                await set_commit_status(owner, repo_name, head_sha, "error", msg[:140])
            except Exception:
                pass
        return f"❌ {msg}"

    except Exception as e:
        log.error(f"Pipeline error: {repr(e)}")
        log.error(traceback.format_exc())
        await update_scan(scan_id, status="failed", error_message=repr(e))
        if pr and owner and head_sha:
            try:
                await set_commit_status(owner, repo_name, head_sha, "error", f"Error: {str(e)[:120]}")
            except Exception:
                pass
        return f"Pipeline error: {repr(e)}"


async def _fetch_safe(owner: str, repo: str, path: str, ref: str) -> str | None:
    """Fetch file content, returning None on failure."""
    try:
        return await fetch_file_content(owner, repo, path, ref)
    except Exception:
        return None


def _extract_vulns(scan_results: str, llm_detections: list) -> list[dict]:
    """Extract vulnerability records from scan output and LLM detections."""
    vulns = []

    # Parse semgrep-style findings from scan results
    for line in scan_results.splitlines():
        line = line.strip()
        if line.startswith("["):
            # Format: [rule_id] file:line — message
            try:
                bracket_end = line.index("]")
                rule_id = line[1:bracket_end]
                rest = line[bracket_end + 2:]
                if " — " in rest:
                    location, message = rest.split(" — ", 1)
                    file_part = location.rsplit(":", 1)
                    file_name = file_part[0]
                    line_num = int(file_part[1]) if len(file_part) > 1 else 0
                else:
                    file_name = rest
                    line_num = 0
                    message = ""

                severity = "MEDIUM"
                if any(k in rule_id.lower() for k in ("critical", "sqli", "rce", "command")):
                    severity = "CRITICAL"
                elif any(k in rule_id.lower() for k in ("high", "xss", "ssrf")):
                    severity = "HIGH"

                vulns.append({
                    "file": file_name,
                    "line": line_num,
                    "rule_id": rule_id,
                    "severity": severity,
                    "message": message,
                    "category": "static_analysis",
                })
            except (ValueError, IndexError):
                pass

    # LLM detections
    for d in llm_detections:
        vulns.append({
            "file": d.file,
            "line": d.line,
            "rule_id": d.pattern,
            "severity": "MEDIUM",
            "message": d.risk_note,
            "category": d.category,
        })

    return vulns