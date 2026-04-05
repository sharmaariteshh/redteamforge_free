"""
RedTeamForge — Orchestrator
Coordinates the full PR analysis pipeline:
  Ingest → Diff Parse → Parallel (Scan + Fuzz + LLM Detect) → Attack Engine → LLM Analysis → Report → Comment
"""

import asyncio
import traceback

from agents.ingest_agent import ingest
from agents.scan_agent import static_scan
from agents.fuzz_agent import fuzz
from agents.llm_agent import analyze
from agents.report_agent import generate_report

from diff_parser import parse_pr_files_response, changed_paths
from llm_detector import scan_files, LLMDetection
from attack_engine import simulate_attacks
from github_client import fetch_pr_files, fetch_file_content, post_comment
from db import get_cached, set_cached
from config import PIPELINE_TIMEOUT_SECS


async def run_pipeline(data: dict) -> str:
    """
    Full analysis pipeline. Returns the markdown report string.
    Also posts the report as a GitHub PR comment if webhook data is present.
    """
    try:
        print("🚀 Pipeline started")

        pr = data.get("pull_request")
        owner = ""
        repo_name = ""
        pr_number = 0
        pr_url = ""
        head_sha = ""

        if pr:
            full_name = pr["base"]["repo"]["full_name"]
            owner, repo_name = full_name.split("/")
            pr_number = pr["number"]
            pr_url = pr["html_url"]
            head_sha = pr["head"]["sha"]

            # ── Check cache ──────────────────────────────
            cached = await get_cached(full_name, head_sha)
            if cached:
                print("⚡ Cache hit — returning cached report")
                return cached.get("report", "")

        # ── Step 1: Ingest (clone repo) ──────────────────
        repo_path = await ingest(data)
        print("✅ Ingest done")

        # ── Step 2: Get changed files ────────────────────
        changed = []
        file_paths = []
        if pr and owner:
            pr_files_json = await fetch_pr_files(owner, repo_name, pr_number)
            changed = parse_pr_files_response(pr_files_json)
            file_paths = changed_paths(changed, extensions={".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".yaml", ".yml", ".json"})
            print(f"📂 Changed files: {len(file_paths)}")
        else:
            print("📂 Full repo scan (no PR context)")

        # ── Step 3: Fetch file contents for LLM detection ─
        file_contents: dict[str, str] = {}
        if pr and owner and file_paths:
            head_ref = pr["head"]["ref"]
            fetch_tasks = [
                _fetch_safe(owner, repo_name, p, head_ref)
                for p in file_paths[:30]  # cap at 30 files
            ]
            results = await asyncio.gather(*fetch_tasks)
            for path, content in zip(file_paths[:30], results):
                if content is not None:
                    file_contents[path] = content
        else:
            # Manual mode: read files from disk
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

        # ── Step 4: Parallel — Scan + Fuzz + LLM Detect ──
        scan_task = static_scan(repo_path, file_paths or None)
        fuzz_task = fuzz(repo_path, file_contents)
        llm_detect_task = asyncio.to_thread(scan_files, file_contents)

        scan_results, fuzz_results, llm_detections = await asyncio.wait_for(
            asyncio.gather(scan_task, fuzz_task, llm_detect_task),
            timeout=PIPELINE_TIMEOUT_SECS,
        )
        print("✅ Scan + Fuzz + LLM detection done")

        # ── Step 5: Attack simulation ────────────────────
        attacks = simulate_attacks(scan_results, fuzz_results)
        print(f"⚔️  Attack simulations: {len(attacks)}")

        # ── Step 6: LLM expert analysis ─────────────────
        llm_det_text = ""
        if llm_detections:
            llm_det_text = "\n".join(
                f"- {d.file}:{d.line} — {d.pattern} ({d.category})"
                for d in llm_detections
            )

        llm_analysis = await analyze(scan_results, fuzz_results, llm_det_text)
        print("✅ LLM analysis done")

        # ── Step 7: Generate report ──────────────────────
        report = generate_report(
            scan_results=scan_results,
            fuzz_results=fuzz_results,
            llm_analysis=llm_analysis,
            attacks=attacks,
            llm_detections=llm_detections,
            pr_url=pr_url,
        )
        print("🔥 Report generated")

        # ── Step 8: Post comment to GitHub ───────────────
        if pr and owner and pr_number:
            try:
                await post_comment(owner, repo_name, pr_number, report)
                print(f"💬 Comment posted to PR #{pr_number}")
            except Exception as e:
                print(f"⚠️  Failed to post comment: {repr(e)}")

        # ── Step 9: Cache results ────────────────────────
        if pr and head_sha:
            full_name = f"{owner}/{repo_name}"
            await set_cached(full_name, head_sha, {"report": report})

        # ── Save report locally ──────────────────────────
        with open("report.md", "w", encoding="utf-8") as f:
            f.write(report)

        return report

    except asyncio.TimeoutError:
        msg = f"❌ Pipeline timed out after {PIPELINE_TIMEOUT_SECS}s"
        print(msg)
        return msg
    except Exception as e:
        print(f"❌ ERROR: {repr(e)}")
        traceback.print_exc()
        return f"Pipeline error: {repr(e)}"


async def _fetch_safe(owner: str, repo: str, path: str, ref: str) -> str | None:
    """Fetch file content, returning None on failure."""
    try:
        return await fetch_file_content(owner, repo, path, ref)
    except Exception:
        return None