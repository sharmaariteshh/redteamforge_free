"""Quick smoke test for RedTeamForge Phase 3 modules."""

# ── Diff Parser ─────────────────────────────────────────
from diff_parser import parse_diff, changed_paths

diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,5 @@
+import openai
 from flask import Flask
+import os
 app = Flask(__name__)
"""
files = parse_diff(diff)
assert len(files) == 1, f"Expected 1 file, got {len(files)}"
assert files[0].path == "app.py"
print("✅ diff_parser OK")

# ── LLM Detector ────────────────────────────────────────
from llm_detector import scan_content

code = 'import openai\nclient = openai.ChatCompletion.create(model="gpt-4")\nprompt = f"Answer: {user_input}"'
detections = scan_content("app.py", code)
assert len(detections) >= 2, f"Expected >= 2 detections, got {len(detections)}"
categories = {d.category for d in detections}
assert "sdk" in categories
print(f"✅ llm_detector OK — {len(detections)} detections")

# ── Attack Engine ────────────────────────────────────────
from attack_engine import simulate_attacks

attacks = simulate_attacks("sql_injection found in query.py\nxss in template.html")
assert len(attacks) >= 2, f"Expected >= 2 attacks, got {len(attacks)}"
names = {a.vuln_name for a in attacks}
assert "SQL Injection" in names
assert "Cross-Site Scripting (XSS)" in names
print(f"✅ attack_engine OK — {len(attacks)} simulations")

# ── Report Agent ─────────────────────────────────────────
from agents.report_agent import generate_report, compute_risk_score

score = compute_risk_score("sql_injection\nxss", attacks, detections)
assert 0 < score <= 100, f"Bad risk score: {score}"
print(f"✅ risk score OK — {score}/100")

report = generate_report(
    scan_results="[sqli] app.py:5 — SQL injection",
    fuzz_results=["[FUZZ] app.py — Sink detected (sqli)"],
    llm_analysis="SQL Injection found. Use parameterized queries.",
    attacks=attacks,
    llm_detections=detections,
    pr_url="https://github.com/test/repo/pull/1",
)
assert "RedTeamForge Security Report" in report
assert "Attack Simulations" in report
assert "LLM / AI Code Detections" in report
print("✅ report_agent OK")

# ── Database Layer ───────────────────────────────────────
import asyncio
from db import generate_scan_id, create_scan, update_scan, get_scan, list_scans, save_vulnerabilities, save_simulations, get_stats

async def test_db():
    sid = generate_scan_id()
    assert len(sid) == 12, f"Bad scan ID length: {len(sid)}"

    await create_scan(sid, "test/repo", pr_number=1, pr_url="https://github.com/test/repo/pull/1", head_sha="abc123")

    await update_scan(sid, status="running")
    scan = await get_scan(sid)
    assert scan is not None
    assert scan["status"] == "running"

    await update_scan(sid, status="completed", risk_score=65, report="# Test Report")
    scan = await get_scan(sid)
    assert scan["risk_score"] == 65

    await save_vulnerabilities(sid, [
        {"file": "app.py", "line": 5, "rule_id": "sqli", "severity": "CRITICAL", "message": "SQL Injection", "category": "static_analysis"},
    ])
    await save_simulations(sid, attacks)

    scan = await get_scan(sid)
    assert len(scan["vulnerabilities"]) == 1
    assert len(scan["simulations"]) >= 2

    scans = await list_scans()
    assert any(s["id"] == sid for s in scans)

    stats = await get_stats()
    assert stats["total_scans"] >= 1

    print(f"✅ database OK — scan {sid}")

asyncio.run(test_db())

# ── Logger ───────────────────────────────────────────────
from logger import get_logger, set_scan_id, get_scan_id

set_scan_id("test-001")
assert get_scan_id() == "test-001"
log = get_logger("test")
log.info("Smoke test log entry")
print("✅ logger OK")

# ── Retry ────────────────────────────────────────────────
from retry import with_retry
import httpx

@with_retry(max_attempts=2, retry_on=(ValueError,))
async def _will_succeed():
    return 42

assert asyncio.run(_will_succeed()) == 42
print("✅ retry OK")

# ── FastAPI App ──────────────────────────────────────────
import hashlib, hmac as _hmac, json as _json
from fastapi.testclient import TestClient
from main import app
from config import GITHUB_WEBHOOK_SECRET

client = TestClient(app)
resp = client.get("/")
assert resp.status_code == 200
data = resp.json()
assert data["name"] == "RedTeamForge"
assert data["version"] == "3.0.0"
print("✅ FastAPI health check OK")

# Helper: compute valid HMAC-SHA256 signature
def _sign(body: bytes) -> str:
    sig = _hmac.new(GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"

# Webhook with INVALID signature → 401
resp = client.post("/github/webhook", json={"action": "opened"}, headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=invalid"})
assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
print("✅ Webhook rejects invalid signature correctly")

# Webhook with VALID signature, push event → ignored
push_body = _json.dumps({"action": "opened"}).encode()
resp = client.post("/github/webhook", content=push_body, headers={
    "Content-Type": "application/json",
    "X-GitHub-Event": "push",
    "X-Hub-Signature-256": _sign(push_body),
})
assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
assert resp.json()["status"] == "ignored"
print("✅ Webhook push event ignored correctly")

# ── API Endpoints ────────────────────────────────────────
resp = client.get("/api/scans")
assert resp.status_code == 200
assert "scans" in resp.json()
print("✅ API /api/scans OK")

resp = client.get("/api/stats")
assert resp.status_code == 200
assert "total_scans" in resp.json()
print("✅ API /api/stats OK")

# ── Dashboard Routes ─────────────────────────────────────
resp = client.get("/dashboard")
assert resp.status_code == 200
assert "RedTeamForge" in resp.text
print("✅ Dashboard route OK")

print("\n🎉 All Phase 3 smoke tests passed!")
