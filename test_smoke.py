"""Quick smoke test for RedTeamForge Phase 2 modules."""

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

# ── FastAPI App ──────────────────────────────────────────
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)
resp = client.get("/")
assert resp.status_code == 200
data = resp.json()
assert data["name"] == "RedTeamForge"
assert data["version"] == "2.0.0"
print("✅ FastAPI health check OK")

# Webhook with invalid signature
resp = client.post("/github/webhook", json={"action": "opened"}, headers={"X-GitHub-Event": "push"})
assert resp.status_code == 200  # push events are ignored, not rejected
print("✅ Webhook push event ignored correctly")

print("\n🎉 All smoke tests passed!")
