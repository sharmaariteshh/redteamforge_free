import os
import base64
import httpx
from dotenv import load_dotenv

load_dotenv()
token = os.environ["GITHUB_TOKEN"]
owner = "sharmaariteshh"
repo = "redteamforge_free"
headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}

client = httpx.Client(base_url="https://api.github.com", headers=headers)

# 1. Get main branch SHA
r = client.get(f"/repos/{owner}/{repo}/git/ref/heads/main")
sha = r.json()["object"]["sha"]
print(f"Main SHA: {sha}")

# 2. Create test branch
r = client.post(f"/repos/{owner}/{repo}/git/refs", json={
    "ref": "refs/heads/test-vuln-scan",
    "sha": sha
})
print(f"Create branch: {r.status_code}")

# 3. Create a deliberately vulnerable file
vuln_code = '''from flask import Flask, request
import sqlite3
import os
import subprocess

app = Flask(__name__)

# VULN: Hardcoded secret
DATABASE_PASSWORD = "admin123"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # VULN: SQL Injection - unsanitized input in query
    result = conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(result.fetchall())

@app.route("/search")
def search():
    query = request.args.get("q")
    # VULN: XSS - unescaped user input in response
    return f"<h1>Results for: {query}</h1>"

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    # VULN: Command Injection
    output = subprocess.getoutput(cmd)
    return output

@app.route("/file")
def read_file():
    path = request.args.get("path")
    # VULN: Path Traversal
    with open(path, "r") as f:
        return f.read()

# VULN: LLM usage with prompt injection risk
import openai
client_ai = openai.OpenAI(api_key="sk-1234567890abcdef1234567890abcdef")

@app.route("/ask")
def ask_ai():
    user_input = request.args.get("question")
    # VULN: Prompt injection - user input directly in prompt
    response = client_ai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Answer this: {user_input}"}]
    )
    return response.choices[0].message.content
'''

r = client.put(f"/repos/{owner}/{repo}/contents/vulnerable_app.py", json={
    "message": "Add app with multiple vulnerabilities for security testing",
    "content": base64.b64encode(vuln_code.encode()).decode(),
    "branch": "test-vuln-scan"
})
print(f"Create vuln file: {r.status_code}")

# 4. Create Pull Request
r = client.post(f"/repos/{owner}/{repo}/pulls", json={
    "title": "feat: Add new application endpoint",
    "body": "Added new user management and AI-powered search endpoints.",
    "head": "test-vuln-scan",
    "base": "main"
})
print(f"Create PR: {r.status_code}")
if r.status_code == 201:
    pr = r.json()
    print(f"\n PR created: {pr['html_url']}")
    print(f"PR #{pr['number']} - waiting for RedTeamForge webhook...")
else:
    print(r.text[:500])
