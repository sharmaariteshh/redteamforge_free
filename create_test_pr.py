import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()
token = os.environ.get('GITHUB_TOKEN')
if not token:
    print("No GITHUB_TOKEN found.")
    exit(1)

headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github.v3+json'
}

client = httpx.Client(base_url="https://api.github.com", headers=headers)
owner = "sharmaariteshh"
repo = "redteamforge_free"

# 1. Get main branch SHA
res = client.get(f"/repos/{owner}/{repo}/git/ref/heads/main")
if res.status_code != 200:
    # Try master
    res = client.get(f"/repos/{owner}/{repo}/git/ref/heads/master")
    if res.status_code != 200:
        print("Could not find main or master branch")
        print(res.text)
        exit(1)

sha = res.json()["object"]["sha"]
print(f"Base SHA: {sha}")

# 2. Create a new branch
branch_name = "test-vulnerability-scan"
res = client.post(
    f"/repos/{owner}/{repo}/git/refs",
    json={"ref": f"refs/heads/{branch_name}", "sha": sha}
)
# If branch exists it might return 422, which is fine, we can still push to it ideally, but let's just use it
print(f"Create branch: {res.status_code}")

# 3. Create a vulnerable file via API
vulnerable_code = """
from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

# Hardcoded secret
AWS_ACCESS_KEY_ID = "AKIA1234567890EXAMPLE"

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    # SQL Injection
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchall())

@app.route("/exec")
def exec_cmd():
    cmd = request.args.get("cmd")
    # Command Injection
    os.system(cmd)
    return "Executed"
    
import openai
api_key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
client = openai.OpenAI(api_key=api_key)
"""

res = client.put(
    f"/repos/{owner}/{repo}/contents/vulnerable_app.py",
    json={
        "message": "Add vulnerable app for testing",
        "content": vulnerable_code.encode("utf-8").hex(), # Need base64, using base64 module
        "branch": branch_name
    }
)
import base64
res = client.put(
    f"/repos/{owner}/{repo}/contents/vulnerable_app.py",
    json={
        "message": "Add vulnerable app for testing",
        "content": base64.b64encode(vulnerable_code.encode("utf-8")).decode("utf-8"),
        "branch": branch_name
    }
)
print(f"Create file: {res.status_code}")

# 4. Create PR
res = client.post(
    f"/repos/{owner}/{repo}/pulls",
    json={
        "title": "🔴 Test PR: Vulnerability Scan",
        "body": "This PR contains deliberate vulnerabilities to test the RedTeamForge engine.",
        "head": branch_name,
        "base": "main" # or master
    }
)

if res.status_code == 422:
    # Try master
    res = client.post(
        f"/repos/{owner}/{repo}/pulls",
        json={
            "title": "🔴 Test PR: Vulnerability Scan",
            "body": "This PR contains deliberate vulnerabilities to test the RedTeamForge engine.",
            "head": branch_name,
            "base": "master"
        }
    )

print(f"Create PR: {res.status_code}")
if "html_url" in res.json():
    print(f"PR created successfully: {res.json()['html_url']}")
else:
    print(res.text)
