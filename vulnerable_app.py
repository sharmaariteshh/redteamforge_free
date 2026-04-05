from flask import Flask, request
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
