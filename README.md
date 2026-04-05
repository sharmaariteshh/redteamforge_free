# 🛡️ RedTeamForge

**Autonomous AI Red-Team Security Engine for CI/CD Pipelines**

RedTeamForge analyzes pull requests, detects vulnerabilities, simulates attacks, and posts detailed security reports as PR comments — all automatically.

---

## ⚡ Features

- **GitHub Webhook Integration** — Triggers automatically on PR open/sync
- **PR Diff Analysis** — Scans only changed files for speed
- **Static Analysis** — Semgrep with auto-config
- **LLM Code Detection** — Detects OpenAI, LangChain, prompt injection risks
- **Attack Simulation** — Generates attack steps and payloads for each finding
- **Fuzz Testing** — Identifies injection sinks in changed code
- **Risk Scoring** — 0-100 score with severity weighting
- **AI Expert Analysis** — Ollama-powered red-team analysis
- **Markdown Reports** — Professional security reports posted to GitHub
- **Scan Caching** — SQLite cache avoids redundant scans
- **< 90 Second Performance** — Async parallel execution

---

## 🏗️ Architecture

```
GitHub PR → Webhook → FastAPI
    → Orchestrator
        → Ingest (shallow clone)
        → Diff Parser (changed files only)
        → Parallel:
            ├── Semgrep Scan
            ├── Fuzz Testing
            └── LLM Detection
        → Attack Engine
        → Ollama LLM Analysis
        → Report Generator
    → GitHub PR Comment
```

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/sharmaariteshh/redteamforge_free.git
cd redteamforge_free
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your GitHub token and webhook secret
```

### 3. Start Ollama

```bash
ollama pull llama3
ollama serve
```

### 4. Run the Server

```bash
uvicorn main:app --reload --port 8000
```

### 5. Expose with ngrok (for webhooks)

```bash
ngrok http 8000
# Copy the HTTPS URL
```

### 6. Configure GitHub Webhook

1. Go to your repo → Settings → Webhooks → Add webhook
2. **Payload URL:** `https://your-ngrok-url/github/webhook`
3. **Content type:** `application/json`
4. **Secret:** Same as `GITHUB_WEBHOOK_SECRET` in `.env`
5. **Events:** Select "Pull requests"

---

## 📡 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/github/webhook` | GitHub webhook receiver |
| `POST` | `/scan` | Manual repo scan |
| `POST` | `/test/pr` | Test endpoint (sync) |
| `GET` | `/docs` | Swagger UI |

### Manual Scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo": "https://github.com/user/repo.git"}'
```

### Test a PR

```bash
curl -X POST http://localhost:8000/test/pr \
  -H "Content-Type: application/json" \
  -d '{"owner": "sharmaariteshh", "repo": "redteamforge_free", "pr_number": 1}'
```

---

## 📊 Report Format

```
🛡️ RedTeamForge Security Report

📋 Summary — risk score, finding counts
🔍 Static Analysis Findings — Semgrep results
🧪 Fuzz Testing Results — injection sink detection
⚔️ Attack Simulations — steps + payloads per vuln
🤖 LLM/AI Detections — prompt injection risks
🧠 AI Red-Team Analysis — Ollama expert analysis
✅ Recommendations — merge / block guidance
```

---

## 🛠️ Tech Stack (100% Free)

| Component | Tool |
|-----------|------|
| Backend | FastAPI |
| LLM | Ollama (llama3) |
| Scanner | Semgrep |
| Database | SQLite |
| HTTP | httpx (async) |
| Hosting | Local + ngrok / Fly.io |

---

## 📁 Project Structure

```
redteamforge_free/
├── main.py              # FastAPI app + endpoints
├── config.py            # Environment configuration
├── github_client.py     # GitHub API interactions
├── diff_parser.py       # PR diff parsing
├── llm_detector.py      # LLM/AI code detection
├── attack_engine.py     # Attack simulation engine
├── db.py                # SQLite scan cache
├── .env.example         # Environment template
├── requirements.txt     # Python dependencies
├── agents/
│   ├── orchestrator.py  # Pipeline coordinator
│   ├── ingest_agent.py  # Repo cloning
│   ├── scan_agent.py    # Semgrep scanning
│   ├── fuzz_agent.py    # Fuzz testing
│   ├── llm_agent.py     # Ollama LLM analysis
│   └── report_agent.py  # Report generation
└── data/
    └── repo/            # Cloned PR repo
```

---

## 👤 Author

**Ritesh Sharma** — [@sharmaariteshh](https://github.com/sharmaariteshh)

---

## 📝 License

MIT
