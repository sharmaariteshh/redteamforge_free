"""
RedTeamForge — Configuration
Loads settings from environment variables with sensible defaults.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── Ollama / LLM ──────────────────────────────────────────────
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "llama3")

# ── GitHub ────────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_API_BASE = "https://api.github.com"

# ── Performance ───────────────────────────────────────────────
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "4"))
LLM_MAX_INPUT_CHARS = int(os.getenv("LLM_MAX_INPUT_CHARS", "12000"))
PIPELINE_TIMEOUT_SECS = int(os.getenv("PIPELINE_TIMEOUT_SECS", "90"))

# ── Paths ─────────────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
REPO_DIR = os.path.join(DATA_DIR, "repo")
DB_PATH = os.path.join(DATA_DIR, "redteamforge.db")
