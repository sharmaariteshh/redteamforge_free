"""
RedTeamForge — SQLite scan cache
Stores previous scan results keyed by (repo, commit_sha) to avoid redundant work.
"""

import aiosqlite
import json
import time
from config import DB_PATH

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS scan_cache (
    repo        TEXT    NOT NULL,
    commit_sha  TEXT    NOT NULL,
    results     TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    PRIMARY KEY (repo, commit_sha)
);
"""


async def _get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    await db.execute(_INIT_SQL)
    await db.commit()
    return db


async def get_cached(repo: str, sha: str) -> dict | None:
    """Return cached scan results or None."""
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT results FROM scan_cache WHERE repo = ? AND commit_sha = ?",
            (repo, sha),
        )
        row = await cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None
    finally:
        await db.close()


async def set_cached(repo: str, sha: str, results: dict) -> None:
    """Store scan results in the cache."""
    db = await _get_db()
    try:
        await db.execute(
            "INSERT OR REPLACE INTO scan_cache (repo, commit_sha, results, created_at) VALUES (?, ?, ?, ?)",
            (repo, sha, json.dumps(results), time.time()),
        )
        await db.commit()
    finally:
        await db.close()
