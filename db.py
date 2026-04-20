"""
RedTeamForge — Database Layer
SQLite persistence for scans, vulnerabilities, simulations, and scan cache.
"""

import aiosqlite
import json
import time
import uuid
from config import DB_PATH


# ── Schema ────────────────────────────────────────────────────

_INIT_SQL = """
CREATE TABLE IF NOT EXISTS scan_cache (
    repo        TEXT    NOT NULL,
    commit_sha  TEXT    NOT NULL,
    results     TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    PRIMARY KEY (repo, commit_sha)
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT    PRIMARY KEY,
    repo            TEXT    NOT NULL,
    pr_number       INTEGER,
    pr_url          TEXT    DEFAULT '',
    head_sha        TEXT    DEFAULT '',
    status          TEXT    NOT NULL DEFAULT 'pending',
    risk_score      INTEGER DEFAULT 0,
    report          TEXT    DEFAULT '',
    error_message   TEXT    DEFAULT '',
    created_at      REAL    NOT NULL,
    completed_at    REAL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL,
    file        TEXT    NOT NULL,
    line        INTEGER DEFAULT 0,
    rule_id     TEXT    DEFAULT '',
    severity    TEXT    DEFAULT 'MEDIUM',
    message     TEXT    DEFAULT '',
    category    TEXT    DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS simulations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL,
    vuln_name       TEXT    NOT NULL,
    severity        TEXT    DEFAULT 'MEDIUM',
    cwe             TEXT    DEFAULT '',
    impact          TEXT    DEFAULT '',
    steps_json      TEXT    DEFAULT '[]',
    payloads_json   TEXT    DEFAULT '[]',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


# ── Connection helper ─────────────────────────────────────────

async def _get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = _dict_factory
    await db.executescript(_INIT_SQL)
    await db.commit()
    return db


def _dict_factory(cursor, row):
    """Convert rows directly to plain dicts."""
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


# ── Scan Cache (Phase 2 compat) ──────────────────────────────

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
            return json.loads(row["results"])
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


# ── Scans CRUD ────────────────────────────────────────────────

def generate_scan_id() -> str:
    """Generate a unique scan ID."""
    return str(uuid.uuid4())[:12]


async def create_scan(
    scan_id: str,
    repo: str,
    pr_number: int | None = None,
    pr_url: str = "",
    head_sha: str = "",
) -> str:
    """Create a new scan record with status 'pending'."""
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO scans (id, repo, pr_number, pr_url, head_sha, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
            (scan_id, repo, pr_number, pr_url, head_sha, time.time()),
        )
        await db.commit()
        return scan_id
    finally:
        await db.close()


async def update_scan(
    scan_id: str,
    status: str | None = None,
    risk_score: int | None = None,
    report: str | None = None,
    error_message: str | None = None,
) -> None:
    """Update scan fields. Only non-None values are updated."""
    db = await _get_db()
    try:
        fields = []
        values = []
        if status is not None:
            fields.append("status = ?")
            values.append(status)
            if status in ("completed", "failed"):
                fields.append("completed_at = ?")
                values.append(time.time())
        if risk_score is not None:
            fields.append("risk_score = ?")
            values.append(risk_score)
        if report is not None:
            fields.append("report = ?")
            values.append(report)
        if error_message is not None:
            fields.append("error_message = ?")
            values.append(error_message)

        if fields:
            values.append(scan_id)
            await db.execute(
                f"UPDATE scans SET {', '.join(fields)} WHERE id = ?",
                tuple(values),
            )
            await db.commit()
    finally:
        await db.close()


async def get_scan(scan_id: str) -> dict | None:
    """Get a single scan by ID, including its vulns and simulations."""
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        scan = dict(row)

        # Vulnerabilities
        cursor = await db.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity, file",
            (scan_id,),
        )
        scan["vulnerabilities"] = [dict(r) for r in await cursor.fetchall()]

        # Simulations
        cursor = await db.execute(
            "SELECT * FROM simulations WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        )
        sims = []
        for r in await cursor.fetchall():
            sim = dict(r)
            sim["steps"] = json.loads(sim.pop("steps_json", "[]"))
            sim["payloads"] = json.loads(sim.pop("payloads_json", "[]"))
            sims.append(sim)
        scan["simulations"] = sims

        return scan
    finally:
        await db.close()


async def list_scans(
    repo: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List scans with optional filters. Returns metadata only (no report body)."""
    db = await _get_db()
    try:
        where = []
        params: list = []
        if repo:
            where.append("repo LIKE ?")
            params.append(f"%{repo}%")
        if status:
            where.append("status = ?")
            params.append(status)

        where_clause = f"WHERE {' AND '.join(where)}" if where else ""
        params.extend([limit, offset])

        cursor = await db.execute(
            f"""SELECT id, repo, pr_number, pr_url, head_sha, status, risk_score,
                       error_message, created_at, completed_at
                FROM scans {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?""",
            tuple(params),
        )
        return [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()


async def save_vulnerabilities(scan_id: str, vulns: list[dict]) -> None:
    """Bulk-insert vulnerability records for a scan."""
    if not vulns:
        return
    db = await _get_db()
    try:
        await db.executemany(
            """INSERT INTO vulnerabilities (scan_id, file, line, rule_id, severity, message, category)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id,
                    v.get("file", ""),
                    v.get("line", 0),
                    v.get("rule_id", ""),
                    v.get("severity", "MEDIUM"),
                    v.get("message", ""),
                    v.get("category", ""),
                )
                for v in vulns
            ],
        )
        await db.commit()
    finally:
        await db.close()


async def save_simulations(scan_id: str, simulations: list) -> None:
    """Bulk-insert attack simulation records for a scan."""
    if not simulations:
        return
    db = await _get_db()
    try:
        await db.executemany(
            """INSERT INTO simulations (scan_id, vuln_name, severity, cwe, impact, steps_json, payloads_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id,
                    s.vuln_name if hasattr(s, "vuln_name") else s.get("vuln_name", ""),
                    s.severity if hasattr(s, "severity") else s.get("severity", ""),
                    s.cwe if hasattr(s, "cwe") else s.get("cwe", ""),
                    s.impact if hasattr(s, "impact") else s.get("impact", ""),
                    json.dumps(s.steps if hasattr(s, "steps") else s.get("steps", [])),
                    json.dumps(s.payloads if hasattr(s, "payloads") else s.get("payloads", [])),
                )
                for s in simulations
            ],
        )
        await db.commit()
    finally:
        await db.close()


async def get_stats() -> dict:
    """Aggregate statistics for the dashboard."""
    db = await aiosqlite.connect(DB_PATH)
    await db.executescript(_INIT_SQL)
    try:
        stats = {}
        cursor = await db.execute("SELECT COUNT(*) FROM scans")
        row = await cursor.fetchone()
        stats["total_scans"] = row[0] if row else 0

        cursor = await db.execute("SELECT AVG(risk_score) FROM scans WHERE status = 'completed'")
        row = await cursor.fetchone()
        avg = row[0] if row else None
        stats["avg_risk_score"] = round(avg, 1) if avg else 0

        cursor = await db.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed' AND risk_score >= 50")
        row = await cursor.fetchone()
        stats["critical_scans"] = row[0] if row else 0

        cursor = await db.execute("SELECT COUNT(*) FROM vulnerabilities")
        row = await cursor.fetchone()
        stats["total_vulnerabilities"] = row[0] if row else 0

        cursor = await db.execute(
            """SELECT severity, COUNT(*) as cnt FROM vulnerabilities
               GROUP BY severity ORDER BY cnt DESC LIMIT 5"""
        )
        rows = await cursor.fetchall()
        stats["vuln_by_severity"] = {str(r[0]): int(r[1]) for r in rows}

        cursor = await db.execute(
            """SELECT category, COUNT(*) as cnt FROM vulnerabilities
               WHERE category != '' GROUP BY category ORDER BY cnt DESC LIMIT 5"""
        )
        rows = await cursor.fetchall()
        stats["vuln_by_category"] = {str(r[0]): int(r[1]) for r in rows}

        cursor = await db.execute("SELECT COUNT(*) FROM simulations")
        row = await cursor.fetchone()
        stats["total_simulations"] = row[0] if row else 0

        return stats
    finally:
        await db.close()

