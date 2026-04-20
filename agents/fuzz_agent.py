"""
RedTeamForge — Fuzz Agent
Targeted fuzzing: applies common attack payloads against patterns
found in the changed code to detect injection points.
"""

from __future__ import annotations
import re
from logger import get_logger

log = get_logger("fuzz_agent")

PAYLOADS = {
    "sqli": [
        "' OR '1'='1' --",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(document.domain)",
    ],
    "path_traversal": [
        "../../../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//etc/shadow",
    ],
    "command_injection": [
        "; id",
        "| cat /etc/passwd",
        "$(whoami)",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
    ],
}

# Simple pattern detectors in source code
_SINK_PATTERNS = {
    "sqli": re.compile(r"(execute|cursor|query|raw\s*\(|\.format\(.*SELECT)", re.IGNORECASE),
    "xss": re.compile(r"(innerHTML|document\.write|render_template_string|mark_safe|\bHtml\b)", re.IGNORECASE),
    "path_traversal": re.compile(r"(open\(|os\.path|send_file|FileResponse|read_file)", re.IGNORECASE),
    "command_injection": re.compile(r"(subprocess|os\.system|os\.popen|exec\(|eval\(|getoutput)", re.IGNORECASE),
    "ssti": re.compile(r"(render_template_string|Template\(|from_string)", re.IGNORECASE),
}


async def fuzz(repo_path: str, changed_files_content: dict[str, str] | None = None) -> list[str]:
    """
    Analyze changed file contents to identify potential sinks,
    then report which payload categories are applicable.
    Returns a list of fuzz findings.
    """
    findings: list[str] = []

    if not changed_files_content:
        log.info("No files to fuzz")
        return ["Fuzz: No files to analyze."]

    for filepath, content in changed_files_content.items():
        for category, pattern in _SINK_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                payloads = PAYLOADS[category]
                findings.append(
                    f"[FUZZ] {filepath} — Sink detected ({category}): {matches[0]}. "
                    f"Applicable payloads: {payloads[:2]}"
                )

    if not findings:
        findings.append("Fuzz: No injection sinks detected in changed files.")
        log.info("No injection sinks found")
    else:
        log.info(f"Fuzz found {len(findings)} sinks")

    return findings
