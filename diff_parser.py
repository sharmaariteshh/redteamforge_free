"""
RedTeamForge — Diff Parser
Parses unified diffs from GitHub to extract changed files and line ranges.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class ChangedHunk:
    """A single hunk inside a file diff."""
    start_line: int
    line_count: int
    added_lines: list[int] = field(default_factory=list)


@dataclass
class ChangedFile:
    """Represents a single changed file in a PR diff."""
    path: str
    status: str  # added, modified, removed, renamed
    hunks: list[ChangedHunk] = field(default_factory=list)
    patch: str = ""


_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_diff(raw_diff: str) -> list[ChangedFile]:
    """Parse a unified diff string into a list of ChangedFile objects."""
    files: list[ChangedFile] = []
    current_file: ChangedFile | None = None
    current_hunk: ChangedHunk | None = None
    current_line = 0

    for line in raw_diff.splitlines():
        header_match = _DIFF_HEADER.match(line)
        if header_match:
            current_file = ChangedFile(
                path=header_match.group(2),
                status="modified",
            )
            files.append(current_file)
            current_hunk = None
            continue

        if current_file is None:
            continue

        # detect new / deleted
        if line.startswith("new file"):
            current_file.status = "added"
            continue
        if line.startswith("deleted file"):
            current_file.status = "removed"
            continue
        if line.startswith("rename from"):
            current_file.status = "renamed"
            continue

        hunk_match = _HUNK_HEADER.match(line)
        if hunk_match:
            start = int(hunk_match.group(1))
            count = int(hunk_match.group(2) or "1")
            current_hunk = ChangedHunk(start_line=start, line_count=count)
            current_file.hunks.append(current_hunk)
            current_line = start
            continue

        if current_hunk is not None:
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.added_lines.append(current_line)
                current_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                pass  # deleted line — don't increment
            else:
                current_line += 1

    return files


def parse_pr_files_response(files_json: list[dict]) -> list[ChangedFile]:
    """Convert the /pulls/{n}/files JSON response into ChangedFile objects."""
    results: list[ChangedFile] = []
    for f in files_json:
        cf = ChangedFile(
            path=f["filename"],
            status=f.get("status", "modified"),
            patch=f.get("patch", ""),
        )
        # Parse hunks from the embedded patch
        if cf.patch:
            for hunk_match in _HUNK_HEADER.finditer(cf.patch):
                start = int(hunk_match.group(1))
                count = int(hunk_match.group(2) or "1")
                cf.hunks.append(ChangedHunk(start_line=start, line_count=count))
        results.append(cf)
    return results


def changed_paths(files: list[ChangedFile], extensions: set[str] | None = None) -> list[str]:
    """Return just the file paths, optionally filtered by extension."""
    paths = [f.path for f in files if f.status != "removed"]
    if extensions:
        paths = [p for p in paths if any(p.endswith(ext) for ext in extensions)]
    return paths
