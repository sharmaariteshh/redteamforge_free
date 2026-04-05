"""
RedTeamForge — LLM / AI-SDK Detector
Scans source code for usage of LLM libraries, API keys, and prompt patterns
that introduce prompt-injection and data-exfiltration risks.
"""

from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class LLMDetection:
    file: str
    line: int
    pattern: str
    category: str  # "sdk", "api_key", "prompt_pattern"
    risk_note: str


# ── Detection rules ───────────────────────────────────────────

_SDK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bimport\s+openai\b"), "OpenAI SDK import"),
    (re.compile(r"\bfrom\s+openai\b"), "OpenAI SDK import"),
    (re.compile(r"\bimport\s+langchain\b"), "LangChain import"),
    (re.compile(r"\bfrom\s+langchain\b"), "LangChain import"),
    (re.compile(r"\bimport\s+anthropic\b"), "Anthropic SDK import"),
    (re.compile(r"\bfrom\s+anthropic\b"), "Anthropic SDK import"),
    (re.compile(r"\bimport\s+cohere\b"), "Cohere SDK import"),
    (re.compile(r"\bfrom\s+transformers\b"), "HuggingFace Transformers import"),
    (re.compile(r"\bChatCompletion\b"), "ChatCompletion API call"),
    (re.compile(r"\bCompletion\.create\b"), "Legacy Completion API call"),
    (re.compile(r"\bllm\s*=\s*"), "LLM variable assignment"),
    (re.compile(r"\bChatOpenAI\b"), "LangChain ChatOpenAI usage"),
    (re.compile(r"\bRetrievalQA\b"), "LangChain RetrievalQA usage"),
    (re.compile(r"\bConversationChain\b"), "LangChain ConversationChain usage"),
]

_KEY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "Possible OpenAI API key"),
    (re.compile(r"OPENAI_API_KEY\s*="), "OpenAI API key assignment"),
    (re.compile(r"ANTHROPIC_API_KEY\s*="), "Anthropic API key assignment"),
    (re.compile(r"api[_-]?key\s*[:=]\s*[\"'][^\"']{10,}", re.IGNORECASE), "Generic API key assignment"),
]

_PROMPT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(system|user|assistant)\s*[:=]\s*[\"']", re.IGNORECASE), "Prompt role assignment"),
    (re.compile(r"\bprompt\s*=\s*f?[\"']", re.IGNORECASE), "Prompt string construction"),
    (re.compile(r"\{user_input\}|\{query\}|\{question\}", re.IGNORECASE), "User input interpolated into prompt"),
    (re.compile(r"\.format\(.*input", re.IGNORECASE), "Prompt formatted with user input"),
]


def scan_content(file_path: str, content: str) -> list[LLMDetection]:
    """Scan a single file's content for LLM-related patterns."""
    detections: list[LLMDetection] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern, label in _SDK_PATTERNS:
            if pattern.search(line):
                detections.append(LLMDetection(
                    file=file_path,
                    line=line_num,
                    pattern=label,
                    category="sdk",
                    risk_note="LLM SDK detected — review for prompt injection, data leakage, and cost abuse vectors.",
                ))

        for pattern, label in _KEY_PATTERNS:
            if pattern.search(line):
                detections.append(LLMDetection(
                    file=file_path,
                    line=line_num,
                    pattern=label,
                    category="api_key",
                    risk_note="Hardcoded API key detected — rotate immediately and move to environment variables.",
                ))

        for pattern, label in _PROMPT_PATTERNS:
            if pattern.search(line):
                detections.append(LLMDetection(
                    file=file_path,
                    line=line_num,
                    pattern=label,
                    category="prompt_pattern",
                    risk_note="User-controlled input flows into LLM prompt — potential prompt injection risk (CWE-20).",
                ))

    return detections


def scan_files(file_contents: dict[str, str]) -> list[LLMDetection]:
    """Scan multiple files. file_contents maps filepath → content string."""
    all_detections: list[LLMDetection] = []
    for path, content in file_contents.items():
        all_detections.extend(scan_content(path, content))
    return all_detections
