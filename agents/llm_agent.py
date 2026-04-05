"""
RedTeamForge — LLM Analysis Agent
Sends scan + fuzz results to Ollama with the master prompt for expert analysis.
"""

import httpx
from config import OLLAMA_URL, MODEL, LLM_MAX_INPUT_CHARS

MASTER_PROMPT = """You are RedTeamForge — an elite AI red-team security analysis system.

STRICT RULES:
- Do NOT hallucinate or invent vulnerabilities.
- ONLY use the SCAN RESULTS and FUZZ RESULTS provided below.
- Ignore runtime errors (UnicodeEncodeError, ImportError, etc.).
- If no real vulnerabilities are found, respond: "No real vulnerabilities detected."

INPUT:
──────────────────────────────────────
SCAN RESULTS:
{scan}

FUZZ RESULTS:
{fuzz}

LLM DETECTIONS:
{llm_detections}
──────────────────────────────────────

TASKS:
1. Identify ONLY real, confirmed vulnerabilities from the scan results.
2. For each vulnerability provide:
   - Name
   - Severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
   - CWE ID
   - Impact description
   - Recommended fix

3. If vulnerabilities exist, provide attack simulation:
   - Step-by-step attack scenario
   - Example payloads

4. If LLM/AI code is detected:
   - Highlight prompt injection risks
   - Note data leakage vectors
   - Recommend mitigations

Be technical, precise, and concise. Do not include disclaimers.
"""


async def analyze(
    scan_results: str,
    fuzz_results: list[str],
    llm_detections: str = "",
) -> str:
    """Send combined results to Ollama for expert analysis."""

    # Truncate inputs to stay within context limits
    scan_trimmed = scan_results[:LLM_MAX_INPUT_CHARS]
    fuzz_trimmed = "\n".join(fuzz_results)[:LLM_MAX_INPUT_CHARS // 2]
    llm_trimmed = llm_detections[:LLM_MAX_INPUT_CHARS // 4]

    prompt = MASTER_PROMPT.format(
        scan=scan_trimmed,
        fuzz=fuzz_trimmed,
        llm_detections=llm_trimmed or "None detected.",
    )

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            res = await client.post(OLLAMA_URL, json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
            })
            res.raise_for_status()
            return res.json().get("response", "")
        except httpx.HTTPStatusError as e:
            return f"LLM analysis error (HTTP {e.response.status_code}): {e.response.text[:500]}"
        except httpx.ConnectError:
            return (
                "⚠️ Could not connect to Ollama. "
                "Make sure Ollama is running (`ollama serve`) and the model is pulled."
            )
        except Exception as e:
            return f"LLM analysis error: {repr(e)}"
