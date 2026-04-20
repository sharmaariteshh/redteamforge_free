"""
RedTeamForge — LLM Analysis Agent
Sends scan + fuzz results to Ollama with the master prompt for expert analysis.
Now with retry logic and structured logging.
"""

import httpx
from config import OLLAMA_URL, MODEL, LLM_MAX_INPUT_CHARS
from logger import get_logger
from retry import with_retry

log = get_logger("llm_agent")

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


async def _call_ollama(prompt: str) -> str:
    """Call Ollama API with retry."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        res = await client.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        })
        res.raise_for_status()
        return res.json().get("response", "")


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

    try:
        # Apply retry with up to 3 attempts and exponential backoff
        retry_call = with_retry(
            max_attempts=3,
            min_wait=2.0,
            max_wait=15.0,
            retry_on=(httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError),
        )
        result = await retry_call(_call_ollama)(prompt)
        log.info("Ollama analysis complete")
        return result
    except httpx.ConnectError:
        log.warning("Could not connect to Ollama — skipping AI analysis")
        return (
            "⚠️ Could not connect to Ollama. "
            "Make sure Ollama is running (`ollama serve`) and the model is pulled."
        )
    except Exception as e:
        log.error(f"LLM analysis error: {repr(e)}")
        return f"LLM analysis error: {repr(e)}"
