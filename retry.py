"""
RedTeamForge — Retry & Resilience
Tenacity-based retry decorators for external API calls.
"""

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import httpx
import logging

# Bridge tenacity logging to our logger
_log = logging.getLogger("tenacity.retry")


def with_retry(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 10.0,
    retry_on: tuple = (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError),
):
    """
    Decorator factory for retrying async functions with exponential backoff.

    Usage:
        @with_retry(max_attempts=3)
        async def call_api():
            ...
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=min_wait, max=max_wait),
        retry=retry_if_exception_type(retry_on),
        before_sleep=before_sleep_log(_log, logging.WARNING),
        reraise=True,
    )
