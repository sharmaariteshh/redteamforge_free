"""
RedTeamForge — Structured Logging
Loguru-based logging with scan_id context, JSON file sink, and console output.
"""

import sys
import os
from contextvars import ContextVar
from loguru import logger

# ── Context var for scan-scoped tracing ───────────────────────
_scan_id_var: ContextVar[str] = ContextVar("scan_id", default="system")

LOG_DIR = os.path.join(os.path.dirname(__file__), "data", "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def _scan_id_patcher(record):
    """Inject scan_id into every log record."""
    record["extra"]["scan_id"] = _scan_id_var.get("system")


def setup_logging(level: str = "INFO") -> None:
    """Configure Loguru with console + JSON file sinks."""
    logger.remove()  # Remove default handler

    # Console sink — human-readable
    logger.configure(patcher=_scan_id_patcher)
    logger.add(
        sys.stderr,
        format=(
            "<green>{time:HH:mm:ss}</green> | "
            "<level>{level:<8}</level> | "
            "<cyan>{extra[scan_id]}</cyan> | "
            "{message}"
        ),
        level=level,
        colorize=True,
    )

    # JSON file sink — structured, rotated
    logger.add(
        os.path.join(LOG_DIR, "redteamforge_{time:YYYY-MM-DD}.log"),
        format="{time:YYYY-MM-DDTHH:mm:ss} | {level} | {extra[scan_id]} | {message}",
        level="DEBUG",
        rotation="10 MB",
        retention="7 days",
        compression="zip",
        enqueue=True,
    )


def set_scan_id(scan_id: str) -> None:
    """Set the scan_id context for the current async task."""
    _scan_id_var.set(scan_id)


def get_scan_id() -> str:
    """Get the current scan_id context."""
    return _scan_id_var.get("system")


def get_logger(name: str = "redteamforge"):
    """Return the configured logger (same instance, name is for readability)."""
    return logger.bind(module=name)


# Auto-setup on import
setup_logging(os.getenv("LOG_LEVEL", "INFO"))
