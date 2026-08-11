"""
Logging configuration.

Data Setup:  Reads config/logging_config.json; falls back to safe defaults.
Data Input:  A one-time setup call at process start.
Data Output: Configured handlers on the three logger streams.

Three streams, because they answer different questions:

  * **application** (`network_defender`) — what the software did. Debugging.
  * **security** (`network_defender.security`) — what the network did. The
    detection record an incident review reads.
  * **audit** (`network_defender.audit`) — who asked the system for what:
    outbound API calls and inbound HTTP requests.

Console is always configured: containers expect stdout and the orchestrator
handles collection and rotation. Files are opt-in for bare-metal deployments —
on by default would mean a stray `logs/` directory on every test run.
"""

import json
import logging
import logging.handlers
import sys
from typing import Any

from ..shared.paths import CONFIG_DIR, resolve_project_path
from .formatter import JsonFormatter
from .redaction import RedactionFilter

LOGGER_APP = "network_defender"
LOGGER_SECURITY = "network_defender.security"
LOGGER_AUDIT = "network_defender.audit"

CONFIG_FILE = "logging_config.json"
DEFAULT_LEVEL = "INFO"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUPS = 5

_configured = False


def load_logging_config() -> dict[str, Any]:
    """
    Read logging settings, falling back to defaults when absent.

    Returns:
        The parsed configuration dict.
    """
    path = CONFIG_DIR / CONFIG_FILE
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as handle:
            return dict(json.load(handle))
    except (OSError, ValueError):
        # Logging must come up even with a broken config file; otherwise a
        # typo silences the very system that would report it.
        return {}


def _build_console_handler(service: str) -> logging.Handler:
    """Build the stdout handler every deployment gets."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service=service))
    handler.addFilter(RedactionFilter())
    return handler


def _build_file_handler(filename: str, service: str, config: dict[str, Any]) -> logging.Handler:
    """Build a size-rotating file handler, creating its directory if needed."""
    path = resolve_project_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=int(config.get("max_bytes", DEFAULT_MAX_BYTES)),
        backupCount=int(config.get("backup_count", DEFAULT_BACKUPS)),
        encoding="utf-8",
    )
    handler.setFormatter(JsonFormatter(service=service))
    handler.addFilter(RedactionFilter())
    return handler


def _configure_stream(
    name: str, level: str, handlers: list[logging.Handler], propagate: bool
) -> None:
    """Attach handlers to one logger, replacing anything already there."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = list(handlers)
    logger.propagate = propagate


def setup_logging(
    service: str = "network-defender",
    level: str | None = None,
    force: bool = False,
) -> None:
    """
    Configure structured logging for the process.

    Idempotent: repeated calls are ignored unless `force` is set, so importing
    a module twice cannot double every log line.

    Args:
        service: Emitted as the `service` field, distinguishing sensor from API.
        level:   Overrides the configured level.
        force:   Reconfigure even if setup already ran (used by tests).
    """
    global _configured
    if _configured and not force:
        return

    config = load_logging_config()
    resolved_level = level or str(config.get("level", DEFAULT_LEVEL)).upper()
    files = config.get("files", {})

    app_handlers = [_build_console_handler(service)]
    security_handlers = [_build_console_handler(service)]
    audit_handlers = [_build_console_handler(service)]

    # Security and audit streams do not propagate: without that, every security
    # record would also be written by the application handler, doubling volume
    # and putting detection records in the debugging log.
    if files.get("enabled"):
        app_handlers.append(_build_file_handler(files.get("app", "logs/app.log"), service, files))
        security_handlers.append(
            _build_file_handler(files.get("security", "logs/security.log"), service, files)
        )
        audit_handlers.append(
            _build_file_handler(files.get("audit", "logs/audit.log"), service, files)
        )

    _configure_stream(LOGGER_APP, resolved_level, app_handlers, propagate=False)
    _configure_stream(LOGGER_SECURITY, resolved_level, security_handlers, propagate=False)
    _configure_stream(LOGGER_AUDIT, resolved_level, audit_handlers, propagate=False)

    _configured = True


def get_security_logger() -> logging.Logger:
    """Return the security stream: what the network did."""
    return logging.getLogger(LOGGER_SECURITY)


def get_audit_logger() -> logging.Logger:
    """Return the audit stream: who asked the system for what."""
    return logging.getLogger(LOGGER_AUDIT)
