"""
Logging and observability (Milestone 12).

Structured JSON logs on stdout, correlation IDs that survive the pipeline's
thread hand-offs, separate application/security/audit streams, and redaction
that runs on the handler so no call site can forget it.
"""

from network_defender.observability.context import (
    bind_correlation_id,
    correlation_scope,
    get_correlation_id,
    new_correlation_id,
    set_correlation_id,
)
from network_defender.observability.formatter import JsonFormatter
from network_defender.observability.logging_setup import (
    LOGGER_APP,
    LOGGER_AUDIT,
    LOGGER_SECURITY,
    get_audit_logger,
    get_security_logger,
    setup_logging,
)
from network_defender.observability.redaction import (
    REDACTED,
    RedactionFilter,
    redact_text,
    redact_value,
)

__all__ = [
    "LOGGER_APP",
    "LOGGER_AUDIT",
    "LOGGER_SECURITY",
    "REDACTED",
    "JsonFormatter",
    "RedactionFilter",
    "bind_correlation_id",
    "correlation_scope",
    "get_audit_logger",
    "get_correlation_id",
    "get_security_logger",
    "new_correlation_id",
    "redact_text",
    "redact_value",
    "set_correlation_id",
    "setup_logging",
]
