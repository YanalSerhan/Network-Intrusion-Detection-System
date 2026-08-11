"""
Secret redaction for log records.

Data Setup:  Sensitive key names and patterns are defined here, not in config,
             so a misconfigured deployment cannot switch redaction off.
Data Input:  LogRecords about to be emitted.
Data Output: The same records with secrets replaced by a placeholder.

Why a filter rather than careful call sites
-------------------------------------------
"Just don't log secrets" fails in practice: a dict gets logged wholesale, an
exception message embeds a connection string, a new provider adds a token
field. Logs are also the artefact most likely to be shipped off-host, pasted
into a ticket, or retained for years. A filter on the handler is the one place
that catches all of those, including code written later by someone who has not
read this docstring.

Redaction runs on both the message and every `extra=` field, and applies
recursively to nested structures, because a token is just as exposed at
`payload.auth.key` as at the top level.
"""

import logging
import re
from typing import Any

REDACTED = "***REDACTED***"

#: Field names whose values are always replaced. Matched case-insensitively as
#: substrings, so `abuseipdb_api_key` and `X-API-Key` are both caught.
SENSITIVE_KEYS = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "credential", "private_key", "session",
)

#: Values that leak secrets regardless of the field they arrive in.
#:
#: Order matters. The Bearer pattern runs first because the generic key/value
#: pattern would otherwise match "Authorization: Bearer" and redact the word
#: "Bearer" while leaving the token itself in plain sight.
SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Bearer tokens in headers or messages.
    re.compile(r"(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+/=-]+)", re.IGNORECASE),
    # Database URLs embed credentials: postgresql://user:password@host/db
    re.compile(r"(?P<prefix>[a-z+]+://[^:/\s]+:)[^@\s]+(?P<suffix>@)", re.IGNORECASE),
    # "api_key=abc123", "token: abc123", "password=hunter2"
    re.compile(
        r"(?P<prefix>\b(?:api[_-]?key|token|password|secret|authorization)\b\s*[=:]\s*)"
        r"(?P<value>[^\s,;&'\"}\]]+)",
        re.IGNORECASE,
    ),
)

#: Cap on recursion into nested structures. Deeply nested payloads are far more
#: likely to be a cycle or an accident than something worth logging in full.
MAX_DEPTH = 6


def _is_sensitive_key(key: str) -> bool:
    """Return True if a field name suggests the value is a credential."""
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEYS)


def redact_text(text: str) -> str:
    """
    Replace credential-shaped substrings in free text.

    Args:
        text: The text to scrub.

    Returns:
        The text with secret values replaced.
    """
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group('prefix')}{REDACTED}", text)
    return text


def redact_value(value: Any, depth: int = 0) -> Any:
    """
    Recursively redact secrets in a value.

    Args:
        value: Any loggable value.
        depth: Current recursion depth.

    Returns:
        The value with secrets replaced.
    """
    if depth >= MAX_DEPTH:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_sensitive_key(str(key)) else redact_value(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return type(value)(redact_value(item, depth + 1) for item in value)
    return value


class RedactionFilter(logging.Filter):
    """Scrubs credentials from every record passing through a handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Redact the record in place.

        Always returns True: the filter exists to modify records, never to
        suppress them. Dropping a log line because it looked sensitive would
        lose the operational signal along with the secret.
        """
        # Render the message now, so redaction sees the interpolated result
        # rather than a format string whose arguments still hold the secret.
        record.msg = redact_text(record.getMessage())
        record.args = ()

        for key, value in list(record.__dict__.items()):
            if key.startswith("_") or key in {"msg", "args", "message"}:
                continue
            if _is_sensitive_key(key):
                record.__dict__[key] = REDACTED
            elif isinstance(value, (str, dict, list, tuple, set)):
                record.__dict__[key] = redact_value(value)

        return True
