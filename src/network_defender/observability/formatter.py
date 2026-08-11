"""
Structured JSON log formatter.

Data Setup:  No configuration beyond the field list below.
Data Input:  Standard library LogRecords.
Data Output: One JSON object per line.

Why one line per record
-----------------------
Log aggregators (Loki, CloudWatch, Elastic) split on newlines. A pretty-printed
or multi-line record becomes several unrelated entries, and a stack trace
becomes dozens — which is exactly when you most need them grouped. Exceptions
are therefore folded into a single `exception` string field.

Field names are fixed and lowercase so a query written against one deployment
works against another; anything a caller passes via `extra=` is merged in
alongside, not nested, so `alert_id` is queryable as `alert_id`.
"""

import json
import logging
import traceback
from datetime import UTC, datetime
from typing import Any

from .context import get_correlation_id
from .redaction import redact_text

#: Attributes the logging module puts on every record. Anything outside this
#: set came from `extra=` and is caller-supplied context worth emitting.
_RESERVED = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "module", "msecs",
        "message", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """Renders LogRecords as single-line JSON objects."""

    def __init__(self, service: str = "network-defender") -> None:
        """
        Initialise the formatter.

        Args:
            service: Value emitted as the `service` field, so logs from the
                sensor and the API remain distinguishable once shipped to a
                shared aggregator.
        """
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        """
        Render one record as a JSON line.

        Args:
            record: The record to format.

        Returns:
            A JSON object string with no embedded newlines.
        """
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": self._service,
            "message": record.getMessage(),
        }

        correlation_id = get_correlation_id()
        if correlation_id:
            payload["correlation_id"] = correlation_id

        # Source location is only useful when something went wrong; including
        # it on every INFO line inflates volume for no operational benefit.
        if record.levelno >= logging.WARNING:
            payload["source"] = f"{record.module}:{record.funcName}:{record.lineno}"

        if record.exc_info:
            # Redacted here rather than in the filter: the filter runs before
            # the traceback is rendered, so it cannot reach this text. And
            # exception messages are a common leak — connection strings and
            # tokens routinely end up in them.
            rendered = "".join(traceback.format_exception(*record.exc_info)).strip()
            payload["exception"] = redact_text(rendered)

        payload.update(self._extras(record))
        return json.dumps(payload, default=str, ensure_ascii=False)

    @staticmethod
    def _extras(record: logging.LogRecord) -> dict[str, Any]:
        """Return caller-supplied `extra=` fields, skipping private names."""
        return {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED and not key.startswith("_")
        }
