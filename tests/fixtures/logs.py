"""
Log-capture helpers for the observability suite.

Data Setup:  ``handler`` wires a capturing handler onto an isolated logger.
Data Input:  Log calls made through ``log(handler)``.
Data Output: The formatted lines, and their parsed JSON payloads.

Asserting on the formatted output rather than on the record object is
deliberate: the thing that has to be right is the line that reaches the log
aggregator, and only the formatter and its filters decide that.
"""

import json
import logging
from collections.abc import Iterator

import pytest

from network_defender.observability import JsonFormatter, RedactionFilter

#: The logger every captured record is emitted through.
CAPTURE_LOGGER_NAME = "network_defender.test_target"

#: Fields every record must carry, whatever else varies.
REQUIRED_FIELDS = {"timestamp", "level", "logger", "service", "message"}


class CapturingHandler(logging.Handler):
    """Collects formatted records so tests can assert on the emitted JSON."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []
        self.setFormatter(JsonFormatter(service="test-service"))
        self.addFilter(RedactionFilter())

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    @property
    def records(self) -> list[dict[str, object]]:
        """Parsed JSON payloads."""
        return [json.loads(line) for line in self.lines]

    @property
    def text(self) -> str:
        """All output as one string, for leak assertions."""
        return "\n".join(self.lines)


@pytest.fixture()
def handler() -> Iterator[CapturingHandler]:
    """A logger wired to a capturing handler, isolated from global config."""
    capture = CapturingHandler()
    logger = logging.getLogger(CAPTURE_LOGGER_NAME)
    logger.handlers = [capture]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield capture
    logger.handlers = []


def log(handler: CapturingHandler) -> logging.Logger:
    """Return the logger the given capturing handler is attached to."""
    return logging.getLogger(CAPTURE_LOGGER_NAME)
