"""Tests for log format, redaction and correlation propagation."""

import json
import logging
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from network_defender.observability import (
    REDACTED,
    JsonFormatter,
    RedactionFilter,
    bind_correlation_id,
    correlation_scope,
    get_correlation_id,
    new_correlation_id,
    redact_text,
    redact_value,
    set_correlation_id,
)
from network_defender.observability.logging_setup import (
    LOGGER_APP,
    LOGGER_AUDIT,
    LOGGER_SECURITY,
    load_logging_config,
    setup_logging,
)

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
    logger = logging.getLogger("network_defender.test_target")
    logger.handlers = [capture]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield capture
    logger.handlers = []


def log(handler: CapturingHandler) -> logging.Logger:
    """Return the logger the handler is attached to."""
    return logging.getLogger("network_defender.test_target")


# --------------------------------------------------------------------------
# Format
# --------------------------------------------------------------------------


def test_every_record_is_a_single_json_line(handler: CapturingHandler) -> None:
    """Aggregators split on newlines; a multi-line record becomes several."""
    log(handler).info("Something happened\nwith an embedded newline")

    assert len(handler.lines) == 1
    assert "\n" not in handler.lines[0]
    assert json.loads(handler.lines[0])["message"].count("\n") == 1


def test_required_fields_are_always_present(handler: CapturingHandler) -> None:
    log(handler).info("hello")
    record = handler.records[0]

    assert set(record) >= REQUIRED_FIELDS
    assert record["level"] == "INFO"
    assert record["service"] == "test-service"
    assert record["logger"] == "network_defender.test_target"


def test_timestamp_is_iso_utc(handler: CapturingHandler) -> None:
    log(handler).info("hello")
    timestamp = str(handler.records[0]["timestamp"])

    assert timestamp.endswith("+00:00")
    assert "T" in timestamp


def test_extra_fields_are_merged_not_nested(handler: CapturingHandler) -> None:
    """`alert_id` must be queryable as `alert_id`, not `extra.alert_id`."""
    log(handler).info("Alert raised", extra={"alert_id": "abc", "severity": "high"})
    record = handler.records[0]

    assert record["alert_id"] == "abc"
    assert record["severity"] == "high"


def test_source_location_only_on_warnings_and_above(handler: CapturingHandler) -> None:
    """Including it on every INFO line inflates volume for no benefit."""
    log(handler).info("routine")
    log(handler).warning("unusual")

    assert "source" not in handler.records[0]
    assert "source" in handler.records[1]


def test_exceptions_are_folded_into_one_field(handler: CapturingHandler) -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        log(handler).error("Failed", exc_info=True)

    record = handler.records[0]
    assert "ValueError: boom" in str(record["exception"])
    assert len(handler.lines) == 1


def test_message_interpolation_happens_before_emit(handler: CapturingHandler) -> None:
    log(handler).info("Loaded %d rules from %s", 7, "rules/")
    assert handler.records[0]["message"] == "Loaded 7 rules from rules/"


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


def test_database_url_password_is_redacted(handler: CapturingHandler) -> None:
    log(handler).info("Connecting to postgresql://admin:hunter2@db:5432/nd")

    assert "hunter2" not in handler.text
    assert REDACTED in handler.text


def test_sensitive_extra_fields_are_redacted(handler: CapturingHandler) -> None:
    log(handler).info("Configured", extra={"api_key": "sk-live-123", "provider": "abuseipdb"})
    record = handler.records[0]

    assert record["api_key"] == REDACTED
    assert record["provider"] == "abuseipdb"  # non-sensitive fields survive


def test_secrets_inside_exceptions_are_redacted(handler: CapturingHandler) -> None:
    """The filter runs before the traceback is rendered, so this is a real gap."""
    try:
        raise ValueError("auth failed for token=SUPERSECRET")
    except ValueError:
        log(handler).error("Provider call failed", exc_info=True)

    assert "SUPERSECRET" not in handler.text


def test_nested_secrets_are_redacted(handler: CapturingHandler) -> None:
    log(handler).info("Payload", extra={"body": {"auth": {"password": "hunter2"}}})
    assert "hunter2" not in handler.text


@pytest.mark.parametrize(
    "text",
    [
        "api_key=sk-live-abc123",
        "token: ghp_abcdef123456",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
        "password=hunter2",
        "mysql://root:s3cr3t@127.0.0.1/db",
    ],
)
def test_credential_shaped_text_is_redacted(text: str) -> None:
    redacted = redact_text(text)
    secrets = ("sk-live-abc123", "ghp_abcdef123456", "eyJhbGciOiJIUzI1NiJ9", "hunter2", "s3cr3t")
    for secret in secrets:
        assert secret not in redacted


def test_redaction_preserves_non_secrets() -> None:
    assert redact_text("Loaded 13 detectors from config/") == "Loaded 13 detectors from config/"
    assert redact_value({"src_ip": "45.155.205.233"}) == {"src_ip": "45.155.205.233"}


def test_redaction_handles_collections_and_depth() -> None:
    result = redact_value({"items": [{"token": "abc"}, {"ip": "1.1.1.1"}]})
    assert result == {"items": [{"token": REDACTED}, {"ip": "1.1.1.1"}]}


def test_redaction_never_drops_a_record(handler: CapturingHandler) -> None:
    """Losing the operational signal along with the secret would be worse."""
    log(handler).info("password=hunter2")
    assert len(handler.lines) == 1


# --------------------------------------------------------------------------
# Correlation IDs
# --------------------------------------------------------------------------


def test_correlation_id_appears_in_records(handler: CapturingHandler) -> None:
    with correlation_scope("fixed-id"):
        log(handler).info("inside")
    log(handler).info("outside")

    assert handler.records[0]["correlation_id"] == "fixed-id"
    assert "correlation_id" not in handler.records[1]


def test_scope_restores_the_previous_id() -> None:
    """Nesting must hand the outer ID back, not clear it."""
    with correlation_scope("outer"):
        with correlation_scope("inner"):
            assert get_correlation_id() == "inner"
        assert get_correlation_id() == "outer"
    assert get_correlation_id() is None


def test_scope_mints_an_id_when_none_is_given() -> None:
    with correlation_scope() as correlation_id:
        assert correlation_id
        assert get_correlation_id() == correlation_id


def test_ids_are_unique_and_short() -> None:
    ids = {new_correlation_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(value) == 16 for value in ids)


def test_set_and_clear() -> None:
    set_correlation_id("manual")
    assert get_correlation_id() == "manual"
    set_correlation_id(None)
    assert get_correlation_id() is None


def test_context_does_not_cross_threads_without_binding() -> None:
    """The reason bind_correlation_id exists at all."""
    seen: list[str | None] = []

    with correlation_scope("request-id"):
        thread = threading.Thread(target=lambda: seen.append(get_correlation_id()))
        thread.start()
        thread.join()

    assert seen == [None]


def test_bind_carries_the_id_across_a_thread() -> None:
    seen: list[str | None] = []

    with correlation_scope("request-id"):
        work = bind_correlation_id(lambda: seen.append(get_correlation_id()))

    thread = threading.Thread(target=work)
    thread.start()
    thread.join()

    assert seen == ["request-id"]


# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------


def test_setup_configures_the_three_streams() -> None:
    setup_logging(service="test", force=True)

    for name in (LOGGER_APP, LOGGER_SECURITY, LOGGER_AUDIT):
        logger = logging.getLogger(name)
        assert logger.handlers, f"{name} has no handler"
        assert all(any(isinstance(f, RedactionFilter) for f in h.filters) for h in logger.handlers)


def test_security_and_audit_do_not_propagate() -> None:
    """Otherwise every detection record is duplicated into the app log."""
    setup_logging(service="test", force=True)

    assert logging.getLogger(LOGGER_SECURITY).propagate is False
    assert logging.getLogger(LOGGER_AUDIT).propagate is False


def test_setup_is_idempotent() -> None:
    setup_logging(service="test", force=True)
    before = len(logging.getLogger(LOGGER_APP).handlers)

    setup_logging(service="test")
    assert len(logging.getLogger(LOGGER_APP).handlers) == before


def test_files_are_off_by_default() -> None:
    """No stray logs/ directory should appear during a test run."""
    assert load_logging_config().get("files", {}).get("enabled") is False


def test_file_handlers_rotate_when_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from network_defender.observability import logging_setup

    monkeypatch.setattr(
        logging_setup,
        "load_logging_config",
        lambda: {
            "level": "INFO",
            "files": {
                "enabled": True,
                "app": str(tmp_path / "app.log"),
                "security": str(tmp_path / "security.log"),
                "audit": str(tmp_path / "audit.log"),
                "max_bytes": 1024,
                "backup_count": 2,
            },
        },
    )
    setup_logging(service="test", force=True)
    try:
        logging.getLogger(LOGGER_APP).info("written to file")
        assert (tmp_path / "app.log").exists()

        handlers = logging.getLogger(LOGGER_APP).handlers
        rotating = [h for h in handlers if hasattr(h, "maxBytes")]
        assert rotating and rotating[0].maxBytes == 1024  # type: ignore[attr-defined]
        assert rotating[0].backupCount == 2  # type: ignore[attr-defined]
    finally:
        setup_logging(service="test", force=True)


def test_missing_config_falls_back_to_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An absent config must not stop logging from coming up."""
    from network_defender.observability import logging_setup

    monkeypatch.setattr(logging_setup, "CONFIG_DIR", tmp_path)
    assert load_logging_config() == {}


def test_malformed_config_falls_back_to_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo must not silence the system that would report it."""
    from network_defender.observability import logging_setup

    (tmp_path / "logging_config.json").write_text("{ this is not json")
    monkeypatch.setattr(logging_setup, "CONFIG_DIR", tmp_path)

    assert load_logging_config() == {}
    setup_logging(service="test", force=True)  # must still come up
    assert logging.getLogger(LOGGER_APP).handlers
