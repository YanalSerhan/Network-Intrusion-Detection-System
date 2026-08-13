"""Tests that secrets never reach a log line, however they are supplied."""


import pytest

from network_defender.observability import (
    REDACTED,
    redact_text,
    redact_value,
)
from tests.fixtures.logs import CapturingHandler, log


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
