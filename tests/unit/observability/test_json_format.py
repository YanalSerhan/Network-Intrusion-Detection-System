"""Tests for the JSON log formatter: record shape, required fields, interpolation."""

import json

from tests.fixtures.logs import REQUIRED_FIELDS, CapturingHandler, log


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
