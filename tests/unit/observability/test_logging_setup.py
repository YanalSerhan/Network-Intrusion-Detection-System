"""Tests for stream wiring, file rotation and configuration fallbacks."""

import logging
from pathlib import Path

import pytest

from network_defender.observability import (
    RedactionFilter,
)
from network_defender.observability.logging_setup import (
    LOGGER_APP,
    LOGGER_AUDIT,
    LOGGER_SECURITY,
    load_logging_config,
    setup_logging,
)


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
