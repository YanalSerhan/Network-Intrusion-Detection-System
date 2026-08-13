"""Tests for configuration loading and fail-fast validation reporting."""

import json
from pathlib import Path

import pytest

from network_defender.shared.config import (
    load_app_config,
    load_rate_limit_config,
    validate_all,
)
from network_defender.shared.config_errors import ConfigurationError, load_json_file

# --------------------------------------------------------------------------
# End-to-end loading
# --------------------------------------------------------------------------


def test_env_overrides_reach_the_loaded_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ND__CAPTURE__INTERFACE", "eth9")
    monkeypatch.setenv("ND__API__PORT", "9999")

    config = load_app_config()
    assert config.capture.interface == "eth9"
    assert config.api.port == 9999


def test_config_file_is_the_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(dict(__import__("os").environ)):
        if name.startswith("ND__"):
            monkeypatch.delenv(name, raising=False)

    config = load_app_config()
    assert config.capture.interface == "eth0"  # from setup.json


def test_database_url_still_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connection string is a credential, so it keeps its own path."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pw@host/db")
    assert load_app_config().database.default_url == "postgresql://user:pw@host/db"

# --------------------------------------------------------------------------
# Validation and error reporting
# --------------------------------------------------------------------------


def test_invalid_value_aborts_with_the_field_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ND__API__PORT", "not-a-port")

    with pytest.raises(ConfigurationError) as caught:
        load_app_config()

    message = str(caught.value)
    assert "api.port" in message
    assert "not-a-port" in message  # the offending value, so it is actionable


def test_every_problem_is_reported_in_one_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixing config one restart per mistake is a miserable loop."""
    monkeypatch.setenv("ND__API__PORT", "not-a-port")
    monkeypatch.setenv("ND__MAINTENANCE__STATISTICS_INTERVAL_SECONDS", "-5")

    with pytest.raises(ConfigurationError) as caught:
        load_app_config()

    assert len(caught.value.problems) == 2


def test_out_of_range_values_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ND__THREAT_INTEL__CACHE_TTL_SECONDS", "0")

    with pytest.raises(ConfigurationError, match="greater than 0"):
        load_app_config()


def test_malformed_json_names_the_line(tmp_path: Path) -> None:
    """Settings were intended but are not being applied — that is an error."""
    path = tmp_path / "setup.json"
    path.write_text('{ "capture": { "interface": "eth0" ')

    with pytest.raises(ConfigurationError) as caught:
        load_json_file(path)

    assert "invalid JSON" in str(caught.value)
    assert "line 1" in str(caught.value)


def test_missing_file_is_not_an_error(tmp_path: Path) -> None:
    """Every section has defaults, so a partial config is a valid way to run."""
    assert load_json_file(tmp_path / "absent.json") == {}


def test_non_object_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "setup.json"
    path.write_text(json.dumps([1, 2, 3]))

    with pytest.raises(ConfigurationError, match="expected a JSON object"):
        load_json_file(path)


def test_validate_all_reports_every_file() -> None:
    assert validate_all() == {"setup.json": "ok", "rate_limits.json": "ok"}


def test_validate_all_collects_across_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ND__API__PORT", "not-a-port")

    with pytest.raises(ConfigurationError) as caught:
        validate_all()

    assert any("api.port" in problem for problem in caught.value.problems)


def test_rate_limits_still_load() -> None:
    config = load_rate_limit_config()
    assert "abuseipdb" in config.services
