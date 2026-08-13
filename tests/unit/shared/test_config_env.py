"""
Tests for environment overrides and configuration validation.

The coercion tests matter more than they look: an env var is always a string,
and `bool("false")` is True. Without coercion, `ND__CAPTURE__PROMISCUOUS_MODE=false`
would silently enable the thing an operator meant to disable.
"""

import json
from pathlib import Path

import pytest

from network_defender.shared.config import (
    load_app_config,
    load_rate_limit_config,
    validate_all,
)
from network_defender.shared.config_env import (
    apply_overrides,
    collect_overrides,
)
from network_defender.shared.config_errors import ConfigurationError, load_json_file
from network_defender.shared.config_models import AppConfig

# --------------------------------------------------------------------------
# Override collection and coercion
# --------------------------------------------------------------------------


def test_prefixed_variables_become_nested_overrides() -> None:
    overrides = collect_overrides(AppConfig, {"ND__CAPTURE__INTERFACE": "eth1"})
    assert overrides == {"capture": {"interface": "eth1"}}


def test_unprefixed_variables_are_ignored() -> None:
    """A shared container environment is full of unrelated variables."""
    environ = {"PATH": "/usr/bin", "HOME": "/root", "DATABASE_URL": "sqlite://"}
    assert collect_overrides(AppConfig, environ) == {}


def test_integers_are_coerced() -> None:
    overrides = collect_overrides(AppConfig, {"ND__API__PORT": "9000"})
    assert overrides["api"]["port"] == 9000
    assert isinstance(overrides["api"]["port"], int)


def test_floats_are_coerced() -> None:
    overrides = collect_overrides(
        AppConfig, {"ND__DETECTION__EVALUATION_INTERVAL_SECONDS": "2.5"}
    )
    assert overrides["detection"]["evaluation_interval_seconds"] == 2.5


@pytest.mark.parametrize("raw", ["false", "False", "0", "no", "off"])
def test_falsey_strings_become_false(raw: str) -> None:
    """bool('false') is True — the whole reason coercion exists."""
    overrides = collect_overrides(AppConfig, {"ND__CAPTURE__PROMISCUOUS_MODE": raw})
    assert overrides["capture"]["promiscuous_mode"] is False


@pytest.mark.parametrize("raw", ["true", "True", "1", "yes", "on"])
def test_truthy_strings_become_true(raw: str) -> None:
    overrides = collect_overrides(AppConfig, {"ND__CAPTURE__PROMISCUOUS_MODE": raw})
    assert overrides["capture"]["promiscuous_mode"] is True


def test_uncoercible_values_are_left_for_validation() -> None:
    """Guessing would hide the mistake; validation should report it."""
    overrides = collect_overrides(AppConfig, {"ND__API__PORT": "not-a-port"})
    assert overrides["api"]["port"] == "not-a-port"


def test_lists_accept_json() -> None:
    overrides = collect_overrides(
        AppConfig, {"ND__THREAT_INTEL__PROVIDERS": '["whois", "abuseipdb"]'}
    )
    assert overrides["threat_intel"]["providers"] == ["whois", "abuseipdb"]


def test_lists_accept_comma_separated_values() -> None:
    """Friendlier to type in a shell than JSON quoting."""
    overrides = collect_overrides(AppConfig, {"ND__THREAT_INTEL__PROVIDERS": "whois, ip_api_geo"})
    assert overrides["threat_intel"]["providers"] == ["whois", "ip_api_geo"]


def test_unknown_sections_are_collected_for_validation_to_reject() -> None:
    overrides = collect_overrides(AppConfig, {"ND__NOSUCH__KEY": "value"})
    assert overrides == {"nosuch": {"key": "value"}}


def test_deeper_paths_are_ignored() -> None:
    """The schema is two levels; accepting more would imply support."""
    assert collect_overrides(AppConfig, {"ND__A__B__C": "x"}) == {}


# --------------------------------------------------------------------------
# Merging
# --------------------------------------------------------------------------


def test_overrides_merge_without_dropping_siblings() -> None:
    raw = {"capture": {"interface": "eth0", "snaplen": 65535}}
    merged = apply_overrides(raw, {"capture": {"interface": "eth1"}})

    assert merged["capture"] == {"interface": "eth1", "snaplen": 65535}


def test_merging_does_not_mutate_the_input() -> None:
    raw = {"capture": {"interface": "eth0"}}
    apply_overrides(raw, {"capture": {"interface": "eth1"}})
    assert raw["capture"]["interface"] == "eth0"


def test_overrides_can_introduce_a_missing_section() -> None:
    merged = apply_overrides({}, {"api": {"port": 9000}})
    assert merged == {"api": {"port": 9000}}


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
