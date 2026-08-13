"""Tests for ND__ environment overrides: collection, coercion and merging."""


import pytest

from network_defender.shared.config_env import (
    apply_overrides,
    collect_overrides,
)
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
