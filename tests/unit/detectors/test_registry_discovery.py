"""
Tests for detector discovery: what the registry does with the world as found.

Discovery reads a JSON file that may be missing or corrupt and imports a
package that may not exist. Each of those is a normal condition on a real
host, not an exception, so each has to leave the registry usable.
"""

import json
from pathlib import Path

from network_defender.detectors.registry import DetectorRegistry
from network_defender.shared.paths import PROJECT_ROOT


def test_a_missing_config_file_falls_back_to_defaults(tmp_path: Path) -> None:
    """A fresh install has no detectors.json; every detector must still load."""
    registry = DetectorRegistry(str(tmp_path))

    assert registry.config_data == {}

    registry.load_detectors()
    assert registry.detectors


def test_a_corrupt_config_file_does_not_stop_startup(tmp_path: Path) -> None:
    """Half-written JSON is a bad configuration, not a reason to refuse to run."""
    (tmp_path / "detectors.json").write_text("{ this is not json")
    registry = DetectorRegistry(str(tmp_path))

    assert registry.config_data == {}

    registry.load_detectors()
    assert registry.detectors


def test_an_unimportable_package_yields_no_detectors(tmp_path: Path) -> None:
    """A bad plugin path is reported and survived, not raised."""
    registry = DetectorRegistry(str(tmp_path))

    registry.load_detectors(package_name="network_defender.detectors.does_not_exist")
    assert registry.detectors == []


def test_the_shipped_configuration_loads_every_enabled_detector() -> None:
    """Each entry in config/detectors.json must map to a real detector class."""
    config_dir = PROJECT_ROOT / "config"
    configured = json.loads((config_dir / "detectors.json").read_text())
    enabled = {
        name for name, settings in configured.items() if settings.get("enabled", True)
    }

    registry = DetectorRegistry(str(config_dir))
    registry.load_detectors()

    assert {detector.name for detector in registry.detectors} == enabled


def test_reloading_replaces_rather_than_appends() -> None:
    """Hot reload must not leave two copies of every detector behind."""
    registry = DetectorRegistry(str(PROJECT_ROOT / "config"))

    registry.load_detectors()
    first = len(registry.detectors)
    registry.load_detectors()

    assert len(registry.detectors) == first
