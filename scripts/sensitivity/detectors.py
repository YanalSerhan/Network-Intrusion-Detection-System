"""
Building one detector at a time, with one parameter overridden.

Data Setup:  The registry is loaded once against the shipped config directory.
Data Input:  A detector name and a parameter override.
Data Output: A fresh, configured detector instance.

The classes come from `DetectorRegistry` rather than from an import list here.
Anything hand-maintained would go stale the first time a detector was added,
and going stale would look like a detector that simply never fires — the same
failure mode the registry exists to prevent.

Each sweep point needs its *own* instance: detectors are stateful by design,
so reusing one across grid points would carry a window's counters into the
next configuration's results.
"""

from typing import Any

from network_defender.detectors import DetectorRegistry
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectorConfig
from network_defender.shared.paths import PROJECT_ROOT

#: Name -> (detector class, config class, the shipped configuration values).
_PROFILES: dict[str, tuple[type[BaseDetector[Any]], type[DetectorConfig], dict[str, Any]]] = {}


def _profiles() -> dict[str, tuple[type[BaseDetector[Any]], type[DetectorConfig], dict[str, Any]]]:
    """Load the registry once and remember what each detector is made of."""
    if not _PROFILES:
        registry = DetectorRegistry(str(PROJECT_ROOT / "config"))
        registry.load_detectors()
        for detector in registry.detectors:
            config = detector.config
            _PROFILES[detector.name] = (type(detector), type(config), config.model_dump())
    return _PROFILES


def detector_names() -> list[str]:
    """Return every detector the registry loaded, in a stable order."""
    return sorted(_profiles())


def shipped_value(name: str, parameter: str) -> Any:
    """
    Return a detector's configured value for one parameter.

    Args:
        name:      Detector class name.
        parameter: Configuration field.

    Returns:
        The value in config/detectors.json, or the field default.
    """
    return _profiles()[name][2][parameter]


def build(name: str, **overrides: Any) -> BaseDetector[Any]:
    """
    Build one detector with its shipped configuration and some overrides.

    Args:
        name:        Detector class name, as it appears in detectors.json.
        **overrides: Configuration fields to replace.

    Returns:
        A freshly constructed detector with empty state.

    Raises:
        KeyError: If the registry did not load a detector by that name.
    """
    detector_cls, config_cls, defaults = _profiles()[name]
    return detector_cls(config=config_cls(**{**defaults, **overrides}))
