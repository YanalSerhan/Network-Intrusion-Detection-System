"""
Detector discovery and instantiation.

Data Setup:  A config directory holding detectors.json.
Data Input:  A package to scan, plus any plugin modules declared elsewhere.
Data Output: Instantiated, configured detectors.

Every failure here is contained to one detector: a malformed config section, a
missing threshold, a plugin whose constructor raises. A sensor that refuses to
start because one detector is misconfigured is worse than a sensor running
twelve of thirteen detectors and saying so in the log.

Built-ins are found by scanning `detectors/impl/`; third-party detectors are
found by `plugins.discovery`, and are otherwise identical — same base class,
same config section in detectors.json, same containment. The only difference
the registry makes between them is that a plugin may not take a built-in's
name, because `detectors.json` is keyed by class name and the collision would
silently give one detector the other's thresholds.
"""

import inspect
import json
import logging
from pathlib import Path
from types import ModuleType
from typing import Any

from network_defender.constants import CONFIG_FILE_DETECTORS
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.registry_config import build_config
from network_defender.plugins.discovery import (
    DETECTOR_GROUP,
    discover_modules,
    import_package_modules,
)

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Auto-discovers and registers detector modules."""

    def __init__(self, config_dir: str) -> None:
        """
        Initialise the registry and read the detector configuration.

        Args:
            config_dir: Directory holding detectors.json.
        """
        self.config_dir = Path(config_dir)
        self.detectors: list[BaseDetector[Any]] = []
        self.config_data: dict[str, dict[str, Any]] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load the global detectors configuration."""
        config_path = self.config_dir / CONFIG_FILE_DETECTORS
        if config_path.exists():
            try:
                with open(config_path, encoding="utf-8") as f:
                    self.config_data = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load detectors config from {config_path}: {e}")
        else:
            logger.warning(f"Detectors config not found at {config_path}. Using defaults.")

    def load_detectors(
        self,
        package_name: str = "network_defender.detectors.impl",
        plugin_modules: list[str] | None = None,
    ) -> None:
        """
        Register every detector in the built-in package and in any plugins.

        Args:
            package_name:   Dotted path of the built-in package to scan.
            plugin_modules: Extra dotted module paths from configuration, on
                            top of whatever installed distributions declare
                            through the entry-point group.
        """
        self.detectors.clear()

        for module in import_package_modules(package_name):
            self._register_module(module)
        builtins = {detector.name for detector in self.detectors}

        for module in discover_modules(DETECTOR_GROUP, plugin_modules):
            self._register_module(module, reserved=builtins)

        logger.info(
            f"Loaded {len(self.detectors)} heuristic detectors "
            f"({len(self.detectors) - len(builtins)} from plugins)."
        )

    def _register_module(self, module: ModuleType, reserved: set[str] | None = None) -> None:
        """
        Register every concrete detector class defined in one module.

        Args:
            module:   An imported module to scan.
            reserved: Names a plugin may not take. detectors.json is keyed by
                      class name, so a plugin shadowing a built-in would be
                      handed thresholds meant for something else.
        """
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if not (
                issubclass(obj, BaseDetector)
                and obj is not BaseDetector
                and not inspect.isabstract(obj)
            ):
                continue
            if reserved and obj.__name__ in reserved:
                logger.error(
                    f"Plugin detector {obj.__name__} from {module.__name__} shadows a "
                    f"built-in of the same name and was not loaded."
                )
                continue
            self._register_detector_class(obj)

    def _register_detector_class(self, detector_cls: type[BaseDetector[Any]]) -> None:
        """
        Instantiate and register one detector class.

        Args:
            detector_cls: A concrete BaseDetector subclass, built-in or plugin.
        """
        config = build_config(detector_cls, self.config_data.get(detector_cls.__name__, {}))
        if config is None:
            return
        try:
            self.detectors.append(detector_cls(config=config))
        except Exception as exc:  # noqa: BLE001 - one bad detector must not stop the sensor
            logger.error(f"Failed to instantiate detector {detector_cls.__name__}: {exc}")
