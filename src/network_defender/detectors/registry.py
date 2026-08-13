"""
Detector discovery and instantiation.

Data Setup:  A config directory holding detectors.json.
Data Input:  A package to scan for BaseDetector subclasses.
Data Output: Instantiated, configured detectors.

Every failure here is contained to one detector: a malformed config section, a
missing threshold, a plugin whose constructor raises. A sensor that refuses to
start because one detector is misconfigured is worse than a sensor running
twelve of thirteen detectors and saying so in the log.
"""

import importlib
import inspect
import json
import logging
from pathlib import Path
from typing import Any, TypeVar, get_origin

from network_defender.constants import CONFIG_FILE_DETECTORS

from .base import BaseDetector
from .models import DetectorConfig

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

    def load_detectors(self, package_name: str = "network_defender.detectors.impl") -> None:
        """
        Import every module in a package and register the detectors in it.

        Args:
            package_name: Dotted path of the package to scan.
        """
        self.detectors.clear()

        try:
            package = importlib.import_module(package_name)
            if package.__file__ is None:
                raise ImportError(f"Package {package_name} has no __file__")
            pkg_path = Path(package.__file__).parent
        except ImportError as e:
            logger.error(f"Failed to import detector package {package_name}: {e}")
            return

        for child in pkg_path.glob("*.py"):
            if child.name == "__init__.py":
                continue

            module_name = f"{package_name}.{child.stem}"
            try:
                module = importlib.import_module(module_name)
            except Exception as e:
                logger.error(f"Failed to load detector module {module_name}: {e}")
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseDetector)
                    and obj is not BaseDetector
                    and not inspect.isabstract(obj)
                ):
                    self._register_detector_class(obj)

        logger.info(f"Loaded {len(self.detectors)} heuristic detectors.")

    def _register_detector_class(self, detector_cls: type[BaseDetector[Any]]) -> None:
        """Instantiate and register a detector class."""
        detector_name = detector_cls.__name__

        init_signature = inspect.signature(detector_cls.__init__)
        config_param = init_signature.parameters.get("config")
        if not config_param or config_param.annotation == inspect.Parameter.empty:
            logger.error(
                f"Detector {detector_name} has no typed 'config' parameter in __init__."
            )
            return

        config_cls = config_param.annotation

        # The annotation is not always the config class itself. It is a string
        # under `from __future__ import annotations`, a generic alias when the
        # parameter is parameterised, and a TypeVar when the detector inherits
        # its __init__ from a generic base — which is what a detector family
        # sharing an implementation looks like. In all three cases the class is
        # resolved by name instead.
        if isinstance(config_cls, str | TypeVar) or get_origin(config_cls) is not None:
            # Assume the config class shares the detector's name but ends in
            # "Config"; otherwise look it up in the defining module.
            module = importlib.import_module(detector_cls.__module__)
            config_cls_name = f"{detector_name.replace('Detector', '')}Config"
            config_cls = getattr(module, config_cls_name, DetectorConfig)

        if not (isinstance(config_cls, type) and issubclass(config_cls, DetectorConfig)):
            logger.error(
                f"Config {config_cls} for {detector_name} is not a DetectorConfig subclass."
            )
            return

        config_dict = self.config_data.get(detector_name, {})

        try:
            config_instance = config_cls(**config_dict)
        except Exception as e:
            logger.error(f"Failed to instantiate config for {detector_name}: {e}")
            return

        if not config_instance.enabled:
            logger.info(f"Detector {detector_name} is disabled via config.")
            return

        try:
            detector_instance = detector_cls(config=config_instance)
            self.detectors.append(detector_instance)
        except Exception as e:
            logger.error(f"Failed to instantiate detector {detector_name}: {e}")
