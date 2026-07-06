"""
Detector registry and plugin loader.
"""

import importlib
import inspect
import json
import logging
from pathlib import Path
from typing import get_origin

from network_defender.constants import CONFIG_FILE_DETECTORS

from .base import BaseDetector
from .models import DetectorConfig

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """
    Auto-discovers and registers detector modules.
    """

    def __init__(self, config_dir: str) -> None:
        self.config_dir = Path(config_dir)
        self.detectors: list[BaseDetector] = []
        self.config_data: dict[str, dict] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load the global detectors configuration."""
        config_path = self.config_dir / CONFIG_FILE_DETECTORS
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    self.config_data = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load detectors config from {config_path}: {e}")
        else:
            logger.warning(f"Detectors config not found at {config_path}. Using defaults.")

    def load_detectors(self, package_name: str = "network_defender.detectors.impl") -> None:
        """
        Dynamically import all modules in the given package and instantiate
        all non-abstract subclasses of BaseDetector.
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

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseDetector) and obj is not BaseDetector:
                    if not inspect.isabstract(obj):
                        self._register_detector_class(obj)
        
        logger.info(f"Loaded {len(self.detectors)} heuristic detectors.")

    def _register_detector_class(self, detector_cls: type[BaseDetector]) -> None:
        """Instantiate and register a detector class."""
        detector_name = detector_cls.__name__
        
        init_signature = inspect.signature(detector_cls.__init__)
        config_param = init_signature.parameters.get("config")
        if not config_param or config_param.annotation == inspect.Parameter.empty:
            logger.error(f"Detector {detector_name} is missing a typed 'config' parameter in __init__.")
            return
            
        config_cls = config_param.annotation
        
        # Handle string annotations or Generic Aliases if present
        if isinstance(config_cls, str) or get_origin(config_cls) is not None:
            # We assume the config class has the same name as the detector class but ending in Config
            # Or we can look it up in the module
            module = importlib.import_module(detector_cls.__module__)
            config_cls_name = f"{detector_name.replace('Detector', '')}Config"
            config_cls = getattr(module, config_cls_name, DetectorConfig)
        
        if not (isinstance(config_cls, type) and issubclass(config_cls, DetectorConfig)):
            logger.error(f"Config class {config_cls} for {detector_name} is not a subclass of DetectorConfig.")
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
