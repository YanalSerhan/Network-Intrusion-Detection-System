"""
Working out which config class a detector wants, and building it.

Data Setup:  The detectors.json section for one detector.
Data Input:  A detector class.
Data Output: A validated config instance, or None with a reason logged.

Split out of the registry because it is a different question. The registry
asks "what detectors exist"; this asks "what does this one need to be
constructed", and answering it means reading a type annotation that is not
always a type.
"""

import importlib
import inspect
import logging
from typing import Any, TypeVar, get_origin

from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectorConfig

logger = logging.getLogger(__name__)


def resolve_config_class(
    detector_cls: type[BaseDetector[Any]],
) -> type[DetectorConfig] | None:
    """
    Return the DetectorConfig subclass a detector's __init__ asks for.

    Args:
        detector_cls: A concrete detector class.

    Returns:
        The config class, or None if the detector does not declare a usable one.
    """
    detector_name = detector_cls.__name__
    config_param = inspect.signature(detector_cls.__init__).parameters.get("config")
    if not config_param or config_param.annotation == inspect.Parameter.empty:
        logger.error(f"Detector {detector_name} has no typed 'config' parameter in __init__.")
        return None

    config_cls = config_param.annotation

    # The annotation is not always the config class itself. It is a string
    # under `from __future__ import annotations`, a generic alias when the
    # parameter is parameterised, and a TypeVar when the detector inherits its
    # __init__ from a generic base — which is what a detector family sharing
    # an implementation looks like. In all three cases the class is resolved
    # by name instead.
    if isinstance(config_cls, str | TypeVar) or get_origin(config_cls) is not None:
        # Assume the config class shares the detector's name but ends in
        # "Config"; otherwise fall back to the base.
        module = importlib.import_module(detector_cls.__module__)
        config_cls_name = f"{detector_name.replace('Detector', '')}Config"
        config_cls = getattr(module, config_cls_name, DetectorConfig)

    if not (isinstance(config_cls, type) and issubclass(config_cls, DetectorConfig)):
        logger.error(f"Config {config_cls} for {detector_name} is not a DetectorConfig subclass.")
        return None
    return config_cls


def build_config(
    detector_cls: type[BaseDetector[Any]],
    section: dict[str, Any],
) -> DetectorConfig | None:
    """
    Build a detector's config from its detectors.json section.

    Args:
        detector_cls: A concrete detector class.
        section:      That detector's entry in detectors.json, possibly empty.

    Returns:
        A validated config, or None if the detector is disabled or the section
        does not validate. Either way the reason is logged and the sensor
        carries on with the detectors that did work.
    """
    config_cls = resolve_config_class(detector_cls)
    if config_cls is None:
        return None
    try:
        config = config_cls(**section)
    except Exception as exc:  # noqa: BLE001 - one bad section must not stop the sensor
        logger.error(f"Failed to instantiate config for {detector_cls.__name__}: {exc}")
        return None
    if not config.enabled:
        logger.info(f"Detector {detector_cls.__name__} is disabled via config.")
        return None
    return config
