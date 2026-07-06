"""
Base abstract classes for heuristic detectors.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from network_defender.parser.models import ParsedPacket

from .models import DetectionAlert, DetectorConfig

TConfig = TypeVar("TConfig", bound=DetectorConfig)


class BaseDetector(ABC, Generic[TConfig]):
    """
    Abstract base class for all heuristic detectors.
    Ensures that new detectors can be added by subclassing without changing existing code.
    """

    def __init__(self, config: TConfig) -> None:
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the detector."""
        pass

    @abstractmethod
    def ingest(self, packet: ParsedPacket) -> None:
        """
        Ingest a parsed packet. 
        Detectors should update their internal state/counters here.
        """
        pass

    @abstractmethod
    def evaluate(self) -> list[DetectionAlert]:
        """
        Evaluate the internal state and emit alerts if thresholds are met.
        Detectors must also handle clearing/resetting their state for the next window.
        """
        pass

    def emit_alert(self, **kwargs: Any) -> DetectionAlert:
        """
        Helper method to instantiate a DetectionAlert.
        Ensures `detector_name` is correctly populated.
        """
        return DetectionAlert(detector_name=self.name, **kwargs)
