"""
Base abstract classes for heuristic detectors.

The TypeVar/Generic form is kept rather than PEP 695 `class BaseDetector[T]`
syntax: the detector registry inspects `__init__` annotations to resolve each
detector's config class, and the older form keeps that introspection working
across interpreter versions.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from network_defender.parser.models import ParsedPacket

from .models import DetectionAlert, DetectorConfig

TConfig = TypeVar("TConfig", bound=DetectorConfig)


class BaseDetector(ABC, Generic[TConfig]):  # noqa: UP046 - see module docstring
    """
    The lifecycle every heuristic detector implements.

    Three methods, deliberately: ingest a packet, evaluate the accumulated
    state, and name yourself. A new detector is added by subclassing this and
    dropping the module into `impl/` — the registry discovers it, and no
    existing code changes. That is the Open/Closed Principle doing real work
    rather than being cited.

    Detectors are stateful by design. `ingest` is on the hot path and must be
    cheap; the expensive decision belongs in `evaluate`, which the service
    calls on a timer.
    """

    def __init__(self, config: TConfig) -> None:
        """
        Initialise with the detector's validated configuration.

        Args:
            config: The subclass's config model, already validated by the
                registry against config/detectors.json.
        """
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the detector."""
        pass

    @abstractmethod
    def ingest(self, packet: ParsedPacket) -> None:
        """
        Take one packet into the detector's state.

        On the hot path — every enabled detector sees every packet — so this
        should update a counter and return, not decide anything.

        Args:
            packet: The packet to account for.
        """
        pass

    @abstractmethod
    def evaluate(self) -> list[DetectionAlert]:
        """
        Decide what the accumulated state means, and start a fresh window.

        Implementations must clear their state before returning. A window that
        is never cleared grows without bound and, worse, keeps re-alerting on
        traffic that has already been reported.

        Returns:
            Alerts for whatever crossed a threshold this window.
        """
        pass

    def emit_alert(self, **kwargs: Any) -> DetectionAlert:
        """
        Build a DetectionAlert attributed to this detector.

        Exists so no subclass has to remember to set `detector_name`, which
        the alert service uses to select MITRE mapping and confidence scoring
        — an alert with the wrong name is misfiled rather than merely mislabelled.

        Args:
            **kwargs: Any DetectionAlert field except `detector_name`.

        Returns:
            The constructed alert.
        """
        return DetectionAlert(detector_name=self.name, **kwargs)
