"""
Base abstract classes for heuristic detectors.

The TypeVar/Generic form is kept rather than PEP 695 `class BaseDetector[T]`
syntax: the detector registry inspects `__init__` annotations to resolve each
detector's config class, and the older form keeps that introspection working
across interpreter versions.
"""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from network_defender.detectors.edge import EdgeTriggeredMixin
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket

TConfig = TypeVar("TConfig", bound=DetectorConfig)


class BaseDetector(EdgeTriggeredMixin, ABC, Generic[TConfig]):  # noqa: UP046 - see module docstring
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

    How much traffic a detector considers and how often it is asked are two
    different things, and conflating them was a real defect: until Milestone
    21 every detector held state until `evaluate()` cleared it, so the window
    was whatever the shared evaluation interval happened to be — five seconds
    — while nine detectors were configured for sixty or more. Five of them
    could not reach their thresholds at all.

    Now `time_window_seconds` is the detector's own memory and the evaluation
    interval is only how often it is asked. A detector expires its own state
    against capture time; `evaluate()` reports what is currently in the window
    and must not clear it.
    """

    def __init__(self, config: TConfig) -> None:
        """
        Initialise with the detector's validated configuration.

        Args:
            config: The subclass's config model, already validated by the
                registry against config/detectors.json.
        """
        self.config = config
        self._reported: set[str] = set()

    @property
    def window_seconds(self) -> float:
        """How much recent capture time this detector considers."""
        return float(self.config.time_window_seconds)

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
        Report what the last `window_seconds` of traffic means.

        Implementations must **not** clear their state — the window expires on
        its own against capture time. What they must do is drop expired
        observations as they read them, so state stays bounded by one window's
        worth of traffic rather than growing forever, and raise each finding
        once via `report_once` rather than on every evaluation.

        Returns:
            Alerts for whatever crossed a threshold since the last call.
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
