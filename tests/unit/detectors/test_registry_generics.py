"""
Tests that a detector family sharing one implementation still registers.

The registry resolves each detector's config class from its ``__init__``
annotation. When a detector inherits that ``__init__`` from a generic base —
which is what sharing an implementation looks like — the annotation is a
TypeVar rather than a class, and every member of the family was silently
skipped. The three flood detectors disappeared exactly this way.
"""


from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.registry import DetectorRegistry
from network_defender.parser.models import ParsedPacket


class FamilyBase[TConfig: DetectorConfig](BaseDetector[TConfig]):
    """A shared implementation, the way the flood detectors share one."""

    def __init__(self, config: TConfig) -> None:
        super().__init__(config)

    @property
    def name(self) -> str:
        return "FamilyMemberDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Accept and ignore."""

    def evaluate(self) -> list[DetectionAlert]:
        """Never alert."""
        return []


class FamilyMemberConfig(DetectorConfig):
    """Config resolved by name, since the annotation is a TypeVar."""

    threshold: int = 3


class FamilyMemberDetector(FamilyBase[FamilyMemberConfig]):
    """A detector that inherits its __init__ from the generic base above."""


def test_a_detector_inheriting_a_generic_init_is_still_registered(
    registry: DetectorRegistry,
) -> None:
    """
    Resolution must not depend on a detector spelling out its own __init__.

    Before this, sharing an implementation across a detector family silently
    unregistered every member of it: the inherited annotation is a TypeVar
    rather than a config class, and the registry skipped what it could not
    read. The three flood detectors disappeared exactly this way.
    """
    registry._register_detector_class(FamilyMemberDetector)

    assert [d.name for d in registry.detectors] == ["FamilyMemberDetector"]
