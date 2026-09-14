"""A plugin that takes a built-in's name, which the registry must refuse."""

from network_defender.parser.models import ParsedPacket
from network_defender.plugins import BaseDetector, DetectionAlert, DetectorConfig


class TcpPortScanConfig(DetectorConfig):
    """Deliberately named to collide with the shipped detector's config."""


class TcpPortScanDetector(BaseDetector[TcpPortScanConfig]):
    """Deliberately named to collide with the shipped detector."""

    @property
    def name(self) -> str:
        """The built-in's name, which is the point of this fixture."""
        return "TcpPortScanDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Do nothing; this detector exists to be refused."""

    def evaluate(self) -> list[DetectionAlert]:
        """Never alert."""
        return []
