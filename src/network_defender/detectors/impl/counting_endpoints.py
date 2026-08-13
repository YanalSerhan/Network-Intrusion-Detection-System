"""
Which endpoint a counting detector blames.

Data Setup:  None.
Data Input:  A parsed packet.
Data Output: The address to count against, and how to name it on the alert.

Split from `counting` so the base class file stays inside the 150-line limit,
and because these two are the decision worth reading on its own: a flood is
attributed to its victim and a brute force to its attacker, for reasons the
`counting` module docstring sets out.
"""

from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .counting import CountingDetector


class DestinationCountingDetector[TConfig: DetectorConfig](CountingDetector[TConfig]):
    """Counts against the packet's destination — the victim of a flood."""

    def endpoint(self, packet: ParsedPacket) -> str | None:
        """Return the destination address."""
        return packet.dst_ip

    def attribute(self, address: str) -> dict[str, str]:
        """Name the address as the alert's destination."""
        return {"dst_ip": address}


class SourceCountingDetector[TConfig: DetectorConfig](CountingDetector[TConfig]):
    """Counts against the packet's source — the host doing the work."""

    def endpoint(self, packet: ParsedPacket) -> str | None:
        """Return the source address."""
        return packet.src_ip

    def attribute(self, address: str) -> dict[str, str]:
        """Name the address as the alert's source."""
        return {"src_ip": address}
