"""
Which endpoint a counting detector blames.

Data Setup:  None.
Data Input:  A parsed packet.
Data Output: The address to count against, and how to name it on the alert.

Split from `counting` because this is the decision worth reading on its own,
and it is not arbitrary:

  * Floods key on the **destination**. A flood is usually distributed, which
    is the point of it, so per-source counters never individually reach a
    threshold while the victim is what every packet has in common.
  * Credential guessing and ARP abuse key on the **source**. One host is doing
    the work, and the attacker is the identity an analyst needs named.

The cost of the first choice is that a busy server is shaped like a victim,
which the sensitivity corpus measures rather than assumes — see
docs/DETECTION_TUNING.md.
"""

from network_defender.detectors.impl.counting import CountingDetector
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket


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
