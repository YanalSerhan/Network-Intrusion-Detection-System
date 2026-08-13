"""
Volumetric flood detectors: SYN, UDP and ICMP.

Data Setup:  Per-destination counters, reset every evaluation window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per destination that crossed its threshold.

The counting, alerting and window-clearing are shared — see `counting`. What
differs between the three is only which packets count, how many are too many,
and how bad it is: a SYN flood consumes a connection-table entry per packet
and is CRITICAL, a UDP flood consumes bandwidth and is HIGH, and an ICMP flood
is usually noise and is MEDIUM.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .counting_endpoints import DestinationCountingDetector


class SynFloodConfig(DetectorConfig):
    """Tunables for the SYN flood detector."""

    time_window_seconds: int = Field(default=1)
    syn_count_threshold: int = Field(default=100)


class SynFloodDetector(DestinationCountingDetector[SynFloodConfig]):
    """
    Detects a high volume of SYN packets aimed at one destination.

    Counts bare SYNs only. A SYN-ACK is a server answering, and an established
    connection's data carries ACK — counting either would make every busy
    server look like a victim.
    """

    evidence_key = "syn_count"
    severity = Severity.CRITICAL
    tactic = MitreTactic.IMPACT

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SynFloodDetector"

    @property
    def threshold(self) -> int:
        """SYNs per window at or above which the flood is reported."""
        return self.config.syn_count_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for a bare SYN — no ACK, no established connection."""
        return bool(
            packet.protocol == Protocol.TCP and packet.tcp_flags and packet.tcp_flags.syn
        )

    def describe(self, count: int) -> str:
        """Describe the flood for the analyst reading the alert."""
        return f"SYN Flood detected: {count} SYN packets to destination."


class UdpFloodConfig(DetectorConfig):
    """Tunables for the UDP flood detector."""

    time_window_seconds: int = Field(default=1)
    udp_count_threshold: int = Field(default=200)


class UdpFloodDetector(DestinationCountingDetector[UdpFloodConfig]):
    """
    Detects a high volume of UDP datagrams aimed at one destination.

    The threshold is the highest of the three because normal UDP is the
    chattiest: DNS, NTP and discovery protocols all run over it.
    """

    evidence_key = "udp_count"
    severity = Severity.HIGH
    tactic = MitreTactic.IMPACT

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "UdpFloodDetector"

    @property
    def threshold(self) -> int:
        """Datagrams per window at or above which the flood is reported."""
        return self.config.udp_count_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for any UDP datagram."""
        return bool(packet.protocol == Protocol.UDP)

    def describe(self, count: int) -> str:
        """Describe the flood for the analyst reading the alert."""
        return f"UDP Flood detected: {count} packets."


class IcmpFloodConfig(DetectorConfig):
    """Tunables for the ICMP flood detector."""

    time_window_seconds: int = Field(default=1)
    icmp_count_threshold: int = Field(default=50)


class IcmpFloodDetector(DestinationCountingDetector[IcmpFloodConfig]):
    """
    Detects a high volume of ICMP traffic, such as a ping flood.

    The lowest threshold of the three: sustained ICMP at any real rate is
    already abnormal, since nothing legitimate pings in bulk.
    """

    evidence_key = "icmp_count"
    severity = Severity.MEDIUM
    tactic = MitreTactic.IMPACT

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "IcmpFloodDetector"

    @property
    def threshold(self) -> int:
        """Packets per window at or above which the flood is reported."""
        return self.config.icmp_count_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for any ICMP packet."""
        return bool(packet.protocol == Protocol.ICMP)

    def describe(self, count: int) -> str:
        """Describe the flood for the analyst reading the alert."""
        return f"ICMP Flood detected: {count} packets."
