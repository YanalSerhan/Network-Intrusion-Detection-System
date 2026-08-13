"""
Detectors for brute force authentication attempts.
"""

from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class SshBruteForceConfig(DetectorConfig):
    """Tunables for the SSH brute force detector."""

    time_window_seconds: int = Field(default=60)
    connection_count_threshold: int = Field(default=10)
    #: Configurable because moving sshd off 22 is common hardening advice, and
    #: a hardcoded port silently blinds this detector on exactly the hosts
    #: whose operators took that advice.
    ssh_port: int = Field(default=22, ge=1, le=65535)


class SshBruteForceDetector(BaseDetector[SshBruteForceConfig]):
    """
    Detects repeated SSH connections (port 22) from a single IP.
    """

    def __init__(self, config: SshBruteForceConfig) -> None:
        super().__init__(config)
        self._src_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "SshBruteForceDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if (
            packet.protocol == Protocol.TCP
            and packet.dst_port == self.config.ssh_port
            and packet.tcp_flags
            and packet.tcp_flags.syn
            and not packet.tcp_flags.ack
            and packet.src_ip
        ):
            self._src_counts[packet.src_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, count in self._src_counts.items():
            if count >= self.config.connection_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.CREDENTIAL_ACCESS,
                        src_ip=src_ip,
                        description=f"Possible SSH Brute Force: {count} connection attempts.",
                        evidence={"connection_count": count}
                    )
                )
        self._src_counts.clear()
        return alerts


class HttpBruteForceConfig(DetectorConfig):
    time_window_seconds: int = Field(default=60)
    connection_count_threshold: int = Field(default=20)


class HttpBruteForceDetector(BaseDetector[HttpBruteForceConfig]):
    """
    Detects repeated HTTP requests to common auth endpoints from a single IP.
    """

    def __init__(self, config: HttpBruteForceConfig) -> None:
        super().__init__(config)
        self._src_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "HttpBruteForceDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.HTTP and packet.http and packet.http.path and packet.src_ip:
            path = packet.http.path.lower()
            if any(endpoint in path for endpoint in ["login", "auth", "signin", "admin"]):
                self._src_counts[packet.src_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, count in self._src_counts.items():
            if count >= self.config.connection_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.MEDIUM,
                        tactic=MitreTactic.CREDENTIAL_ACCESS,
                        src_ip=src_ip,
                        description=f"Possible HTTP Brute Force: {count} login endpoint requests.",
                        evidence={"request_count": count}
                    )
                )
        self._src_counts.clear()
        return alerts
