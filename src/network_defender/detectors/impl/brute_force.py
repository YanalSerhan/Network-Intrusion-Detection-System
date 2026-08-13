"""
Credential brute force detectors: SSH and HTTP login endpoints.

Data Setup:  A per-source attempt counter, reset every evaluation window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per source that made too many attempts.

Both count toward the *source*, the opposite of the flood detectors: guessing
credentials is one attacker working through a list, and the attacker is what
an analyst needs named. A flood's attacker is usually a botnet and its victim
is the useful identity; a brute force's attacker is the useful identity.

Neither sees whether a login succeeded. SSH is encrypted from the second
packet, and an HTTP response body is not something a passive sensor should be
parsing. What both measure is attempt *rate*, which is what distinguishes
someone guessing from someone who mistyped their password.
"""

from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket

#: Path fragments that mark a request as an authentication attempt. Matched as
#: substrings against a lowercased path, so `/api/v2/user/login` counts.
AUTH_PATH_MARKERS = ("login", "auth", "signin", "admin")


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
    Detects repeated SSH connection attempts from one source.

    Counts connection *openings* — bare SYNs — rather than packets. An
    established SSH session carries thousands of packets, so counting those
    would report every legitimate long-running session as an attack.
    """

    def __init__(self, config: SshBruteForceConfig) -> None:
        """Initialise with the validated attempt threshold and SSH port."""
        super().__init__(config)
        self._src_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SshBruteForceDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Count a new connection to the SSH port against its source."""
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
        """Emit an alert per guessing source, then clear the window."""
        alerts = []
        for src_ip, count in self._src_counts.items():
            if count >= self.config.connection_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.CREDENTIAL_ACCESS,
                        src_ip=src_ip,
                        description=f"Possible SSH Brute Force: {count} connection attempts.",
                        evidence={"connection_count": count},
                    )
                )
        self._src_counts.clear()
        return alerts


class HttpBruteForceConfig(DetectorConfig):
    """Tunables for the HTTP brute force detector."""

    time_window_seconds: int = Field(default=60)
    connection_count_threshold: int = Field(default=20)


class HttpBruteForceDetector(BaseDetector[HttpBruteForceConfig]):
    """
    Detects repeated requests to authentication endpoints from one source.

    Only requests whose path looks like a login endpoint count. A web server
    serves hundreds of requests a minute to one visitor without anything being
    wrong; it is the concentration on the login path that is the signal.

    Its threshold is higher than SSH's because a single page load can issue
    several requests to the same path, and because clear-text HTTP auth is
    less immediately valuable to an attacker than a shell.
    """

    def __init__(self, config: HttpBruteForceConfig) -> None:
        """Initialise with the validated request threshold."""
        super().__init__(config)
        self._src_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "HttpBruteForceDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Count the request against its source if it targets an auth path."""
        if packet.protocol == Protocol.HTTP and packet.http and packet.http.path and packet.src_ip:
            path = packet.http.path.lower()
            if any(marker in path for marker in AUTH_PATH_MARKERS):
                self._src_counts[packet.src_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        """Emit an alert per guessing source, then clear the window."""
        alerts = []
        for src_ip, count in self._src_counts.items():
            if count >= self.config.connection_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.MEDIUM,
                        tactic=MitreTactic.CREDENTIAL_ACCESS,
                        src_ip=src_ip,
                        description=f"Possible HTTP Brute Force: {count} login endpoint requests.",
                        evidence={"request_count": count},
                    )
                )
        self._src_counts.clear()
        return alerts
