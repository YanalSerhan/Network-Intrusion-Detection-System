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

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .counting_endpoints import SourceCountingDetector

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


class SshBruteForceDetector(SourceCountingDetector[SshBruteForceConfig]):
    """
    Detects repeated SSH connection attempts from one source.

    Counts connection *openings* — bare SYNs — rather than packets. An
    established SSH session carries thousands of packets, so counting those
    would report every legitimate long-running session as an attack.
    """

    evidence_key = "connection_count"
    severity = Severity.HIGH
    tactic = MitreTactic.CREDENTIAL_ACCESS

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SshBruteForceDetector"

    @property
    def threshold(self) -> int:
        """Connection attempts per window at or above which to alert."""
        return self.config.connection_count_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for a new connection to the configured SSH port."""
        return bool(
            packet.protocol == Protocol.TCP
            and packet.dst_port == self.config.ssh_port
            and packet.tcp_flags
            and packet.tcp_flags.syn
            and not packet.tcp_flags.ack
        )

    def describe(self, count: int) -> str:
        """Describe the attempt burst for the analyst reading the alert."""
        return f"Possible SSH Brute Force: {count} connection attempts."


class HttpBruteForceConfig(DetectorConfig):
    """Tunables for the HTTP brute force detector."""

    time_window_seconds: int = Field(default=60)
    connection_count_threshold: int = Field(default=20)


class HttpBruteForceDetector(SourceCountingDetector[HttpBruteForceConfig]):
    """
    Detects repeated requests to authentication endpoints from one source.

    Only requests whose path looks like a login endpoint count. A web server
    serves hundreds of requests a minute to one visitor without anything being
    wrong; it is the concentration on the login path that is the signal.

    Its threshold is higher than SSH's because a single page load can issue
    several requests to the same path, and because clear-text HTTP auth is
    less immediately valuable to an attacker than a shell.
    """

    evidence_key = "request_count"
    severity = Severity.MEDIUM
    tactic = MitreTactic.CREDENTIAL_ACCESS

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "HttpBruteForceDetector"

    @property
    def threshold(self) -> int:
        """Auth requests per window at or above which to alert."""
        return self.config.connection_count_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for an HTTP request whose path looks like a login."""
        if not (packet.protocol == Protocol.HTTP and packet.http and packet.http.path):
            return False
        path = packet.http.path.lower()
        return any(marker in path for marker in AUTH_PATH_MARKERS)

    def describe(self, count: int) -> str:
        """Describe the request burst for the analyst reading the alert."""
        return f"Possible HTTP Brute Force: {count} login endpoint requests."
