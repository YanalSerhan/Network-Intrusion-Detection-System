"""
Pydantic models for the capture layer.

Data Setup:  No external dependencies; constructed from raw packet data.
Data Input:  Parsed packet attributes (protocol strings, IP addresses, ports).
Data Output: Typed, validated snapshots consumed by the SDK and downstream services.
"""

from datetime import datetime

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class PacketSummary(BaseModel):
    """
    Human-readable summary of a single captured packet.

    Produced by summarise_packet() in packet_summary.py and emitted to any
    downstream consumer (detection engine, dashboard WebSocket, PCAP writer).
    """

    timestamp: datetime = Field(description="Capture timestamp (UTC).")
    protocol: str = Field(description="Highest-layer protocol detected (e.g. 'tcp', 'dns').")
    src_ip: str | None = Field(default=None, description="Source IP address.")
    dst_ip: str | None = Field(default=None, description="Destination IP address.")
    src_port: int | None = Field(default=None, description="Source transport port.")
    dst_port: int | None = Field(default=None, description="Destination transport port.")
    length: int = Field(ge=0, description="Total packet length in bytes.")
    summary: str = Field(description="One-line human-readable description.")
    # Optional protocol-specific extras
    dns_query: str | None = Field(default=None, description="DNS query name (if DNS).")
    http_method: str | None = Field(default=None, description="HTTP method (if HTTP).")
    http_host: str | None = Field(default=None, description="HTTP Host header (if HTTP).")
    http_path: str | None = Field(default=None, description="HTTP request path (if HTTP).")
    http_user_agent: str | None = Field(default=None, description="HTTP User-Agent (if HTTP).")
    tls_sni: str | None = Field(default=None, description="TLS SNI hostname (if TLS).")
    tls_cipher_suites: list[int] | None = Field(
        default=None, description="TLS cipher suite IDs from ClientHello (if TLS)."
    )


class CaptureStatus(BaseModel):
    """
    Snapshot of the CaptureService's current operational state.

    Returned by CaptureService.get_status() and surfaced via the SDK's
    get_capture_status() method for the /health endpoint.
    """

    interface: str = Field(description="Active capture interface name.")
    is_running: bool = Field(description="True while a capture session is active.")
    is_pcap_mode: bool = Field(description="True when replaying from a PCAP file.")
    packets_captured: int = Field(ge=0, description="Total packets captured this session.")
    packets_dropped_rate_limit: int = Field(
        ge=0, description="Packets dropped by the rate limiter."
    )
    packets_dropped_filter: int = Field(
        ge=0, description="Packets dropped by protocol/BPF filter."
    )
    bpf_filter: str = Field(description="Current BPF filter expression (empty = none).")
    pcap_output_dir: str = Field(description="Directory where PCAP files are saved.")


class ProtocolFilterConfig(BaseModel):
    """
    Protocol-level allow/deny lists injected into the capture filter.

    Semantics:
      - If allow_list is non-empty, only listed protocols pass.
      - deny_list always takes precedence over allow_list.
    """

    allow_list: list[str] = Field(default_factory=list)
    deny_list: list[str] = Field(default_factory=list)
