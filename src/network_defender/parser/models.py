"""
Pydantic models for the packet parser layer.

Data Setup:  No external dependencies; constructed from extracted packet fields.
Data Input:  Typed field values produced by extractor functions in extractors.py.
Data Output: Normalised, validated ParsedPacket consumed by the Detection Engine
             and any downstream service that needs structured packet data.
"""

from datetime import datetime

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field


class TcpFlags(BaseModel):
    """
    Named boolean representation of the TCP control-bit field.

    Each flag maps directly to the corresponding RFC 793 bit position.
    Populated only when the packet carries a TCP layer.
    """

    syn: bool = Field(default=False, description="SYN — synchronise sequence numbers.")
    ack: bool = Field(default=False, description="ACK — acknowledgement field is significant.")
    fin: bool = Field(default=False, description="FIN — no more data from sender.")
    rst: bool = Field(default=False, description="RST — reset the connection.")
    psh: bool = Field(default=False, description="PSH — push buffered data to receiver.")
    urg: bool = Field(default=False, description="URG — urgent pointer field is significant.")


class DnsFields(BaseModel):
    """
    DNS-layer fields extracted from the first query record (DNSQR).

    Populated only when the packet is identified as DNS.
    """

    query_name: str | None = Field(default=None, description="Queried domain name.")
    record_type: int | None = Field(
        default=None, description="DNS record type integer (e.g. 1=A, 28=AAAA)."
    )


class HttpFields(BaseModel):
    """
    HTTP/1.x request fields extracted from the HTTPRequest Scapy layer.

    Populated only for clear-text HTTP traffic; HTTPS is handled by TlsFields.
    """

    method: str | None = Field(default=None, description="HTTP method (GET, POST, …).")
    path: str | None = Field(default=None, description="Request-URI path.")
    host: str | None = Field(default=None, description="HTTP Host header value.")
    user_agent: str | None = Field(default=None, description="User-Agent header value.")


class TlsFields(BaseModel):
    """
    TLS ClientHello metadata — no key material, no decryption.

    Populated when a TCP payload begins with a TLS handshake record (0x16)
    containing a ClientHello message.
    """

    sni: str | None = Field(default=None, description="Server Name Indication hostname.")
    cipher_suites: list[int] | None = Field(
        default=None, description="Offered cipher suite IDs from ClientHello."
    )


class ParsedPacket(BaseModel):
    """
    Normalised, protocol-agnostic representation of a single network packet.

    Produced by PacketParser.parse() and consumed by the Detection Engine.
    All optional fields are None when the corresponding protocol layer is absent.

    Data Setup:  Assembled by PacketParser; no external I/O required.
    Data Input:  Field values from extractor functions in extractors.py.
    Data Output: Immutable snapshot for detectors, alerting, and the dashboard.
    """

    timestamp: datetime = Field(description="Capture timestamp (UTC).")
    src_ip: str | None = Field(default=None, description="Source IP address (IPv4 or IPv6).")
    dst_ip: str | None = Field(default=None, description="Destination IP address.")
    src_port: int | None = Field(default=None, description="Source transport port.")
    dst_port: int | None = Field(default=None, description="Destination transport port.")
    protocol: str = Field(description="Highest-layer protocol string (from Protocol enum).")
    length: int = Field(ge=0, description="Total packet length in bytes.")
    tcp_flags: TcpFlags | None = Field(default=None, description="TCP flags (TCP packets only).")
    dns: DnsFields | None = Field(default=None, description="DNS query fields (DNS packets only).")
    http: HttpFields | None = Field(default=None, description="HTTP request fields (HTTP only).")
    tls: TlsFields | None = Field(default=None, description="TLS ClientHello metadata (TLS only).")
    raw_summary: str = Field(description="One-line human-readable packet description.")
