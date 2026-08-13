"""
The flat field set a ParsedPacket is projected onto.

Data Setup:  None.
Data Input:  A ParsedPacket.
Data Output: A dict of its scalar fields, plus its protocol sections.

Two consumers need the same projection and neither can share the other's
target: the database maps a packet onto an ORM row, the API maps it onto a
response model. Written out twice, adding a field meant remembering both — and
the one that got forgotten would drop the field silently rather than fail,
because both targets tolerate a missing optional.

Protocol sections are collected into one nested dict rather than spread across
sparse per-protocol fields, which is also how the database stores them: most
of every row would otherwise be NULL, and each new protocol would need a
migration.
"""

from typing import Any

from .models import ParsedPacket

#: The optional protocol-specific sections a packet may carry.
PROTOCOL_SECTIONS = ("tcp_flags", "dns", "http", "tls")


def protocol_sections(packet: ParsedPacket) -> dict[str, Any]:
    """
    Return the packet's populated protocol sections, JSON-ready.

    Args:
        packet: The packet to project.

    Returns:
        Section name to its dumped fields, omitting sections not present.
    """
    return {
        section: getattr(packet, section).model_dump(mode="json")
        for section in PROTOCOL_SECTIONS
        if getattr(packet, section) is not None
    }


def scalar_fields(packet: ParsedPacket) -> dict[str, Any]:
    """
    Return the packet's flat fields, common to every representation of it.

    Args:
        packet: The packet to project.

    Returns:
        Field name to value, ready to splat into a record or response model.
    """
    return {
        "timestamp": packet.timestamp,
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "protocol": packet.protocol,
        "length": packet.length,
        "raw_summary": packet.raw_summary,
    }
