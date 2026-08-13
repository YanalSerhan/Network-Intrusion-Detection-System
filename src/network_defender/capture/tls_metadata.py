"""
TLS ClientHello metadata extraction.

Data Setup:  No configuration; pure byte parsing.
Data Input:  A Scapy packet whose TCP payload begins with a TLS record.
Data Output: (SNI hostname, offered cipher suite IDs), either may be None.

Only the unencrypted ClientHello is read. No key material is touched and no
decryption is attempted: the SNI and the cipher list are sent in the clear, and
they are what makes an encrypted flow attributable to a destination at all.

The record is walked by hand rather than with Scapy's TLS layer, which is an
optional dependency and raises on the truncated or malformed handshakes that a
sensor sees constantly. Any parse failure returns (None, None): missing
metadata degrades an alert, an exception would drop the packet.
"""

from scapy.layers.inet import TCP
from scapy.packet import Packet

from ..constants import TlsHandshakeType

#: TLS record content-type marking a handshake message.
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
#: `server_name` extension type within the ClientHello.
_TLS_SNI_TYPE = 0x00

#: Record header (5) + handshake type (1) + handshake length (3).
_HANDSHAKE_BODY_OFFSET = 9
_CLIENT_VERSION_BYTES = 2
_CLIENT_RANDOM_BYTES = 32
_MIN_RECORD_BYTES = 6


def extract_tls_metadata(packet: Packet) -> tuple[str | None, list[int] | None]:
    """
    Parse a TLS ClientHello for its SNI hostname and offered cipher suites.

    Args:
        packet: Scapy packet with a TCP layer carrying a TLS record.

    Returns:
        Tuple of (sni_hostname | None, cipher_suite_ids | None).
    """
    try:
        raw = bytes(packet[TCP].payload)
        if len(raw) < _MIN_RECORD_BYTES or raw[0] != _TLS_CONTENT_TYPE_HANDSHAKE:
            return None, None
        if raw[5] != TlsHandshakeType.CLIENT_HELLO:
            return None, None

        offset = _HANDSHAKE_BODY_OFFSET + _CLIENT_VERSION_BYTES + _CLIENT_RANDOM_BYTES
        offset += 1 + raw[offset]  # session ID
        cipher_len = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        ciphers = [
            int.from_bytes(raw[offset + i : offset + i + 2], "big") for i in range(0, cipher_len, 2)
        ]
        offset += cipher_len
        offset += 1 + raw[offset]  # compression methods

        if offset + 2 > len(raw):
            return None, ciphers
        ext_total = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        return _find_sni(raw, offset, offset + ext_total), ciphers
    except Exception:  # noqa: BLE001 - malformed handshakes must not drop packets
        return None, None


def _find_sni(raw: bytes, offset: int, end: int) -> str | None:
    """
    Scan the ClientHello extension block for the server_name value.

    Args:
        raw:    The full TLS record bytes.
        offset: Start of the extension list.
        end:    One past the last extension byte.

    Returns:
        The requested hostname, or None if no SNI extension is present.
    """
    while offset + 4 <= end:
        ext_type = int.from_bytes(raw[offset : offset + 2], "big")
        ext_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        offset += 4
        if ext_type == _TLS_SNI_TYPE and offset + ext_len <= end:
            # SNI list: list_len(2) + name_type(1) + name_len(2) + name
            name_len = int.from_bytes(raw[offset + 3 : offset + 5], "big")
            start = offset + 5
            return raw[start : start + name_len].decode("utf-8", "replace")
        offset += ext_len
    return None
