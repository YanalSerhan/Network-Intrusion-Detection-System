"""
PCAP file I/O helpers.

Data Setup:  No external configuration; accepts file paths at call time.
Data Input:  File system paths to .pcap / .pcapng files, or a packet list.
Data Output: Iterator of Scapy packet objects (read); .pcap file on disk (write).
"""

from collections.abc import Iterator
from pathlib import Path

from scapy.packet import Packet  # type: ignore[import-untyped]
from scapy.utils import rdpcap, wrpcap  # type: ignore[import-untyped]


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """
    Read all packets from a PCAP file and yield them one by one.

    This is a lazy iterator — the entire file is loaded by Scapy's rdpcap
    and then yielded packet-by-packet to allow downstream consumers to
    apply backpressure via the rate limiter without buffering everything.

    Args:
        path: Absolute or relative path to a .pcap / .pcapng file.

    Yields:
        Scapy Packet objects in capture order.

    Raises:
        FileNotFoundError: If the path does not point to an existing file.
        Scapy exceptions: Propagated on corrupt/unsupported file format.
    """
    resolved = Path(path)
    if not resolved.is_file():
        raise FileNotFoundError(f"PCAP file not found: {resolved}")

    packets = rdpcap(str(resolved))
    yield from packets


def write_pcap(packets: list[Packet], path: str | Path) -> None:
    """
    Write a list of Scapy packets to a PCAP file.

    Parent directories are created automatically if they do not exist.

    Args:
        packets: List of Scapy packet objects to save.
        path:    Destination file path (.pcap extension recommended).

    Raises:
        OSError: If the directory cannot be created or the file cannot be written.
    """
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(resolved), packets)


def append_pcap(packet: Packet, path: str | Path) -> None:
    """
    Append a single packet to an existing PCAP file (or create it).

    Uses Scapy's wrpcap with append=True to avoid loading the entire file
    into memory when incrementally saving a live capture session.

    Args:
        packet: Single Scapy packet to append.
        path:   Destination file path.
    """
    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(resolved), [packet], append=True)
