"""
Volume and fan-out cases: data leaving, hosts spreading, and their honest twins.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for exfiltration and lateral movement.

The exfiltration detector is explicit that it has no opinion on destination —
"a backup to cloud storage and a staged archive leaving for an attacker look
identical on the wire". This corpus takes that at its word and includes the
backup, so the precision figure reflects the design decision rather than
assuming it away.

Byte volume is built from offload-sized segments rather than MTU-sized frames.
Any capture taken on a host with segmentation offload enabled looks like this,
and it keeps a hundred-megabyte case to a couple of thousand packets.
"""

from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import (
    BACKUP_SERVER,
    CLOUD_STORAGE,
    COMPROMISED_HOST,
    EDGE_SERVER,
    EPHEMERAL_BASE,
    MONITOR,
    WORKSTATION,
    internal_range,
)
from .timing import spread

FAMILY = "exfiltration"

#: A generic segmentation-offload segment, just under the 65 535-octet ceiling
#: the IP total-length field imposes.
SEGMENT_BYTES = 60_000
MEGABYTE = 1_000_000

HTTPS_PORT = 443
SMB_PORT = 445
SNMP_PORT = 161


def _bulk_transfer(src: str, dst: str, megabytes: int, seconds: float) -> list[Any]:
    """One source pushing a volume of data to one destination."""
    payload = b"\x00" * SEGMENT_BYTES
    count = (megabytes * MEGABYTE) // SEGMENT_BYTES
    return spread(
        [
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=EPHEMERAL_BASE, dport=HTTPS_PORT, flags="PA")
            / payload
            for _ in range(count)
        ],
        seconds,
    )


def _fan_out(src: str, targets: list[str], port: int, udp: bool, seconds: float) -> list[Any]:
    """One source reaching many internal peers on one service port."""
    transport = UDP(dport=port) if udp else TCP(dport=port, flags="S")
    return spread(
        [Ether() / IP(src=src, dst=target) / transport for target in targets],
        seconds,
    )


def cases() -> list[Case]:
    """Return every volume and fan-out case, positive and negative."""
    return [
        attack(
            "exfil_30mb",
            {"DataExfiltrationDetector"},
            lambda: _bulk_transfer(COMPROMISED_HOST, CLOUD_STORAGE, 30, 60.0),
            "A staged archive under the shipped 50 MB threshold — the volume "
            "an attacker picks precisely because it is under it.",
            FAMILY,
        ),
        attack(
            "exfil_120mb",
            {"DataExfiltrationDetector"},
            lambda: _bulk_transfer(COMPROMISED_HOST, CLOUD_STORAGE, 120, 60.0),
            "A bulk copy well over the shipped threshold, present so the recall "
            "curve has a point that survives raising it.",
            FAMILY,
        ),
        attack(
            "lateral_smb_15",
            {"LateralMovementDetector"},
            lambda: _fan_out(COMPROMISED_HOST, internal_range(15), SMB_PORT, False, 60.0),
            "Fifteen internal peers over SMB, under the shipped threshold of "
            "twenty.",
            FAMILY,
        ),
        attack(
            "lateral_smb_40",
            {"LateralMovementDetector"},
            lambda: _fan_out(COMPROMISED_HOST, internal_range(40), SMB_PORT, False, 30.0),
            "A compromised host enumerating the segment: forty internal peers in "
            "thirty seconds, twice the shipped threshold.",
            FAMILY,
        ),
        benign(
            "backup_upload_60mb",
            lambda: _bulk_transfer(WORKSTATION, BACKUP_SERVER, 60, 60.0),
            "A nightly backup to an internal server. Over the shipped "
            "threshold, and the detector is documented as not caring where "
            "the bytes went.",
            FAMILY,
        ),
        benign(
            "video_call_25mb",
            lambda: _bulk_transfer(WORKSTATION, CLOUD_STORAGE, 25, 60.0),
            "An hour of video conferencing, under the threshold but within "
            "reach of a lowered one.",
            FAMILY,
        ),
        benign(
            "snmp_poll_18_hosts",
            lambda: _fan_out(MONITOR, internal_range(18), SNMP_PORT, True, 60.0),
            "A monitoring server polling eighteen devices. Fan-out is its "
            "job, and it is the negative that bounds the lateral threshold.",
            FAMILY,
        ),
        benign(
            "fileserver_clients_30",
            lambda: [
                packet
                for client in internal_range(30, start=150)
                for packet in _fan_out(client, [EDGE_SERVER], SMB_PORT, False, 5.0)
            ],
            "Thirty clients reaching one file server: high internal traffic, "
            "but one peer each. A control proving the detector measures "
            "fan-out rather than volume.",
            FAMILY,
        ),
    ]
