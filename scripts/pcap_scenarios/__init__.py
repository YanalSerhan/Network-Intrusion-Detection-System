"""
The synthetic traffic scenarios end-to-end tests replay.

Data Setup:  Nothing — each scenario is a pure function of the constants in
             `common`, seeded so successive runs produce identical bytes.
Data Input:  None.
Data Output: A list of Scapy packets, timestamped as if captured live.

Each scenario is built to cross exactly one detector's threshold in
config/detectors.json and to stay clear of every other detector's. That is
what makes the end-to-end assertions specific: an unexpected extra alert means
a detector fired on traffic that is not its subject — a false positive worth
failing the build over.
"""

from .baseline import benign
from .command_control import beaconing, dns_tunneling, suspicious_port
from .credentials import http_brute_force, ssh_brute_force
from .exfiltration import data_exfiltration, lateral_movement
from .floods import arp_spoofing, icmp_flood, syn_flood, udp_flood
from .reconnaissance import tcp_port_scan

#: Scenario name -> builder. The name becomes the .pcap filename, and the
#: end-to-end suite parametrises over these keys.
SCENARIOS = {
    "tcp_port_scan": tcp_port_scan,
    "syn_flood": syn_flood,
    "udp_flood": udp_flood,
    "icmp_flood": icmp_flood,
    "arp_spoofing": arp_spoofing,
    "dns_tunneling": dns_tunneling,
    "ssh_brute_force": ssh_brute_force,
    "http_brute_force": http_brute_force,
    "beaconing": beaconing,
    "suspicious_port": suspicious_port,
    "data_exfiltration": data_exfiltration,
    "lateral_movement": lateral_movement,
    "benign": benign,
}

__all__ = ["SCENARIOS"]
