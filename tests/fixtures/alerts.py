"""Fixtures for the alert pipeline: a raw detection, a packet and a rule."""

import pytest

from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import Rule

from .builders import make_detection, make_packet, make_rule
from .constants import INTERNAL_IP, INTERNAL_PEER_IP


@pytest.fixture()
def detection() -> DetectionAlert:
    """A representative heuristic detection from the port scan detector."""
    return make_detection(src_ip=INTERNAL_IP)


@pytest.fixture()
def packet() -> ParsedPacket:
    """A representative parsed TCP packet between two internal hosts."""
    return make_packet(src_ip=INTERNAL_IP, dst_ip=INTERNAL_PEER_IP, tcp_flags=None)


@pytest.fixture()
def rule() -> Rule:
    """A representative YAML-loaded rule."""
    return make_rule()
