"""
Capture-service fixtures.

Data Setup:  A CaptureConfig pointed at a nominal interface with rate limiting
             and protocol filtering switched off.
Data Input:  None.
Data Output: A CaptureConfig, or a CaptureService built from it.

Rate limiting is off rather than generous so a slow CI runner cannot turn a
behavioural test into a timing test; the limiter has its own suite.
"""

import pytest

from network_defender.capture.service import CaptureService
from network_defender.shared.config_models import CaptureConfig


@pytest.fixture()
def capture_config() -> CaptureConfig:
    """Capture configuration with every optional restriction disabled."""
    return CaptureConfig(
        interface="eth0",
        bpf_filter="",
        snaplen=65535,
        promiscuous_mode=False,
        buffer_size=1024,
        max_packets_per_second=0,
        protocol_allow_list=[],
        protocol_deny_list=[],
        pcap_output_dir="captures/",
    )


@pytest.fixture()
def service(capture_config: CaptureConfig) -> CaptureService:
    """A capture service over the permissive test configuration."""
    return CaptureService(config=capture_config)
