"""Parser fixtures: a started PacketParser ready to accept packets."""

import pytest

from network_defender.parser.parser import PacketParser


@pytest.fixture()
def started_parser() -> PacketParser:
    """A PacketParser that has been started, as the pipeline would leave it."""
    parser = PacketParser()
    parser.start()
    return parser
