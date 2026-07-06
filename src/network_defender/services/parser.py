"""
Parser service re-export shim.

The full implementation lives in network_defender.parser.parser.
This module re-exports PacketParser so that imports from
``network_defender.services.parser`` continue to work unchanged.

Data Setup:  See network_defender.parser.parser.PacketParser.
Data Input:  See network_defender.parser.parser.PacketParser.
Data Output: See network_defender.parser.parser.PacketParser.
"""

from ..parser.parser import PacketParser

__all__ = ["PacketParser"]
