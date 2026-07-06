"""
Network Defender — public package surface.

External consumers should import from here or from the SDK:
    from network_defender import NetworkDefenderSDK
    from network_defender import __version__
"""

from .sdk.sdk import NetworkDefenderSDK
from .shared.version import __version__

__all__ = ["NetworkDefenderSDK", "__version__"]
