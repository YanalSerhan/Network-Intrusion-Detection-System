"""
Capture service re-export shim.

The full implementation lives in network_defender.capture.service.
This module re-exports CaptureService so that existing imports from
``network_defender.services.capture`` continue to work unchanged.

Data Setup:  See network_defender.capture.service.CaptureService.
Data Input:  See network_defender.capture.service.CaptureService.
Data Output: See network_defender.capture.service.CaptureService.
"""

from ..capture.service import CaptureService

__all__ = ["CaptureService"]
