"""
Full CaptureService implementation (Milestone 3).

Data Setup:  CaptureConfig injected via constructor; no hardcoded values.
Data Input:  Raw packets from a live NIC (Scapy AsyncSniffer) or PCAP file.
Data Output: PacketSummary objects via registered callback; CaptureStatus snapshots.

Live capture runs in a background thread via Scapy's AsyncSniffer. A rate
limiter guards the callback and a protocol filter drops unwanted traffic before
downstream delivery. PCAP replay lives in `pcap_replay`.
"""

import threading
from collections.abc import Callable

from scapy.packet import Packet  # type: ignore[import-untyped]
from scapy.sendrecv import AsyncSniffer  # type: ignore[import-untyped]

from ..shared.base import BaseService
from ..shared.config_models import CaptureConfig
from .filters import apply_protocol_filter, validate_bpf_filter
from .models import CaptureStatus, ProtocolFilterConfig
from .pcap_replay import PcapReplayMixin
from .rate_limiter import CaptureRateLimiter

# Type alias for packet consumer callbacks
PacketCallback = Callable[[Packet], None]


class CaptureService(PcapReplayMixin, BaseService):
    """
    Manages live packet capture and PCAP file replay.

    Consumers register a callback via set_packet_callback(); every admitted
    packet is passed to the callback after rate-limit and protocol filtering.
    """

    def __init__(self, config: CaptureConfig) -> None:
        """
        Initialise the capture service.

        Args:
            config: Validated CaptureConfig (interface, BPF filter, rate limit, …).
        """
        super().__init__(service_name="CaptureService")
        self._config = config
        self._sniffer: AsyncSniffer | None = None
        self._stop_event = threading.Event()
        self._callback: PacketCallback | None = None
        self._rate_limiter = CaptureRateLimiter(rate_pps=config.max_packets_per_second)
        self._protocol_filter = ProtocolFilterConfig(
            allow_list=list(config.protocol_allow_list),
            deny_list=list(config.protocol_deny_list),
        )
        self._packets_captured = 0
        self._packets_dropped_filter = 0
        self._is_pcap_mode = False
        self._captured_packets: list[Packet] = []
        self._lock = threading.Lock()

    def set_packet_callback(self, callback: PacketCallback) -> None:
        """Register a callback invoked for every admitted packet."""
        self._callback = callback

    def set_bpf_filter(self, expr: str) -> None:
        """
        Update the BPF filter expression (validated before applying).

        Args:
            expr: BPF filter string (e.g. 'tcp port 80'). Empty = no filter.

        Raises:
            ValueError: If the expression fails BPF compilation.
        """
        if not validate_bpf_filter(expr):
            raise ValueError(f"Invalid BPF filter expression: '{expr}'")
        self._config = self._config.model_copy(update={"bpf_filter": expr})

    def set_protocol_filter(self, allow: list[str], deny: list[str]) -> None:
        """
        Replace the protocol allow/deny lists at runtime.

        Args:
            allow: Protocols to allow (empty = allow all).
            deny:  Protocols to always drop.
        """
        self._protocol_filter = ProtocolFilterConfig(allow_list=allow, deny_list=deny)

    def _do_start(self) -> None:
        """Start the AsyncSniffer on the configured interface."""
        self._stop_event.clear()
        bpf = self._config.bpf_filter or None
        self._sniffer = AsyncSniffer(
            iface=self._config.interface,
            filter=bpf,
            snaplen=self._config.snaplen,
            promisc=self._config.promiscuous_mode,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        self._is_pcap_mode = False
        self.logger.info("Live capture started on interface '%s'.", self._config.interface)

    def _do_stop(self) -> None:
        """Stop the AsyncSniffer and signal the stop event."""
        self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        self.logger.info("CaptureService stopped. Packets captured: %d", self._packets_captured)

    def _do_health_check(self) -> dict:  # type: ignore[type-arg]
        return self.get_status().model_dump()

    def get_status(self) -> CaptureStatus:
        """Return a snapshot of the current capture state."""
        with self._lock:
            return CaptureStatus(
                interface=self._config.interface,
                is_running=self._running,
                is_pcap_mode=self._is_pcap_mode,
                packets_captured=self._packets_captured,
                packets_dropped_rate_limit=self._rate_limiter.packets_dropped,
                packets_dropped_filter=self._packets_dropped_filter,
                bpf_filter=self._config.bpf_filter,
                pcap_output_dir=self._config.pcap_output_dir,
            )

    def _on_packet(self, pkt: Packet) -> None:
        """Callback invoked by AsyncSniffer for each captured packet."""
        if not self._rate_limiter.acquire():
            return  # backpressure: drop silently

        if not apply_protocol_filter(pkt, self._protocol_filter):
            with self._lock:
                self._packets_dropped_filter += 1
            return

        with self._lock:
            self._packets_captured += 1
            self._captured_packets.append(pkt)

        if self._callback is not None:
            self._callback(pkt)
