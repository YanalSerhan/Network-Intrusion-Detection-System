"""
WebSocket connection registry.

Data Setup:  No configuration; one registry per broadcaster.
Data Input:  Connect/disconnect events and frames to fan out.
Data Output: Frames delivered to every healthy client.

Broadcast is deliberately fault-tolerant. A client that has closed its laptop
lid, lost its network, or simply stopped reading will raise on send; if that
propagated, one dead browser would abort delivery to everyone else and take
down the poll loop with it. Failed sends therefore drop that client and
continue.
"""

import asyncio
from typing import Any

from starlette.websockets import WebSocket

from ...shared.base import LoggableMixin


class ConnectionManager(LoggableMixin):
    """Tracks connected dashboard clients and fans frames out to them."""

    def __init__(self) -> None:
        """Initialise an empty registry."""
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def count(self) -> int:
        """Number of currently connected clients."""
        return len(self._clients)

    @property
    def is_empty(self) -> bool:
        """True when no client is connected."""
        return not self._clients

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept a connection and register it.

        Args:
            websocket: The client socket.
        """
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """
        Remove a connection from the registry.

        Args:
            websocket: The client socket.
        """
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, frame: dict[str, Any]) -> int:
        """
        Send a frame to every connected client.

        Args:
            frame: The JSON-serialisable payload.

        Returns:
            Number of clients that received it.
        """
        async with self._lock:
            targets = list(self._clients)

        delivered = 0
        dead: list[WebSocket] = []
        for client in targets:
            try:
                await client.send_json(frame)
                delivered += 1
            except Exception:  # noqa: BLE001 - one dead client must not stop the rest
                dead.append(client)

        if dead:
            async with self._lock:
                for client in dead:
                    self._clients.discard(client)
            self.logger.info("Dropped %d unreachable dashboard client(s).", len(dead))

        return delivered
