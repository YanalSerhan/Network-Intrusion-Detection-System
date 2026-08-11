"""
WebSocket endpoint for the live dashboard feed.

Data Setup:  Broadcaster held on app.state, shared by every connection.
Data Input:  Client connections; heartbeat messages from the browser.
Data Output: Snapshot and delta frames.

Authentication runs before the handshake is accepted. Browsers cannot set
custom headers on a WebSocket, so when a key is configured it is read from the
`token` query parameter — the standard workaround. Rejecting before `accept()`
means an unauthorised client never receives a single frame.
"""

from typing import Annotated

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ...constants import ENV_API_KEY
from ...shared.secrets import get_secret
from ..live.broadcaster import LiveBroadcaster

router = APIRouter(tags=["live"])

#: Close code for policy violation (RFC 6455 §7.4.1).
WS_POLICY_VIOLATION = 1008


def _is_authorised(token: str | None) -> bool:
    """Return True if the connection may proceed."""
    expected = get_secret(ENV_API_KEY)
    return not expected or token == expected


@router.websocket("/ws/live")
async def live_feed(
    websocket: WebSocket,
    token: Annotated[str | None, Query(description="API key, when one is configured.")] = None,
) -> None:
    """
    Stream alerts and counters to a dashboard client.

    On connect the client receives a snapshot so the UI is populated
    immediately; afterwards it receives only deltas.

    Args:
        websocket: The client connection.
        token:     API key, required only when one is configured.
    """
    if not _is_authorised(token):
        await websocket.close(code=WS_POLICY_VIOLATION, reason="Invalid or missing API key.")
        return

    broadcaster: LiveBroadcaster = websocket.app.state.broadcaster
    await broadcaster.connections.connect(websocket)

    try:
        for frame in broadcaster.snapshot():
            await websocket.send_json(frame)

        # The client sends nothing meaningful, but receiving keeps the
        # connection accounted for and gives a clean disconnect signal
        # instead of relying on a send failing later.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # noqa: BLE001 - never let one socket raise into the server
        broadcaster.logger.info("Live client dropped: %s", exc)
    finally:
        await broadcaster.connections.disconnect(websocket)
