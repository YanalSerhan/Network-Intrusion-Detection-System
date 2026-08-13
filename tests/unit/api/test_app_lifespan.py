"""
Tests for application startup and shutdown.

The lifespan handler is the one part of the API the injected-SDK tests never
run: they hand `create_app` an SDK precisely so the handler is skipped. That
leaves the code a real deployment executes first — and the code that decides
whether a crashed process releases its database handles — untested.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from network_defender.api.app import create_app


def test_startup_builds_a_readonly_sdk_and_shutdown_releases_it() -> None:
    """The API reads what the sensor wrote; it must never open a capture."""
    sdk = MagicMock()

    with (
        patch("network_defender.api.app.NetworkDefenderSDK.create", return_value=sdk) as create,
        patch("network_defender.api.app.LiveBroadcaster") as broadcaster_cls,
        patch("network_defender.api.app.setup_logging") as setup,
    ):
        broadcaster = broadcaster_cls.return_value
        broadcaster.stop = AsyncMock()
        with TestClient(create_app()):
            pass

    create.assert_called_once_with()
    setup.assert_called_once()
    sdk.start_readonly.assert_called_once_with()
    sdk.start.assert_not_called()
    sdk.stop_readonly.assert_called_once_with()
    broadcaster.start.assert_called_once_with()
    broadcaster.stop.assert_awaited_once_with()


def test_the_sdk_is_reachable_from_application_state() -> None:
    """Route dependencies resolve the SDK off app.state, not a module global."""
    sdk = MagicMock()

    with (
        patch("network_defender.api.app.NetworkDefenderSDK.create", return_value=sdk),
        patch("network_defender.api.app.LiveBroadcaster") as broadcaster_cls,
        patch("network_defender.api.app.setup_logging"),
    ):
        broadcaster_cls.return_value.stop = AsyncMock()
        app = create_app()
        with TestClient(app):
            assert app.state.sdk is sdk


def test_an_injected_sdk_bypasses_startup_entirely() -> None:
    """Tests and embedders own the lifecycle when they supply their own SDK."""
    injected = MagicMock()

    with patch("network_defender.api.app.NetworkDefenderSDK.create") as create:
        app = create_app(sdk=injected)

    create.assert_not_called()
    assert app.state.sdk is injected
