"""Unit tests for BaseService and mixins."""

from typing import Any

import pytest

from network_defender.shared.base import BaseService, LoggableMixin, ValidatableMixin


# ---------------------------------------------------------------------------
# Concrete stubs for testing abstract base classes
# ---------------------------------------------------------------------------


class ConcreteService(BaseService):
    """Minimal concrete subclass for testing BaseService behaviour."""

    def _do_start(self) -> None:
        pass

    def _do_stop(self) -> None:
        pass

    def _do_health_check(self) -> dict[str, Any]:
        return {"detail": "ok"}


class ConcreteValidator(ValidatableMixin):
    """Minimal concrete subclass for testing ValidatableMixin."""

    def validate(self, data: Any) -> bool:
        return isinstance(data, str) and len(data) > 0


# ---------------------------------------------------------------------------
# LoggableMixin tests
# ---------------------------------------------------------------------------


def test_loggable_mixin_provides_named_logger() -> None:
    """LoggableMixin.logger should return a Logger named after the class."""
    import logging

    class MyComponent(LoggableMixin):
        pass

    comp = MyComponent()
    assert comp.logger.name == "network_defender.MyComponent"
    assert isinstance(comp.logger, logging.Logger)


# ---------------------------------------------------------------------------
# ValidatableMixin tests
# ---------------------------------------------------------------------------


def test_validatable_mixin_valid_data() -> None:
    v = ConcreteValidator()
    assert v.validate("hello") is True


def test_validatable_mixin_invalid_data() -> None:
    v = ConcreteValidator()
    assert v.validate("") is False
    assert v.validate(42) is False


# ---------------------------------------------------------------------------
# BaseService Template Method tests
# ---------------------------------------------------------------------------


def test_base_service_starts_and_sets_running_flag() -> None:
    svc = ConcreteService(service_name="test")
    assert svc.is_running is False
    svc.start()
    assert svc.is_running is True


def test_base_service_stops_and_clears_running_flag() -> None:
    svc = ConcreteService(service_name="test")
    svc.start()
    svc.stop()
    assert svc.is_running is False


def test_base_service_health_check_includes_running_and_service_name() -> None:
    svc = ConcreteService(service_name="test")
    svc.start()
    health = svc.health_check()
    assert health["running"] is True
    assert health["service"] == "test"
    assert health["detail"] == "ok"
