"""
Base classes and mixins for Network Defender components.

Design contract (applied to every core component):
  Data Input:  Described in the class-level docstring.
  Data Output: Described in the class-level docstring.
  Data Setup:  Described in __init__ docstring (dependencies injected, never hard-coded).

These base classes enforce:
  - Single Responsibility Principle via focused mixins.
  - Template Method pattern for structured, repeatable workflows.
  - Dependency injection for all external collaborators.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any


class LoggableMixin:
    """
    Mixin: provides a pre-configured logger scoped to the concrete class name.

    Single responsibility: logging setup only.
    Can be independently tested by asserting `self.logger` is a Logger instance.
    """

    @property
    def logger(self) -> logging.Logger:
        """Return a logger named after the concrete class."""
        return logging.getLogger(f"network_defender.{type(self).__name__}")


class ValidatableMixin(ABC):
    """
    Mixin: enforces a validate() contract on any component that processes input data.

    Single responsibility: input validation only.
    Concrete classes must implement validate() and call it before processing.
    """

    @abstractmethod
    def validate(self, data: Any) -> bool:
        """
        Validate incoming data before processing.

        Args:
            data: The data item to validate (type varies by subclass).

        Returns:
            True if the data is valid and should be processed; False otherwise.
        """


class BaseService(LoggableMixin, ABC):
    """
    Abstract base for all domain services (capture, parsing, detection, alerting).

    Template Method pattern: subclasses implement _do_start / _do_stop /
    _do_health_check; the public start() / stop() / health_check() methods
    add shared cross-cutting behaviour (logging, error handling) around them.

    Data Setup:  All dependencies are injected via __init__ parameters.
    Data Input:  Specific to each subclass.
    Data Output: Specific to each subclass.
    """

    def __init__(self, service_name: str) -> None:
        """
        Initialise the base service.

        Args:
            service_name: Human-readable name used in logs and health responses.
        """
        self._service_name = service_name
        self._running = False

    # ------------------------------------------------------------------
    # Template Method: public surface
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the service, delegating to _do_start after logging."""
        self.logger.info("Starting service", extra={"service": self._service_name})
        self._do_start()
        self._running = True
        self.logger.info("Service started", extra={"service": self._service_name})

    def stop(self) -> None:
        """Stop the service, delegating to _do_stop after logging."""
        self.logger.info("Stopping service", extra={"service": self._service_name})
        self._do_stop()
        self._running = False
        self.logger.info("Service stopped", extra={"service": self._service_name})

    def health_check(self) -> dict[str, Any]:
        """Return a health-check dict describing current service status."""
        status = self._do_health_check()
        status["running"] = self._running
        status["service"] = self._service_name
        return status

    @property
    def is_running(self) -> bool:
        """True if the service has been started and not yet stopped."""
        return self._running

    # ------------------------------------------------------------------
    # Template Method: subclass hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def _do_start(self) -> None:
        """Subclass-specific startup logic."""

    @abstractmethod
    def _do_stop(self) -> None:
        """Subclass-specific shutdown logic."""

    @abstractmethod
    def _do_health_check(self) -> dict[str, Any]:
        """Return a dict of service-specific health metrics."""
