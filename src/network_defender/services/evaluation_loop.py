"""
Periodic evaluation trigger for stateful detectors.

Data Setup:  Interval and callback injected via __init__.
Data Input:  Wall-clock time.
Data Output: Repeated invocations of the supplied evaluation callback.

Why this exists
---------------
Stateful detectors accumulate counters in `ingest()` and only emit alerts when
`evaluate()` is called. Without a periodic trigger nothing ever calls it: the
counters grow forever and no alert is ever raised. This loop closes that gap
and doubles as the window flush, since detectors reset their state on evaluate.
"""

import threading
from collections.abc import Callable

from ..shared.base import LoggableMixin


class PeriodicEvaluator(LoggableMixin):
    """
    Calls a callback on a fixed interval from a daemon background thread.

    Usage:
        evaluator = PeriodicEvaluator(5.0, detection_service.evaluate_detectors)
        evaluator.start()
        ...
        evaluator.stop()
    """

    def __init__(self, interval_seconds: float, callback: Callable[[], object]) -> None:
        """
        Initialise the evaluator.

        Args:
            interval_seconds: Seconds between callback invocations. Must be > 0.
            callback:         Zero-argument callable invoked on each tick.

        Raises:
            ValueError: If interval_seconds is not positive.
        """
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero.")
        self._interval = interval_seconds
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        """True while the background thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the background thread. A second call is a no-op."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="detector-evaluation-loop", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        """
        Signal the loop to stop and wait briefly for the thread to exit.

        Args:
            timeout: Seconds to wait for the thread; defaults to one interval.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout if timeout is not None else self._interval)
            self._thread = None

    def run_once(self) -> None:
        """
        Invoke the callback a single time, swallowing any exception.

        Exposed so callers can force an evaluation (e.g. at shutdown, to flush
        pending detector state) without waiting for the next tick.
        """
        try:
            self._callback()
        except Exception as exc:  # noqa: BLE001 - a bad detector must not kill the loop
            self.logger.error("Detector evaluation failed", extra={"error": str(exc)})

    def _run(self) -> None:
        """Thread body: evaluate on each interval until stopped."""
        while not self._stop_event.wait(self._interval):
            self.run_once()
