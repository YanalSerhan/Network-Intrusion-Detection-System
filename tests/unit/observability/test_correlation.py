"""Tests for correlation-ID storage, scoping and propagation across threads."""

import threading

from network_defender.observability import (
    bind_correlation_id,
    correlation_scope,
    get_correlation_id,
    new_correlation_id,
    set_correlation_id,
)
from tests.fixtures.logs import CapturingHandler, log


def test_correlation_id_appears_in_records(handler: CapturingHandler) -> None:
    with correlation_scope("fixed-id"):
        log(handler).info("inside")
    log(handler).info("outside")

    assert handler.records[0]["correlation_id"] == "fixed-id"
    assert "correlation_id" not in handler.records[1]


def test_scope_restores_the_previous_id() -> None:
    """Nesting must hand the outer ID back, not clear it."""
    with correlation_scope("outer"):
        with correlation_scope("inner"):
            assert get_correlation_id() == "inner"
        assert get_correlation_id() == "outer"
    assert get_correlation_id() is None


def test_scope_mints_an_id_when_none_is_given() -> None:
    with correlation_scope() as correlation_id:
        assert correlation_id
        assert get_correlation_id() == correlation_id


def test_ids_are_unique_and_short() -> None:
    ids = {new_correlation_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(value) == 16 for value in ids)


def test_set_and_clear() -> None:
    set_correlation_id("manual")
    assert get_correlation_id() == "manual"
    set_correlation_id(None)
    assert get_correlation_id() is None


def test_context_does_not_cross_threads_without_binding() -> None:
    """The reason bind_correlation_id exists at all."""
    seen: list[str | None] = []

    with correlation_scope("request-id"):
        thread = threading.Thread(target=lambda: seen.append(get_correlation_id()))
        thread.start()
        thread.join()

    assert seen == [None]


def test_bind_carries_the_id_across_a_thread() -> None:
    seen: list[str | None] = []

    with correlation_scope("request-id"):
        work = bind_correlation_id(lambda: seen.append(get_correlation_id()))

    thread = threading.Thread(target=work)
    thread.start()
    thread.join()

    assert seen == ["request-id"]
