/**
 * Hook tests.
 *
 * Focused on the failure behaviour that is hard to notice by clicking around:
 * theme persistence, error surfacing, and the live feed's reconnect and
 * snapshot-versus-delta handling.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import type { AlertSummary } from "../api/types";
import { useApi } from "./useApi";
import { useLiveFeed } from "./useLiveFeed";
import { useTheme } from "./useTheme";

function alert(id: string): AlertSummary {
  return {
    alert_id: id,
    timestamp: "2026-08-11T10:00:00Z",
    last_seen: "2026-08-11T10:00:00Z",
    severity: "high",
    source: "detector",
    rule_triggered: `Rule-${id}`,
    src_ip: "45.155.205.233",
    dst_ip: null,
    protocol: "tcp",
    confidence: 0.8,
    tactic: null,
    status: "new",
    occurrences: 1,
  };
}

describe("useTheme", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.dataset.theme = "dark";
  });

  it("toggles and persists the choice", () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current.theme).toBe("dark");

    act(() => result.current.toggleTheme());

    expect(result.current.theme).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("nd-theme")).toBe("light");
  });
});

describe("useApi", () => {
  it("exposes data once resolved", async () => {
    const { result } = renderHook(() => useApi(() => Promise.resolve({ ok: true }), []));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toEqual({ ok: true });
  });

  it("surfaces the server's message for an ApiError", async () => {
    const { result } = renderHook(() =>
      useApi(() => Promise.reject(new ApiError(404, "not_found", "No alert with that id.")), []),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe("No alert with that id.");
  });

  it("gives a generic message when the API is unreachable", async () => {
    const { result } = renderHook(() =>
      useApi(() => Promise.reject(new TypeError("Failed to fetch")), []),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toMatch(/Could not reach/);
  });
});

/** Minimal WebSocket stand-in so the hook can be driven deterministically. */
class MockSocket {
  static last: MockSocket | null = null;
  static created = 0;

  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  closed = false;

  constructor(readonly url: string) {
    MockSocket.last = this;
    MockSocket.created += 1;
  }

  close() {
    this.closed = true;
    this.onclose?.();
  }

  emit(frame: unknown) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}

describe("useLiveFeed", () => {
  beforeEach(() => {
    MockSocket.created = 0;
    MockSocket.last = null;
    vi.stubGlobal("WebSocket", MockSocket);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("reports the connection state", async () => {
    const { result } = renderHook(() => useLiveFeed());
    expect(result.current.state).toBe("connecting");

    act(() => MockSocket.last!.onopen?.());
    expect(result.current.state).toBe("open");
  });

  it("replaces the list on a snapshot and prepends deltas", () => {
    const { result } = renderHook(() => useLiveFeed());
    act(() => MockSocket.last!.onopen?.());

    act(() =>
      MockSocket.last!.emit({
        type: "alerts",
        sent_at: "",
        initial: true,
        alerts: [alert("a"), alert("b")],
      }),
    );
    expect(result.current.alerts.map((item) => item.alert_id)).toEqual(["b", "a"]);

    act(() =>
      MockSocket.last!.emit({ type: "alerts", sent_at: "", initial: false, alerts: [alert("c")] }),
    );
    expect(result.current.alerts.map((item) => item.alert_id)).toEqual(["c", "b", "a"]);
  });

  it("caps stored alerts so a storm cannot grow memory without bound", () => {
    const { result } = renderHook(() => useLiveFeed());
    act(() => MockSocket.last!.onopen?.());

    for (let batch = 0; batch < 4; batch += 1) {
      act(() =>
        MockSocket.last!.emit({
          type: "alerts",
          sent_at: "",
          initial: false,
          alerts: Array.from({ length: 40 }, (_, index) => alert(`${batch}-${index}`)),
        }),
      );
    }

    expect(result.current.alerts).toHaveLength(100);
  });

  it("stores counters from a stats frame", () => {
    const { result } = renderHook(() => useLiveFeed());
    act(() => MockSocket.last!.onopen?.());

    act(() =>
      MockSocket.last!.emit({
        type: "stats",
        sent_at: "",
        total_alerts: 12,
        alerts_by_severity: { high: 3 },
        packets_retained: 40,
        top_talkers: { "1.1.1.1": 5 },
        protocol_distribution: { tcp: 9 },
      }),
    );

    expect(result.current.stats?.totalAlerts).toBe(12);
    expect(result.current.stats?.topTalkers).toEqual({ "1.1.1.1": 5 });
  });

  it("ignores a malformed frame rather than tearing down the connection", () => {
    const { result } = renderHook(() => useLiveFeed());
    act(() => MockSocket.last!.onopen?.());

    act(() => MockSocket.last!.onmessage?.({ data: "not json" }));
    expect(result.current.state).toBe("open");
  });

  it("closes the socket on unmount and does not reconnect", () => {
    const { unmount } = renderHook(() => useLiveFeed());
    const socket = MockSocket.last!;

    unmount();

    expect(socket.closed).toBe(true);
    expect(MockSocket.created).toBe(1);
  });
});
