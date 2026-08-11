/**
 * WebSocket live feed with automatic reconnection.
 *
 * Reconnect uses exponential backoff with jitter. Fixed-interval retries from
 * every open dashboard would arrive in lockstep and hammer the API at the
 * exact moment it is recovering; jitter spreads them out.
 *
 * Alerts are capped in state: an alert storm streams thousands of records, and
 * keeping them all would grow memory without bound and make React re-render an
 * ever-longer list. The full history is a REST query away.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { apiKey } from "../api/client";
import type { AlertSummary, LiveFrame } from "../api/types";

export type ConnectionState = "connecting" | "open" | "closed";

/** Most recent alerts held in memory; older ones live in the database. */
const MAX_LIVE_ALERTS = 100;
const BASE_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;

export interface LiveStats {
  totalAlerts: number;
  alertsBySeverity: Record<string, number>;
  packetsRetained: number;
  topTalkers: Record<string, number>;
  protocolDistribution: Record<string, number>;
}

function socketUrl(): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const key = apiKey();
  const token = key ? `?token=${encodeURIComponent(key)}` : "";
  return `${protocol}//${window.location.host}/ws/live${token}`;
}

export function useLiveFeed(): {
  alerts: AlertSummary[];
  stats: LiveStats | null;
  state: ConnectionState;
} {
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [stats, setStats] = useState<LiveStats | null>(null);
  const [state, setState] = useState<ConnectionState>("connecting");

  const socketRef = useRef<WebSocket | null>(null);
  const attemptRef = useRef(0);
  const timerRef = useRef<number | undefined>(undefined);
  const closedRef = useRef(false);

  const handleFrame = useCallback((frame: LiveFrame) => {
    if (frame.type === "alerts") {
      setAlerts((current) => {
        // `initial` is the snapshot sent on connect: replace rather than
        // prepend, otherwise a reconnect duplicates everything on screen.
        const merged = frame.initial
          ? [...frame.alerts].reverse()
          : [...[...frame.alerts].reverse(), ...current];
        return merged.slice(0, MAX_LIVE_ALERTS);
      });
    } else if (frame.type === "stats") {
      setStats({
        totalAlerts: frame.total_alerts,
        alertsBySeverity: frame.alerts_by_severity,
        packetsRetained: frame.packets_retained,
        topTalkers: frame.top_talkers,
        protocolDistribution: frame.protocol_distribution,
      });
    }
  }, []);

  const connect = useCallback(() => {
    if (closedRef.current) return;
    setState("connecting");

    const socket = new WebSocket(socketUrl());
    socketRef.current = socket;

    socket.onopen = () => {
      attemptRef.current = 0;
      setState("open");
    };

    socket.onmessage = (event) => {
      try {
        handleFrame(JSON.parse(event.data as string) as LiveFrame);
      } catch {
        // A malformed frame is not worth tearing the connection down for.
      }
    };

    socket.onclose = () => {
      setState("closed");
      if (closedRef.current) return;

      const attempt = Math.min(attemptRef.current++, 5);
      const backoff = Math.min(BASE_RETRY_MS * 2 ** attempt, MAX_RETRY_MS);
      const jitter = Math.random() * backoff * 0.3;
      timerRef.current = window.setTimeout(connect, backoff + jitter);
    };

    socket.onerror = () => socket.close();
  }, [handleFrame]);

  useEffect(() => {
    closedRef.current = false;
    connect();

    return () => {
      closedRef.current = true;
      window.clearTimeout(timerRef.current);
      socketRef.current?.close();
    };
  }, [connect]);

  return { alerts, stats, state };
}
