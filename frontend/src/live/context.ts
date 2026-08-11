/**
 * The live-feed context and its consumer hook.
 *
 * Kept out of LiveProvider.tsx so that file exports only a component: React
 * Fast Refresh silently stops working for a module that mixes component and
 * non-component exports, which makes editing the provider require a full
 * reload during development.
 */
import { createContext, useContext } from "react";

import type { AlertSummary } from "../api/types";
import type { ConnectionState, LiveStats } from "../hooks/useLiveFeed";

export interface LiveContextValue {
  alerts: AlertSummary[];
  stats: LiveStats | null;
  state: ConnectionState;
}

export const LiveContext = createContext<LiveContextValue>({
  alerts: [],
  stats: null,
  state: "connecting",
});

/** Read the shared live feed. Safe outside a provider — returns empty state. */
export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}
