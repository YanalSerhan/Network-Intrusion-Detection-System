/**
 * Shares one live connection across the whole app.
 *
 * Without this, every component calling `useLiveFeed` would open its own
 * WebSocket: the header badge and the overview page alone would mean two
 * connections per browser tab, each receiving identical frames. The provider
 * opens exactly one and distributes the result.
 */
import type { ReactNode } from "react";

import { useLiveFeed } from "../hooks/useLiveFeed";
import { LiveContext } from "./context";

export function LiveProvider({ children }: { children: ReactNode }) {
  const value = useLiveFeed();
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}
