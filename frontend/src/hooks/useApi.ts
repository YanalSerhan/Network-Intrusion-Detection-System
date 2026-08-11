/**
 * Data-fetching hook with loading, error and refresh handling.
 *
 * Deliberately small — a query library would be more capable, but the
 * dashboard has a handful of endpoints and the live feed already handles
 * freshness, so the dependency would not earn its weight.
 *
 * The abort-on-unmount guard is the part that matters: without it, navigating
 * away mid-request sets state on an unmounted component, and a slow response
 * can overwrite the results of a newer one.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "../api/client";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refresh: () => void;
}

export function useApi<T>(fetcher: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  // Held in a ref so a stale in-flight request can tell it has been superseded.
  const requestId = useRef(0);

  useEffect(() => {
    const id = ++requestId.current;
    let active = true;

    setLoading(true);
    fetcher()
      .then((result) => {
        if (!active || id !== requestId.current) return;
        setData(result);
        setError(null);
      })
      .catch((caught: unknown) => {
        if (!active || id !== requestId.current) return;
        setError(
          caught instanceof ApiError ? caught.message : "Could not reach the Network Defender API.",
        );
      })
      .finally(() => {
        if (active && id === requestId.current) setLoading(false);
      });

    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const refresh = useCallback(() => setNonce((value) => value + 1), []);

  return { data, error, loading, refresh };
}
