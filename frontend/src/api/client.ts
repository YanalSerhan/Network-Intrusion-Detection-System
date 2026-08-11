/**
 * Typed REST client.
 *
 * One place that knows about URLs, the API key header and the error envelope,
 * so components deal in typed data and a thrown `ApiError` rather than raw
 * fetch responses.
 */
import type {
  AlertDetail,
  AlertStatus,
  AlertSummary,
  ApiErrorBody,
  Page,
  PacketView,
  RuleView,
  Severity,
  StatisticsPoint,
  StatisticsSummary,
} from "./types";

const BASE = "/api/v1";

/** A failed request, carrying the server's stable error code. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * The API key, if the deployment configured one.
 *
 * Read from a meta tag so the same bundle works in every environment; baking
 * it in at build time would mean rebuilding to rotate a key.
 */
function apiKey(): string | null {
  return document.querySelector<HTMLMetaElement>('meta[name="nd-api-key"]')?.content || null;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = apiKey();
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {}),
      ...init.headers,
    },
  });

  if (!response.ok) {
    // Every failure uses the same envelope, but a proxy or gateway can return
    // HTML, so fall back rather than throwing a JSON parse error.
    let code = "http_error";
    let message = `Request failed with status ${response.status}.`;
    try {
      const body = (await response.json()) as ApiErrorBody;
      code = body.error?.code ?? code;
      message = body.error?.message ?? message;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, code, message);
  }

  return (await response.json()) as T;
}

function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export interface AlertQuery {
  severity?: Severity | "";
  status?: AlertStatus | "";
  hours?: number | "";
  limit?: number;
  offset?: number;
}

export const api = {
  listAlerts: (params: AlertQuery = {}) =>
    request<Page<AlertSummary>>(`/alerts${query({ ...params })}`),

  getAlert: (alertId: string) => request<AlertDetail>(`/alerts/${alertId}`),

  getAlertPackets: (alertId: string) => request<PacketView[]>(`/alerts/${alertId}/packets`),

  setAlertStatus: (alertId: string, status: AlertStatus) =>
    request<AlertDetail>(`/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  enrichAlert: (alertId: string) =>
    request<AlertDetail>(`/alerts/${alertId}/enrich`, { method: "POST" }),

  getStatistics: () => request<StatisticsSummary>("/statistics"),

  getStatisticsSeries: (hours = 24) =>
    request<StatisticsPoint[]>(`/statistics/timeseries${query({ hours })}`),

  listRules: () => request<Page<RuleView>>("/rules"),

  setRuleEnabled: (name: string, enabled: boolean) =>
    request<RuleView>(`/rules/${encodeURIComponent(name)}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),

  reloadRules: () =>
    request<{ status: string; loaded_rules_count: number }>("/rules/reload", {
      method: "POST",
    }),
};

export { apiKey };
