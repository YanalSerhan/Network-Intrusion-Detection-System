/**
 * Types mirroring the REST contract in docs/openapi.json.
 *
 * Hand-written rather than generated: the surface is small, and a generated
 * file would be a large unreviewable diff on every API change. If this grows,
 * switch to generating from the committed OpenAPI spec.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "acknowledged" | "resolved" | "false_positive";
export type AlertSource = "detector" | "rule_engine";
export type ThreatVerdict = "unknown" | "clean" | "suspicious" | "malicious";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const ALERT_STATUSES: AlertStatus[] = [
  "new",
  "acknowledged",
  "resolved",
  "false_positive",
];

export interface PageMeta {
  limit: number;
  offset: number;
  count: number;
  total: number | null;
  has_more: boolean;
}

export interface AlertSummary {
  alert_id: string;
  timestamp: string;
  last_seen: string;
  severity: Severity;
  source: AlertSource;
  rule_triggered: string;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: string | null;
  confidence: number;
  tactic: string | null;
  status: AlertStatus;
  occurrences: number;
}

export interface GeoLocation {
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
}

export interface AsnInfo {
  asn: string | null;
  organisation: string | null;
  isp: string | null;
}

export interface WhoisInfo {
  network_name: string | null;
  cidr: string | null;
  registrant: string | null;
  abuse_email: string | null;
}

export interface ThreatIntel {
  ip: string;
  verdict: ThreatVerdict;
  reputation_score: number | null;
  geo: GeoLocation | null;
  asn: AsnInfo | null;
  whois: WhoisInfo | null;
  providers_queried: string[];
  providers_failed: string[];
}

export interface AlertDetail extends AlertSummary {
  src_port: number | null;
  dst_port: number | null;
  technique: string | null;
  packet_summary: string;
  description: string;
  evidence: Record<string, unknown>;
  threat_intel: ThreatIntel | null;
}

export interface PacketView {
  timestamp: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  raw_summary: string;
  fields: Record<string, unknown>;
}

export interface RuleView {
  name: string;
  severity: Severity;
  enabled: boolean;
  window: number;
  threshold: number;
  group_by: string;
  conditions: Array<Record<string, unknown>>;
  source_path: string | null;
}

export interface TopTalker {
  ip: string;
  alert_count: number;
}

export interface StatisticsSummary {
  total_alerts: number;
  alerts_by_severity: Record<string, number>;
  total_packets_retained: number;
  top_talkers: TopTalker[];
  protocol_distribution: Record<string, number>;
}

export interface StatisticsPoint {
  captured_at: string;
  total_packets: number;
  total_alerts: number;
  packets_per_second: number;
  alerts_by_severity: Record<string, number>;
}

export interface Page<T> {
  items: T[];
  meta: PageMeta;
}

export interface ApiErrorBody {
  error: { code: string; message: string; detail?: unknown };
}

/** Frames pushed over the live WebSocket. */
export type LiveFrame =
  | { type: "alerts"; sent_at: string; initial: boolean; alerts: AlertSummary[] }
  | {
      type: "stats";
      sent_at: string;
      total_alerts: number;
      alerts_by_severity: Record<string, number>;
      packets_retained: number;
      top_talkers: Record<string, number>;
      protocol_distribution: Record<string, number>;
    }
  | { type: "error"; sent_at: string; message: string };
