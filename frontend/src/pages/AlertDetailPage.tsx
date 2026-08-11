/**
 * Alert detail: why it fired, what it maps to, and the evidence behind it.
 *
 * Triage actions live here rather than in the list, because deciding an alert
 * is a false positive should follow reading it, not a guess from one table row.
 */
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api } from "../api/client";
import { ALERT_STATUSES, type AlertStatus } from "../api/types";
import { Card } from "../components/Card";
import { PacketViewer } from "../components/PacketViewer";
import { SeverityBadge } from "../components/SeverityBadge";
import { Empty, ErrorState, Loading } from "../components/States";
import { ThreatIntelPanel } from "../components/ThreatIntelPanel";
import { useApi } from "../hooks/useApi";
import styles from "./AlertDetailPage.module.css";

const MITRE_URL = "https://attack.mitre.org";

export function AlertDetailPage() {
  const { alertId = "" } = useParams();
  const [busy, setBusy] = useState(false);

  const alert = useApi(() => api.getAlert(alertId), [alertId]);
  const packets = useApi(() => api.getAlertPackets(alertId), [alertId]);

  async function changeStatus(status: AlertStatus) {
    setBusy(true);
    try {
      await api.setAlertStatus(alertId, status);
      alert.refresh();
    } finally {
      setBusy(false);
    }
  }

  async function enrich() {
    setBusy(true);
    try {
      await api.enrichAlert(alertId);
      alert.refresh();
    } finally {
      setBusy(false);
    }
  }

  if (alert.loading) return <Loading label="Loading alert" />;
  if (alert.error) return <ErrorState message={alert.error} onRetry={alert.refresh} />;
  if (!alert.data) return <Empty message="Alert not found." />;

  const data = alert.data;

  return (
    <>
      <nav className={styles.breadcrumb} aria-label="Breadcrumb">
        <Link to="/alerts">Alerts</Link>
        <span aria-hidden="true"> / </span>
        <span>{data.rule_triggered}</span>
      </nav>

      <header className={styles.header}>
        <SeverityBadge severity={data.severity} />
        <h1 className={styles.heading}>{data.rule_triggered}</h1>
      </header>
      <p className={styles.description}>{data.description}</p>

      <div className={styles.grid}>
        <Card title="Detection">
          <dl className={styles.definitions}>
            <div>
              <dt>Source</dt>
              <dd className={styles.mono}>
                {data.src_ip ?? "—"}
                {data.src_port ? `:${data.src_port}` : ""}
              </dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd className={styles.mono}>
                {data.dst_ip ?? "—"}
                {data.dst_port ? `:${data.dst_port}` : ""}
              </dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>{data.protocol ?? "—"}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{(data.confidence * 100).toFixed(0)}%</dd>
            </div>
            <div>
              <dt>Occurrences</dt>
              <dd>{data.occurrences}</dd>
            </div>
            <div>
              <dt>First seen</dt>
              <dd>{new Date(data.timestamp).toLocaleString()}</dd>
            </div>
            <div>
              <dt>Last seen</dt>
              <dd>{new Date(data.last_seen).toLocaleString()}</dd>
            </div>
            <div>
              <dt>Raised by</dt>
              <dd>{data.source === "rule_engine" ? "Rule engine" : "Detector"}</dd>
            </div>
          </dl>
        </Card>

        <div className={styles.stack}>
          <Card title="MITRE ATT&CK">
            {data.tactic || data.technique ? (
              <ul className={styles.mitre}>
                {data.tactic && (
                  <li>
                    <span className={styles.mitreLabel}>Tactic</span>
                    <a href={`${MITRE_URL}/tactics/${data.tactic}/`}>{data.tactic}</a>
                  </li>
                )}
                {data.technique && (
                  <li>
                    <span className={styles.mitreLabel}>Technique</span>
                    <a href={`${MITRE_URL}/techniques/${data.technique.replace(".", "/")}/`}>
                      {data.technique}
                    </a>
                  </li>
                )}
              </ul>
            ) : (
              <Empty message="No ATT&CK mapping for this detector." />
            )}
          </Card>

          <Card title="Triage">
            <div className={styles.actions}>
              <label className={styles.statusField}>
                <span className={styles.mitreLabel}>Status</span>
                <select
                  value={data.status}
                  disabled={busy}
                  onChange={(event) => changeStatus(event.target.value as AlertStatus)}
                >
                  {ALERT_STATUSES.map((value) => (
                    <option key={value} value={value}>
                      {value.replace("_", " ")}
                    </option>
                  ))}
                </select>
              </label>
              <button type="button" onClick={enrich} disabled={busy}>
                {busy ? "Working…" : "Enrich now"}
              </button>
            </div>
          </Card>
        </div>
      </div>

      <Card title="Threat intelligence">
        <ThreatIntelPanel intel={data.threat_intel} />
      </Card>

      <div className={styles.spaced}>
        <Card title="Evidence">
          <details className={styles.details} open>
            <summary>Detector evidence</summary>
            <pre className={styles.json}>{JSON.stringify(data.evidence, null, 2)}</pre>
          </details>

          {packets.loading && <Loading label="Loading packets" />}
          {packets.error && <ErrorState message={packets.error} onRetry={packets.refresh} />}
          {packets.data?.length === 0 && (
            <Empty message="No packet evidence was retained for this alert." />
          )}
          {packets.data?.map((packet, index) => (
            <PacketViewer key={`${packet.timestamp}-${index}`} packet={packet} index={index} />
          ))}
        </Card>
      </div>
    </>
  );
}
