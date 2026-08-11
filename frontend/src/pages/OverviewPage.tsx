/**
 * Overview: live traffic, top talkers, protocol mix and recent alerts.
 *
 * Counters and the alert list come from the shared WebSocket, so this page
 * updates without polling. The throughput chart comes from persisted
 * snapshots, which is the only source that survives a sensor restart.
 */
import { BarList } from "../components/BarList";
import { AlertTable } from "../components/AlertTable";
import { Card } from "../components/Card";
import { PpsChart } from "../components/PpsChart";
import { StatTile } from "../components/StatTile";
import { Empty, ErrorState, Loading } from "../components/States";
import { api } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useLive } from "../live/context";
import styles from "./OverviewPage.module.css";

const TOP_N = 6;

function toItems(counts: Record<string, number>, limit = TOP_N) {
  return Object.entries(counts)
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

export function OverviewPage() {
  const { alerts, stats } = useLive();
  const series = useApi(() => api.getStatisticsSeries(24), []);

  const bySeverity = stats?.alertsBySeverity ?? {};
  const destinations = alerts.reduce<Record<string, number>>((acc, alert) => {
    if (alert.dst_ip) acc[alert.dst_ip] = (acc[alert.dst_ip] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <h1 className={styles.heading}>Overview</h1>

      <div className={styles.tiles}>
        <StatTile label="Total alerts" value={(stats?.totalAlerts ?? 0).toLocaleString()} />
        <StatTile label="Critical" value={bySeverity.critical ?? 0} tone="critical" />
        <StatTile label="High" value={bySeverity.high ?? 0} tone="high" />
        <StatTile
          label="Packets retained"
          value={(stats?.packetsRetained ?? 0).toLocaleString()}
        />
      </div>

      <div className={styles.chartRow}>
        <Card title="Packets per second">
          {series.loading && <Loading label="Loading throughput" />}
          {series.error && <ErrorState message={series.error} onRetry={series.refresh} />}
          {series.data && <PpsChart points={series.data} />}
        </Card>

        <Card title="Top sources">
          <BarList
            items={toItems(stats?.topTalkers ?? {})}
            emptyLabel="No alert sources recorded yet."
          />
        </Card>
      </div>

      <div className={styles.chartRow}>
        <Card title="Recent alerts">
          {alerts.length === 0 ? (
            <Empty message="No alerts yet. New detections appear here as they happen." />
          ) : (
            <AlertTable alerts={alerts.slice(0, 8)} caption="Most recent detections" />
          )}
        </Card>

        <div className={styles.stack}>
          <Card title="Top destinations">
            <BarList items={toItems(destinations)} emptyLabel="No destinations recorded yet." />
          </Card>
          <Card title="Protocols">
            <BarList
              items={toItems(stats?.protocolDistribution ?? {})}
              emptyLabel="No protocol data yet."
            />
          </Card>
        </div>
      </div>
    </>
  );
}
