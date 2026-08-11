/**
 * Alert table.
 *
 * A real <table> with <th scope="col">, not a grid of divs: screen readers
 * announce the column name with each cell, which is what makes a dense table
 * navigable without sight.
 *
 * Rows are links rather than click handlers on <tr>, so middle-click and
 * "open in new tab" work and keyboard focus lands somewhere meaningful.
 */
import { Link } from "react-router-dom";

import type { AlertSummary } from "../api/types";
import { SeverityBadge } from "./SeverityBadge";
import styles from "./AlertTable.module.css";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function AlertTable({
  alerts,
  caption,
}: {
  alerts: AlertSummary[];
  caption: string;
}) {
  return (
    <div className={styles.scroll}>
      <table className={styles.table}>
        <caption className={styles.caption}>{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Time</th>
            <th scope="col">Detector or rule</th>
            <th scope="col">Source</th>
            <th scope="col">Destination</th>
            <th scope="col" className={styles.numeric}>
              Confidence
            </th>
            <th scope="col" className={styles.numeric}>
              Count
            </th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.alert_id}>
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className={styles.time}>{formatTime(alert.timestamp)}</td>
              <td>
                <Link className={styles.link} to={`/alerts/${alert.alert_id}`}>
                  {alert.rule_triggered}
                </Link>
              </td>
              <td className={styles.mono}>{alert.src_ip ?? "—"}</td>
              <td className={styles.mono}>{alert.dst_ip ?? "—"}</td>
              <td className={styles.numeric}>{alert.confidence.toFixed(2)}</td>
              <td className={styles.numeric}>{alert.occurrences}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
