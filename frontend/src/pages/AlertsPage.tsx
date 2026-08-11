/**
 * Searchable, filterable alert log.
 *
 * Filtering and pagination are **server-side**. The PRD calls out alert storms
 * of thousands of alerts; fetching them all to filter in the browser would
 * freeze the tab and defeat the database indices built for exactly these
 * queries. The client only ever holds one page.
 *
 * The free-text box filters the current page only, and says so — pretending to
 * search everything while only seeing 100 rows would be worse than not
 * offering it.
 */
import { useState } from "react";

import { api } from "../api/client";
import { ALERT_STATUSES, SEVERITIES, type AlertStatus, type Severity } from "../api/types";
import { AlertTable } from "../components/AlertTable";
import { Card } from "../components/Card";
import { Empty, ErrorState, Loading } from "../components/States";
import { useApi } from "../hooks/useApi";
import styles from "./AlertsPage.module.css";

const PAGE_SIZE = 50;
const WINDOWS = [
  { value: "", label: "Any time" },
  { value: "1", label: "Last hour" },
  { value: "24", label: "Last 24 hours" },
  { value: "168", label: "Last 7 days" },
];

export function AlertsPage() {
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<AlertStatus | "">("");
  const [hours, setHours] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const offset = page * PAGE_SIZE;
  const alerts = useApi(
    () =>
      api.listAlerts({
        severity: severity || undefined,
        status: status || undefined,
        hours: hours ? Number(hours) : undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    [severity, status, hours, offset],
  );

  // Changing a filter must reset to the first page, or a user on page 4 of
  // "high" alerts sees an empty page 4 of "critical" ones and assumes there
  // are none.
  function updateFilter<T>(setter: (value: T) => void) {
    return (value: T) => {
      setter(value);
      setPage(0);
    };
  }

  const needle = search.trim().toLowerCase();
  const visible = (alerts.data?.items ?? []).filter((alert) =>
    needle
      ? [alert.rule_triggered, alert.src_ip, alert.dst_ip, alert.protocol]
          .filter(Boolean)
          .some((field) => String(field).toLowerCase().includes(needle))
      : true,
  );

  return (
    <>
      <h1 className={styles.heading}>Alerts</h1>

      <Card title="Filters">
        <div className={styles.filters}>
          <label className={styles.field}>
            <span className={styles.label}>Search this page</span>
            <input
              type="search"
              value={search}
              placeholder="Detector, IP or protocol"
              onChange={(event) => setSearch(event.target.value)}
            />
          </label>

          <label className={styles.field}>
            <span className={styles.label}>Severity</span>
            <select
              value={severity}
              onChange={(event) => updateFilter(setSeverity)(event.target.value as Severity | "")}
            >
              <option value="">All severities</option>
              {SEVERITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>

          <label className={styles.field}>
            <span className={styles.label}>Status</span>
            <select
              value={status}
              onChange={(event) =>
                updateFilter(setStatus)(event.target.value as AlertStatus | "")
              }
            >
              <option value="">All statuses</option>
              {ALERT_STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value.replace("_", " ")}
                </option>
              ))}
            </select>
          </label>

          <label className={styles.field}>
            <span className={styles.label}>Time range</span>
            <select value={hours} onChange={(event) => updateFilter(setHours)(event.target.value)}>
              {WINDOWS.map((window) => (
                <option key={window.value} value={window.value}>
                  {window.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Card>

      <div className={styles.results}>
        <Card title="Results">
          {alerts.loading && <Loading label="Loading alerts" />}
          {alerts.error && <ErrorState message={alerts.error} onRetry={alerts.refresh} />}

          {alerts.data && visible.length === 0 && (
            <Empty
              message={
                needle
                  ? "No alerts on this page match your search."
                  : "No alerts match these filters."
              }
            />
          )}

          {alerts.data && visible.length > 0 && (
            <>
              <AlertTable alerts={visible} caption={`Showing ${visible.length} alert(s)`} />
              <nav className={styles.pager} aria-label="Pagination">
                <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
                  Previous
                </button>
                <span className={styles.pageLabel} aria-live="polite">
                  Page {page + 1}
                </span>
                <button
                  type="button"
                  disabled={!alerts.data.meta.has_more}
                  onClick={() => setPage(page + 1)}
                >
                  Next
                </button>
              </nav>
            </>
          )}
        </Card>
      </div>
    </>
  );
}
