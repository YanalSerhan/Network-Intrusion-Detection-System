/**
 * Loaded detection rules, with runtime enable/disable.
 *
 * Toggling here is a runtime override — the YAML file on disk is untouched and
 * a reload restores it. The page says so, because a control that silently
 * reverts on restart is worse than one that explains itself.
 */
import { useState } from "react";

import { api } from "../api/client";
import { Card } from "../components/Card";
import { SeverityBadge } from "../components/SeverityBadge";
import { Empty, ErrorState, Loading } from "../components/States";
import { useApi } from "../hooks/useApi";
import styles from "./RulesPage.module.css";

export function RulesPage() {
  const rules = useApi(() => api.listRules(), []);
  const [busy, setBusy] = useState<string | null>(null);

  async function toggle(name: string, enabled: boolean) {
    setBusy(name);
    try {
      await api.setRuleEnabled(name, enabled);
      rules.refresh();
    } finally {
      setBusy(null);
    }
  }

  async function reload() {
    setBusy("__reload__");
    try {
      await api.reloadRules();
      rules.refresh();
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <h1 className={styles.heading}>Rules</h1>
      <p className={styles.note}>
        Toggling a rule takes effect immediately but does not edit its YAML file. Reloading
        restores whatever is on disk.
      </p>

      <Card
        title="Loaded rules"
        action={
          <button type="button" onClick={reload} disabled={busy !== null} className={styles.reload}>
            {busy === "__reload__" ? "Reloading…" : "Reload from disk"}
          </button>
        }
      >
        {rules.loading && <Loading label="Loading rules" />}
        {rules.error && <ErrorState message={rules.error} onRetry={rules.refresh} />}
        {rules.data?.items.length === 0 && (
          <Empty message="No rules loaded. Add a .yaml file to the rules directory." />
        )}

        {rules.data && rules.data.items.length > 0 && (
          <div className={styles.scroll}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Window</th>
                  <th scope="col">Threshold</th>
                  <th scope="col">Groups by</th>
                  <th scope="col">Enabled</th>
                </tr>
              </thead>
              <tbody>
                {rules.data.items.map((rule) => (
                  <tr key={rule.name}>
                    <th scope="row" className={styles.name}>
                      {rule.name}
                    </th>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>{rule.window ? `${rule.window}s` : "per packet"}</td>
                    <td>{rule.threshold}</td>
                    <td className={styles.mono}>{rule.group_by}</td>
                    <td>
                      <label className={styles.toggle}>
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          disabled={busy !== null}
                          onChange={(event) => toggle(rule.name, event.target.checked)}
                        />
                        {/* Explicit text: a checkbox alone is announced only as
                            "checked", which is ambiguous in a dense table. */}
                        <span>{rule.enabled ? "Enabled" : "Disabled"}</span>
                      </label>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
