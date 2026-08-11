/**
 * A single headline number.
 *
 * The label is rendered before the value in the DOM so a screen reader
 * announces "Critical, 7" rather than an unexplained "7".
 */
import type { ReactNode } from "react";

import styles from "./StatTile.module.css";

export function StatTile({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "critical" | "high";
}) {
  return (
    <div className={styles.tile}>
      <span className={styles.label}>{label}</span>
      <span className={`${styles.value} ${styles[tone]}`}>{value}</span>
    </div>
  );
}
