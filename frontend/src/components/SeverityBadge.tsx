/**
 * Severity indicator.
 *
 * Always renders the severity *word*, never a bare colour swatch. Around 1 in
 * 12 men has a colour vision deficiency, and "is this red or orange?" is
 * exactly the distinction that fails — so colour reinforces the label rather
 * than carrying the meaning alone (WCAG 1.4.1).
 */
import type { Severity } from "../api/types";
import styles from "./SeverityBadge.module.css";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`${styles.badge} ${styles[severity]}`} data-severity={severity}>
      {LABELS[severity] ?? severity}
    </span>
  );
}
