/**
 * Live-connection indicator.
 *
 * An analyst watching a quiet dashboard cannot tell "no attacks" from "feed
 * broken" — both look like an empty screen. This makes the difference visible,
 * with a text label rather than colour alone.
 */
import { useLive } from "../live/context";
import styles from "./ConnectionBadge.module.css";

const LABELS = {
  open: "Live",
  connecting: "Connecting",
  closed: "Reconnecting",
} as const;

export function ConnectionBadge() {
  const { state } = useLive();

  return (
    <span
      className={`${styles.badge} ${styles[state]}`}
      // Politely announced: a transient reconnect should not interrupt someone
      // mid-sentence, but it should reach a screen reader eventually.
      role="status"
      aria-live="polite"
    >
      <span aria-hidden="true" className={styles.dot} />
      <span className={styles.label}>{LABELS[state]}</span>
    </span>
  );
}
