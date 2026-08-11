/**
 * A ranked list of values with proportional bars.
 *
 * The bar is decorative — the count is always shown as text, so the ranking is
 * readable without perceiving bar length or colour.
 */
import styles from "./BarList.module.css";

export interface BarItem {
  label: string;
  value: number;
}

export function BarList({ items, emptyLabel }: { items: BarItem[]; emptyLabel: string }) {
  if (items.length === 0) {
    return <p className={styles.empty}>{emptyLabel}</p>;
  }

  const max = Math.max(...items.map((item) => item.value), 1);

  return (
    <ul className={styles.list}>
      {items.map((item) => (
        <li key={item.label} className={styles.row}>
          <span className={styles.head}>
            <span className={styles.label} title={item.label}>
              {item.label}
            </span>
            <span className={styles.value}>{item.value.toLocaleString()}</span>
          </span>
          <span aria-hidden="true" className={styles.track}>
            <span className={styles.fill} style={{ width: `${(item.value / max) * 100}%` }} />
          </span>
        </li>
      ))}
    </ul>
  );
}
