/**
 * A titled panel.
 *
 * Uses a real heading element so the page has a navigable outline: screen
 * reader users jump between headings rather than reading linearly.
 */
import type { ReactNode } from "react";

import styles from "./Card.module.css";

export function Card({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className={styles.card} aria-label={title}>
      <header className={styles.header}>
        <h2 className={styles.title}>{title}</h2>
        {action}
      </header>
      <div className={styles.body}>{children}</div>
    </section>
  );
}
