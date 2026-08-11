/**
 * Page chrome: skip link, header, navigation and main region.
 *
 * The skip link is the first focusable element on the page. Without it a
 * keyboard or screen-reader user must tab through every nav item on every
 * navigation before reaching content (WCAG 2.4.1).
 */
import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";

import { useTheme } from "../hooks/useTheme";
import { ConnectionBadge } from "./ConnectionBadge";
import styles from "./Layout.module.css";

const NAV_ITEMS = [
  { to: "/", label: "Overview", end: true },
  { to: "/alerts", label: "Alerts", end: false },
  { to: "/rules", label: "Rules", end: false },
];

export function Layout({ children }: { children: ReactNode }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <>
      <a className={styles.skipLink} href="#main">
        Skip to main content
      </a>

      <header className={styles.header}>
        <div className={styles.inner}>
          <span className={styles.brand}>
            <span aria-hidden="true" className={styles.mark} />
            Network Defender
          </span>

          <nav aria-label="Primary">
            <ul className={styles.navList}>
              {NAV_ITEMS.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      isActive ? `${styles.navLink} ${styles.navLinkActive}` : styles.navLink
                    }
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>

          <div className={styles.actions}>
            <ConnectionBadge />
            <button
              type="button"
              className={styles.themeButton}
              onClick={toggleTheme}
              // The control's purpose is an icon, so it needs an accessible
              // name; aria-pressed conveys that it is a toggle, not an action.
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              aria-pressed={theme === "light"}
            >
              <span aria-hidden="true">{theme === "dark" ? "☀" : "☾"}</span>
            </button>
          </div>
        </div>
      </header>

      <main id="main" className={styles.main} tabIndex={-1}>
        {children}
      </main>
    </>
  );
}
