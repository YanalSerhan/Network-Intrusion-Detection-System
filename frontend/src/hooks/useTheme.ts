/**
 * Dark/light theme state, persisted across sessions.
 *
 * The initial value is read from the DOM rather than from storage, because
 * index.html has already resolved and applied the theme before React mounts.
 * Re-deriving it here would risk disagreeing with what is on screen.
 */
import { useCallback, useEffect, useState } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "nd-theme";

function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  const [theme, setTheme] = useState<Theme>(currentTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Private browsing modes can reject writes; the theme still applies for
      // this session, so a failure to remember it is not worth surfacing.
    }
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((previous) => (previous === "dark" ? "light" : "dark"));
  }, []);

  return { theme, toggleTheme };
}
