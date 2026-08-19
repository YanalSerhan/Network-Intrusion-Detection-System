/**
 * Applies the stored theme before first paint.
 *
 * An external file rather than an inline <script>: the API serves the
 * dashboard under a Content-Security-Policy whose script-src has no
 * 'unsafe-inline', so an inline block is refused — and this one existed to
 * prevent a flash of the wrong colours, which is exactly what being refused
 * caused. Loaded synchronously in <head>, so it still runs before the first
 * paint; reading the stored theme inside React would render the default first.
 */
(function () {
  try {
    var stored = localStorage.getItem("nd-theme");
    var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = stored || (prefersDark ? "dark" : "light");
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
  }
})();
